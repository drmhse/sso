use crate::config::Config;
use crate::constants::TOKEN_REFRESH_LOCK_TIMEOUT_SECONDS;
use crate::crypto::sso::Provider;
use crate::encryption::EncryptionService;
use crate::entities::identities;
use crate::services::token_refresher;
use chrono::{Duration, Utc};
use sea_orm::DatabaseConnection;
use std::collections::HashMap;

const REFRESH_LOOKAHEAD: Duration = Duration::minutes(5);
type OrgProviderCredentialCache = HashMap<(String, String), Option<(String, String)>>;

pub struct TokenRefreshJob {
    db: DatabaseConnection,
    encryption: Option<EncryptionService>,
}

fn platform_oauth_credentials(
    config: &Config,
    provider: Provider,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    match provider {
        Provider::Google => Ok((
            config
                .platform_google_client_id
                .clone()
                .ok_or("Google OAuth provider is not configured. Please set PLATFORM_GOOGLE_CLIENT_ID and PLATFORM_GOOGLE_CLIENT_SECRET environment variables.")?,
            config
                .platform_google_client_secret
                .clone()
                .ok_or("Google OAuth provider is not configured. Please set PLATFORM_GOOGLE_CLIENT_ID and PLATFORM_GOOGLE_CLIENT_SECRET environment variables.")?,
        )),
        Provider::Microsoft => Ok((
            config
                .platform_microsoft_client_id
                .clone()
                .ok_or("Microsoft OAuth provider is not configured. Please set PLATFORM_MICROSOFT_CLIENT_ID and PLATFORM_MICROSOFT_CLIENT_SECRET environment variables.")?,
            config
                .platform_microsoft_client_secret
                .clone()
                .ok_or("Microsoft OAuth provider is not configured. Please set PLATFORM_MICROSOFT_CLIENT_ID and PLATFORM_MICROSOFT_CLIENT_SECRET environment variables.")?,
        )),
        Provider::Github => Err("GitHub token refresh not supported".into()),
        Provider::Oidc => Err("OIDC token refresh not supported yet".into()),
        Provider::Password => Err("Password token refresh not supported".into()),
    }
}

impl TokenRefreshJob {
    pub fn new(db: DatabaseConnection, encryption: Option<EncryptionService>) -> Self {
        Self { db, encryption }
    }

    pub async fn start(self) {
        // Run every 30x the base interval (default: every 5 minutes)
        let mut interval = tokio::time::interval(super::get_cleanup_job_interval(30));

        loop {
            interval.tick().await;

            if let Err(e) = self.refresh_expiring_tokens().await {
                tracing::error!("Token refresh job failed: {}", e);
            }
        }
    }

    async fn refresh_expiring_tokens(&self) -> Result<(), Box<dyn std::error::Error>> {
        use crate::db::DB;
        use crate::store::identities::IdentityStore;

        let threshold = Utc::now() + REFRESH_LOOKAHEAD;
        let threshold_str = threshold.to_rfc3339();

        let expiring_identities =
            IdentityStore::list_needing_refresh(DB::Conn(&self.db), &threshold_str)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        tracing::info!("Found {} tokens to refresh", expiring_identities.len());

        let config = Config::from_env()?;
        let mut credential_cache = OrgProviderCredentialCache::new();

        for identity in expiring_identities {
            match self
                .refresh_single_token(&identity, &config, &mut credential_cache)
                .await
            {
                Ok(_) => tracing::info!("Refreshed token for identity: {}", identity.id),
                Err(e) => {
                    tracing::error!("Failed to refresh token for {}: {}", identity.id, e)
                }
            }
        }

        Ok(())
    }

    async fn refresh_single_token(
        &self,
        identity: &identities::Model,
        config: &Config,
        credential_cache: &mut OrgProviderCredentialCache,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::db::DB;
        use crate::store::token_refresh_locks::TokenRefreshLockStore;

        let lock_acquired = TokenRefreshLockStore::acquire_lock(
            DB::Conn(&self.db),
            &identity.id,
            TOKEN_REFRESH_LOCK_TIMEOUT_SECONDS,
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        if !lock_acquired {
            tracing::debug!(
                identity_id = %identity.id,
                "Skipping token refresh because another worker holds the refresh lock"
            );
            return Ok(());
        }

        let refresh_error = self
            .refresh_single_token_locked(identity, config, credential_cache)
            .await
            .err()
            .map(|e| e.to_string());

        if let Err(e) = TokenRefreshLockStore::release_lock(DB::Conn(&self.db), &identity.id).await
        {
            tracing::warn!(
                identity_id = %identity.id,
                error = %e,
                "Failed to release token refresh lock"
            );
        }

        if let Some(error) = refresh_error {
            return Err(std::io::Error::other(error).into());
        }

        Ok(())
    }

    async fn refresh_single_token_locked(
        &self,
        identity: &identities::Model,
        config: &Config,
        credential_cache: &mut OrgProviderCredentialCache,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Batch discovery is only a hint. Re-read under the per-identity lock
        // so deletion, tenant suspension, service removal/rebinding, and user
        // deletion take effect before provider I/O.
        let identity = self.load_current_authorized_identity(&identity.id).await?;
        let provider = Provider::from_str(&identity.provider)
            .map_err(|e| format!("Invalid provider: {}", e))?;
        if !matches!(provider, Provider::Google | Provider::Microsoft) {
            tracing::debug!(
                identity_id = %identity.id,
                provider = %identity.provider,
                "Skipping unsupported provider token refresh"
            );
            return Ok(());
        }

        // Determine which credentials to use. Service-scoped identities may
        // have an issuing org even when they used platform OAuth credentials.
        let (client_id, client_secret) = self
            .resolve_oauth_credentials(&identity, provider, config, credential_cache)
            .await?;

        let refresh_token = if let Some(ref enc) = self.encryption {
            if identity.refresh_token.is_some() {
                return Err(
                    "Provider refresh token requires migration; run rewrap-secrets --apply".into(),
                );
            }
            if let Some(ref encrypted) = identity.refresh_token_encrypted {
                enc.decrypt_with_context(
                    encrypted,
                    crate::encryption::EncryptionContext::new(
                        "identities",
                        &identity.id,
                        "refresh_token_encrypted",
                    ),
                )?
            } else {
                return Err("No refresh token available".into());
            }
        } else if let Some(ref token) = identity.refresh_token {
            token.clone()
        } else {
            return Err("No refresh token available".into());
        };

        // Credentials and secret decryption can be relatively expensive. Make
        // the authorization check immediately before outbound provider I/O as
        // well, then use that current row as the writeback authority.
        let identity = self.load_current_authorized_identity(&identity.id).await?;
        let expected_refresh_token_encrypted = identity.refresh_token_encrypted.clone();
        let expected_refresh_token_plaintext = identity.refresh_token.clone();
        let new_token = match provider {
            Provider::Microsoft => {
                token_refresher::refresh_microsoft_token(&refresh_token, &client_id, &client_secret)
                    .await?
            }
            Provider::Google => {
                token_refresher::refresh_google_token(
                    &refresh_token,
                    &client_id,
                    &client_secret,
                    config.platform_google_token_url.as_deref(),
                )
                .await?
            }
            Provider::Github => return Ok(()), // GitHub refresh tokens are complex/optional, skip for now
            Provider::Oidc => return Err("OIDC token refresh not supported yet".into()),
            Provider::Password => return Err("Password token refresh not supported".into()),
        };

        // Reauthorize again after network I/O. A tenant suspended or user
        // deleted while the provider request was in flight must not receive a
        // refreshed credential writeback.
        use crate::db::DB;
        use crate::store::identities::IdentityStore;
        use sea_orm::TransactionTrait;

        if let Some(ref enc) = self.encryption {
            let access_encrypted = enc.encrypt_with_context(
                &new_token.access_token,
                crate::encryption::EncryptionContext::new(
                    "identities",
                    &identity.id,
                    "access_token_encrypted",
                ),
            )?;
            let refresh_encrypted = new_token
                .refresh_token
                .as_ref()
                .map(|rt| {
                    enc.encrypt_with_context(
                        rt,
                        crate::encryption::EncryptionContext::new(
                            "identities",
                            &identity.id,
                            "refresh_token_encrypted",
                        ),
                    )
                })
                .transpose()?;

            let expires_at_naive = new_token.expires_at.map(|dt| dt.naive_utc());

            let transaction = self.db.begin().await?;
            Self::load_authorized_identity_on(DB::Tx(&transaction), &identity.id).await?;
            let updated = IdentityStore::update_tokens_encrypted_if_current(
                DB::Tx(&transaction),
                &identity.id,
                expected_refresh_token_encrypted.as_deref(),
                expected_refresh_token_plaintext.as_deref(),
                Some(access_encrypted),
                refresh_encrypted,
                enc.key_id(),
                expires_at_naive,
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            if !updated {
                transaction.rollback().await?;
                return Err("Identity refresh credential changed during provider I/O".into());
            }
            transaction.commit().await?;
        } else {
            let expires_at_naive = new_token.expires_at.map(|dt| dt.naive_utc());

            let transaction = self.db.begin().await?;
            Self::load_authorized_identity_on(DB::Tx(&transaction), &identity.id).await?;
            let updated = IdentityStore::update_tokens_if_current(
                DB::Tx(&transaction),
                &identity.id,
                expected_refresh_token_plaintext.as_deref(),
                Some(&new_token.access_token),
                new_token.refresh_token.as_deref(),
                expires_at_naive,
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
            if !updated {
                transaction.rollback().await?;
                return Err("Identity refresh credential changed during provider I/O".into());
            }
            transaction.commit().await?;
        }

        Ok(())
    }

    async fn load_current_authorized_identity(
        &self,
        identity_id: &str,
    ) -> Result<identities::Model, Box<dyn std::error::Error>> {
        Self::load_authorized_identity_on(crate::db::DB::Conn(&self.db), identity_id).await
    }

    async fn load_authorized_identity_on(
        db: crate::db::DB<'_>,
        identity_id: &str,
    ) -> Result<identities::Model, Box<dyn std::error::Error>> {
        use crate::store::{
            identities::IdentityStore, organizations::OrganizationStore, services::ServiceStore,
            users::UserStore,
        };

        let identity = IdentityStore::find_by_id(db.clone(), identity_id)
            .await?
            .ok_or("Identity no longer exists")?;
        let user = UserStore::find_by_id(db.clone(), &identity.user_id)
            .await?
            .filter(|user| user.deleted_at.is_none())
            .ok_or("Identity user is deleted or missing")?;

        match (
            identity.issuing_org_id.as_deref(),
            identity.issuing_service_id.as_deref(),
        ) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err("Service-scoped identity is missing its organization".into())
            }
            (Some(org_id), service_id) => {
                OrganizationStore::find_by_id(db.clone(), org_id)
                    .await?
                    .filter(|org| org.status == "active")
                    .ok_or("Identity organization is not active")?;
                if let Some(service_id) = service_id {
                    ServiceStore::find_by_id(db.clone(), service_id)
                        .await?
                        .filter(|service| service.org_id == org_id)
                        .ok_or("Identity service does not belong to its organization")?;
                } else if !user.is_platform_owner
                    && user.org_id.as_deref() != Some(org_id)
                    && crate::store::memberships::MembershipStore::find_by_org_and_user(
                        db, org_id, &user.id,
                    )
                    .await?
                    .is_none()
                {
                    return Err("Identity user no longer has organization entitlement".into());
                }
            }
        }

        Ok(identity)
    }

    async fn resolve_oauth_credentials(
        &self,
        identity: &identities::Model,
        provider: Provider,
        config: &Config,
        credential_cache: &mut OrgProviderCredentialCache,
    ) -> Result<(String, String), Box<dyn std::error::Error>> {
        let Some(org_id) = &identity.issuing_org_id else {
            return platform_oauth_credentials(config, provider);
        };

        let cache_key = (org_id.clone(), identity.provider.clone());
        if let Some(cached) = credential_cache.get(&cache_key) {
            return match cached {
                Some((client_id, client_secret)) => Ok((client_id.clone(), client_secret.clone())),
                None => platform_oauth_credentials(config, provider),
            };
        }

        use crate::db::DB;
        use crate::store::organization_oauth_credentials::OrganizationOAuthCredentialsStore;

        let credentials = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
            DB::Conn(&self.db),
            org_id,
            &identity.provider,
        )
        .await
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        if let Some(creds) = credentials {
            let encryption = self
                .encryption
                .as_ref()
                .ok_or("Encryption service unavailable for BYOO secret")?;
            let secret = encryption.decrypt_with_context(
                &creds.client_secret_encrypted,
                crate::encryption::EncryptionContext::new(
                    "organization_oauth_credentials",
                    &creds.id,
                    "client_secret_encrypted",
                ),
            )?;
            let resolved = (creds.client_id, secret);
            credential_cache.insert(cache_key, Some(resolved.clone()));
            Ok(resolved)
        } else {
            credential_cache.insert(cache_key, None);
            platform_oauth_credentials(config, provider)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DB;
    use crate::entities::identities as identity_entity;
    use crate::store::{
        identities::IdentityStore, organizations::OrganizationStore, services::ServiceStore,
        users::UserStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, Set};

    #[tokio::test]
    async fn refresh_authority_rejects_suspension_deleted_user_and_cross_org_service() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let user = UserStore::create(DB::Conn(&db), "refresh-authority@example.test", None, false)
            .await
            .unwrap();
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "refresh-org-a",
            "Refresh org A",
            &user.id,
            None,
        )
        .await
        .unwrap();
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "refresh-org-b",
            "Refresh org B",
            &user.id,
            None,
        )
        .await
        .unwrap();
        OrganizationStore::update_status(DB::Conn(&db), &org_a.id, "active")
            .await
            .unwrap();
        OrganizationStore::update_status(DB::Conn(&db), &org_b.id, "active")
            .await
            .unwrap();
        let service = ServiceStore::create(
            DB::Conn(&db),
            &org_a.id,
            "refresh-service",
            "Refresh service",
            "web",
            "refresh-authority-client",
        )
        .await
        .unwrap();
        let identity = IdentityStore::create(
            DB::Conn(&db),
            &user.id,
            "google",
            "provider-user",
            Some("access"),
            Some("refresh"),
            None,
            None,
            None,
            None,
            None,
            Some(&org_a.id),
            Some(&service.id),
        )
        .await
        .unwrap();
        let job = TokenRefreshJob::new(db.clone(), None);
        assert!(job
            .load_current_authorized_identity(&identity.id)
            .await
            .is_ok());

        OrganizationStore::update_status(DB::Conn(&db), &org_a.id, "suspended")
            .await
            .unwrap();
        assert!(job
            .load_current_authorized_identity(&identity.id)
            .await
            .is_err());
        OrganizationStore::update_status(DB::Conn(&db), &org_a.id, "active")
            .await
            .unwrap();

        let mut cross_context: identity_entity::ActiveModel = identity.clone().into();
        cross_context.issuing_org_id = Set(Some(org_b.id.clone()));
        let cross_context = cross_context.update(&db).await.unwrap();
        assert!(job
            .load_current_authorized_identity(&cross_context.id)
            .await
            .is_err());

        let mut restored: identity_entity::ActiveModel = cross_context.into();
        restored.issuing_org_id = Set(Some(org_a.id.clone()));
        restored.update(&db).await.unwrap();
        let mut deleted_user: crate::entities::users::ActiveModel = user.into();
        deleted_user.deleted_at = Set(Some(Utc::now().naive_utc()));
        deleted_user.update(&db).await.unwrap();
        assert!(job
            .load_current_authorized_identity(&identity.id)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn refresh_writeback_cas_does_not_restore_a_revoked_refresh_token() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let user = UserStore::create(DB::Conn(&db), "refresh-cas@example.test", None, false)
            .await
            .unwrap();
        let identity = IdentityStore::create(
            DB::Conn(&db),
            &user.id,
            "google",
            "refresh-cas-provider-user",
            Some("old-access"),
            Some("old-refresh"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let mut revoked: identity_entity::ActiveModel = identity.clone().into();
        revoked.refresh_token = Set(None);
        revoked.update(&db).await.unwrap();

        assert!(!IdentityStore::update_tokens_if_current(
            DB::Conn(&db),
            &identity.id,
            Some("old-refresh"),
            Some("new-access"),
            Some("new-refresh"),
            Some((Utc::now() + Duration::hours(1)).naive_utc()),
        )
        .await
        .unwrap());
        let unchanged = IdentityStore::find_by_id(DB::Conn(&db), &identity.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(unchanged.access_token.as_deref(), Some("old-access"));
        assert_eq!(unchanged.refresh_token, None);
        assert_eq!(unchanged.last_refreshed_at, None);
    }
}
