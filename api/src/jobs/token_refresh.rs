use crate::auth::sso::Provider;
use crate::auth::token_refresher;
use crate::constants::TOKEN_REFRESH_LOCK_TIMEOUT_SECONDS;
use crate::encryption::EncryptionService;
use crate::entities::identities;
use chrono::{Duration, Utc};
use sea_orm::DatabaseConnection;

const REFRESH_LOOKAHEAD: Duration = Duration::minutes(5);

pub struct TokenRefreshJob {
    db: DatabaseConnection,
    encryption: Option<EncryptionService>,
}

fn platform_oauth_credentials(
    config: &crate::config::Config,
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
        use crate::store::{identities::IdentityStore, DB};

        let threshold = Utc::now() + REFRESH_LOOKAHEAD;
        let threshold_str = threshold.to_rfc3339();

        let expiring_identities =
            IdentityStore::list_needing_refresh(DB::Conn(&self.db), &threshold_str)
                .await
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        tracing::info!("Found {} tokens to refresh", expiring_identities.len());

        for identity in expiring_identities {
            match self.refresh_single_token(&identity).await {
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
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::store::{token_refresh_locks::TokenRefreshLockStore, DB};

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
            .refresh_single_token_locked(identity)
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
    ) -> Result<(), Box<dyn std::error::Error>> {
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

        // 1. Determine which credentials to use. Service-scoped identities may
        // have an issuing org even when they used platform OAuth credentials.
        let config = crate::config::Config::from_env().map_err(|e| e.to_string())?;
        let (client_id, client_secret) = if let Some(org_id) = &identity.issuing_org_id {
            use crate::store::{
                organization_oauth_credentials::OrganizationOAuthCredentialsStore, DB,
            };

            if let Some(creds) = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
                DB::Conn(&self.db),
                org_id,
                &identity.provider,
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?
            {
                let encryption = self
                    .encryption
                    .as_ref()
                    .ok_or("Encryption service unavailable for BYOO secret")?;
                let secret = encryption.decrypt(&creds.client_secret_encrypted)?;
                (creds.client_id, secret)
            } else {
                platform_oauth_credentials(&config, provider)?
            }
        } else {
            platform_oauth_credentials(&config, provider)?
        };

        // 2. Get the refresh token
        let refresh_token = if let Some(ref encrypted) = identity.refresh_token_encrypted {
            if let Some(ref enc) = self.encryption {
                enc.decrypt(encrypted)?
            } else {
                return Err("Encryption service not available".into());
            }
        } else if let Some(ref token) = identity.refresh_token {
            token.clone()
        } else {
            return Err("No refresh token available".into());
        };

        // 3. Call the appropriate refresh function with the correct credentials
        let new_token = match provider {
            Provider::Microsoft => {
                token_refresher::refresh_microsoft_token(&refresh_token, &client_id, &client_secret)
                    .await?
            }
            Provider::Google => {
                let config = crate::config::Config::from_env()
                    .map_err(|e| format!("Failed to load config: {}", e))?;
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

        // 4. Update the identity in the database
        use crate::store::{identities::IdentityStore, DB};

        if let Some(ref enc) = self.encryption {
            let access_encrypted = enc.encrypt(&new_token.access_token)?;
            let refresh_encrypted = new_token
                .refresh_token
                .as_ref()
                .map(|rt| enc.encrypt(rt))
                .transpose()?;

            let expires_at_naive = new_token.expires_at.map(|dt| dt.naive_utc());

            IdentityStore::update_tokens_encrypted(
                DB::Conn(&self.db),
                &identity.id,
                Some(access_encrypted),
                refresh_encrypted,
                enc.key_id(),
                expires_at_naive,
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        } else {
            let expires_at_naive = new_token.expires_at.map(|dt| dt.naive_utc());

            IdentityStore::update_tokens(
                DB::Conn(&self.db),
                &identity.id,
                Some(&new_token.access_token),
                new_token.refresh_token.as_deref(),
                expires_at_naive,
            )
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
        }

        Ok(())
    }
}
