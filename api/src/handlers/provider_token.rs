use crate::auth::sso::Provider;
use crate::auth::token_refresher;
use crate::constants::TOKEN_REFRESH_LOCK_TIMEOUT_SECONDS;
use crate::entities::identities;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    identities::IdentityStore, organization_oauth_credentials::OrganizationOAuthCredentialsStore,
    services::ServiceStore, token_refresh_locks::TokenRefreshLockStore, users::UserStore, DB,
};
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::{DateTime, Duration, Utc};
use sea_orm::DatabaseConnection;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProviderTokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub expires_at: Option<String>,
    pub scopes: Vec<String>,
    pub provider: String,
}

pub async fn get_provider_token(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    auth_user: AuthUser,
) -> Result<Json<ProviderTokenResponse>> {
    let provider = Provider::from_str(&provider_str)?;

    // This endpoint should only be called from service context
    if auth_user.claims.service.is_none() {
        return Err(AppError::BadRequest(
            "Provider tokens can only be requested in service context".to_string(),
        ));
    }

    // 1. Verify service has scopes configured for this provider
    let service = ServiceStore::find_by_org_slug_and_service_slug(
        DB::Conn(&state.db),
        &auth_user.claims.org.clone().unwrap_or_default(),
        &auth_user.claims.service.clone().unwrap_or_default(),
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    // Check if service has scopes configured for the requested provider
    let has_scopes = match provider {
        Provider::Github => service.github_scopes.is_some(),
        Provider::Microsoft => service.microsoft_scopes.is_some(),
        Provider::Google => service.google_scopes.is_some(),
        Provider::Oidc => true, // OIDC scopes are dynamically managed
        Provider::Password => false,
    };

    if !has_scopes {
        return Err(AppError::Forbidden(format!(
            "Service does not have {} scopes configured",
            provider.as_str()
        )));
    }

    // Get organization ID and service ID for proper service-level isolation
    let org_id = service.org_id.clone();
    let service_id = service.id.clone();

    // 2. Get user's identity for this provider, scoped to this specific service
    // This ensures we only access tokens that were obtained via this service's OAuth credentials
    // and provides full service-level isolation
    let identity = IdentityStore::find_by_user_and_provider(
        DB::Conn(&state.db),
        &auth_user.claims.sub,
        provider.as_str(),
        Some(&org_id),
        Some(&service_id),
    )
    .await?
    .ok_or_else(|| {
        AppError::NotFound(format!(
            "User has not authenticated with {} for this service",
            provider.as_str()
        ))
    })?;

    // 3. Check if token is expired or about to expire (< 5 minutes)
    if let Some(expires_at_naive) = &identity.expires_at {
        let expires_at_utc: DateTime<Utc> =
            DateTime::from_naive_utc_and_offset(*expires_at_naive, Utc);
        let now = Utc::now();
        if expires_at_utc < now + Duration::minutes(5) {
            // Token expired or expiring soon - refresh it
            let refreshed_identity = refresh_provider_token_with_lock(&state, &identity).await?;
            let access_token = decrypt_token(
                state.encryption.as_deref(),
                &refreshed_identity.id,
                "access_token_encrypted",
                &refreshed_identity.access_token,
                &refreshed_identity.access_token_encrypted,
            )?;
            return Ok(Json(ProviderTokenResponse {
                access_token: access_token.unwrap_or_default(),
                refresh_token: None,
                expires_at: refreshed_identity
                    .expires_at
                    .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
                scopes: parse_scopes(&refreshed_identity.scopes),
                provider: provider.as_str().to_string(),
            }));
        }
    }

    // 4. Decrypt and return existing token
    let access_token = decrypt_token(
        state.encryption.as_deref(),
        &identity.id,
        "access_token_encrypted",
        &identity.access_token,
        &identity.access_token_encrypted,
    )?;

    Ok(Json(ProviderTokenResponse {
        access_token: access_token.unwrap_or_default(),
        refresh_token: None,
        expires_at: identity
            .expires_at
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        scopes: parse_scopes(&identity.scopes),
        provider: provider.as_str().to_string(),
    }))
}

async fn refresh_provider_token_with_lock(
    state: &AppState,
    identity: &identities::Model,
) -> Result<identities::Model> {
    let lock_timeout = TOKEN_REFRESH_LOCK_TIMEOUT_SECONDS;

    // Try to acquire lock
    let lock_acquired = acquire_refresh_lock(&state.db, &identity.id, lock_timeout).await?;

    if !lock_acquired {
        // Another process is already refreshing - wait and retry
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Fetch updated identity (should have new token now)
        let updated_identity = IdentityStore::find_by_id(DB::Conn(&state.db), &identity.id)
            .await?
            .ok_or_else(|| AppError::NotFound("Identity not found after refresh".to_string()))?;

        return Ok(updated_identity);
    }

    // We have the lock - proceed with refresh
    let result = refresh_provider_token(state, identity).await;

    // Always release lock
    let _ = release_refresh_lock(&state.db, &identity.id).await;

    result
}

async fn refresh_provider_token(
    state: &AppState,
    identity: &identities::Model,
) -> Result<identities::Model> {
    let provider = Provider::from_str(&identity.provider)?;

    let refresh_token = decrypt_token(
        state.encryption.as_deref(),
        &identity.id,
        "refresh_token_encrypted",
        &identity.refresh_token,
        &identity.refresh_token_encrypted,
    )?
    .ok_or_else(|| AppError::OAuth("No refresh token available".to_string()))?;

    // 1. Determine which credentials to use (same logic as background job)
    let (client_id, client_secret) = if let Some(org_id) = &identity.issuing_org_id {
        // Case 1: BYOO Token
        let creds = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
            DB::Conn(&state.db),
            org_id,
            &identity.provider,
        )
        .await?
        .ok_or_else(|| AppError::OAuth("BYOO credentials not found for org".to_string()))?;

        let encryption = state.encryption.as_ref().ok_or_else(|| {
            AppError::OAuth("Encryption service unavailable for BYOO secret".to_string())
        })?;

        // Create OAuth client using the new encapsulated method
        let _oauth_client =
            crate::store::organizations::OrganizationStore::get_oauth_client_for_org(
                DB::Conn(&state.db),
                org_id,
                provider,
                encryption,
            )
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to create OAuth client: {}", e)))?;

        // For now, return the credentials directly since that's what the existing code expects
        let secret = encryption
            .decrypt_with_context(
                &creds.client_secret_encrypted,
                crate::encryption::EncryptionContext::new(
                    "organization_oauth_credentials",
                    &creds.id,
                    "client_secret_encrypted",
                ),
            )
            .map_err(|e| AppError::OAuth(format!("Failed to decrypt BYOO secret: {}", e)))?;

        (creds.client_id, secret)
    } else {
        // Case 2: Platform Token (Admin or Default)
        let _user = UserStore::find_by_id(DB::Conn(&state.db), &identity.user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let config = crate::config::Config::from_env()
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;

        // Case 2: Platform Credentials (used for both admin and non-admin users)
        match provider {
            Provider::Google => (
                config.platform_google_client_id
                    .ok_or_else(|| AppError::OAuth("Google OAuth provider is not configured. Please set PLATFORM_GOOGLE_CLIENT_ID and PLATFORM_GOOGLE_CLIENT_SECRET environment variables.".to_string()))?,
                config.platform_google_client_secret
                    .ok_or_else(|| AppError::OAuth("Google OAuth provider is not configured. Please set PLATFORM_GOOGLE_CLIENT_ID and PLATFORM_GOOGLE_CLIENT_SECRET environment variables.".to_string()))?,
            ),
            Provider::Microsoft => (
                config.platform_microsoft_client_id
                    .ok_or_else(|| AppError::OAuth("Microsoft OAuth provider is not configured. Please set PLATFORM_MICROSOFT_CLIENT_ID and PLATFORM_MICROSOFT_CLIENT_SECRET environment variables.".to_string()))?,
                config.platform_microsoft_client_secret
                    .ok_or_else(|| AppError::OAuth("Microsoft OAuth provider is not configured. Please set PLATFORM_MICROSOFT_CLIENT_ID and PLATFORM_MICROSOFT_CLIENT_SECRET environment variables.".to_string()))?,
            ),
            Provider::Github => {
                return Err(AppError::OAuth(
                    "GitHub token refresh not supported".to_string(),
                ))
            }
            Provider::Oidc => {
                 return Err(AppError::OAuth(
                    "OIDC token refresh not supported yet".to_string(),
                ))
            }
            Provider::Password => {
                 return Err(AppError::OAuth(
                    "Password token refresh not supported".to_string(),
                ))
            }
        }
    };

    // 2. Call provider's token refresh endpoint using centralized module
    let new_token = match provider {
        Provider::Github => {
            return Err(AppError::OAuth(
                "GitHub tokens do not support refresh".to_string(),
            ));
        }
        Provider::Microsoft => {
            token_refresher::refresh_microsoft_token(&refresh_token, &client_id, &client_secret)
                .await
                .map_err(|e| AppError::OAuth(format!("Token refresh failed: {}", e)))?
        }
        Provider::Google => {
            let config = crate::config::Config::from_env()
                .map_err(|e| AppError::InternalServerError(e.to_string()))?;
            token_refresher::refresh_google_token(
                &refresh_token,
                &client_id,
                &client_secret,
                config.platform_google_token_url.as_deref(),
            )
            .await
            .map_err(|e| AppError::OAuth(format!("Token refresh failed: {}", e)))?
        }
        Provider::Oidc => {
            return Err(AppError::OAuth(
                "OIDC token refresh not supported yet".to_string(),
            ));
        }
        Provider::Password => {
            return Err(AppError::OAuth(
                "Password token refresh not supported".to_string(),
            ));
        }
    };

    // Update identity in database
    let expires_at_naive = new_token.expires_at.map(|dt| dt.naive_utc());

    if let Some(encryption) = state.encryption.as_ref() {
        let access_token_encrypted = encryption
            .encrypt_with_context(
                &new_token.access_token,
                crate::encryption::EncryptionContext::new(
                    "identities",
                    &identity.id,
                    "access_token_encrypted",
                ),
            )
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to encrypt access token: {}", e))
            })?;
        let refresh_token_encrypted = new_token
            .refresh_token
            .as_ref()
            .map(|token| {
                encryption
                    .encrypt_with_context(
                        token,
                        crate::encryption::EncryptionContext::new(
                            "identities",
                            &identity.id,
                            "refresh_token_encrypted",
                        ),
                    )
                    .map_err(|e| {
                        AppError::InternalServerError(format!(
                            "Failed to encrypt refresh token: {}",
                            e
                        ))
                    })
            })
            .transpose()?;

        IdentityStore::update_tokens_encrypted(
            DB::Conn(&state.db),
            &identity.id,
            Some(access_token_encrypted),
            refresh_token_encrypted,
            encryption.key_id(),
            expires_at_naive,
        )
        .await?;
    } else {
        IdentityStore::update_tokens(
            DB::Conn(&state.db),
            &identity.id,
            Some(&new_token.access_token),
            new_token.refresh_token.as_deref(),
            expires_at_naive,
        )
        .await?;
    }

    // Fetch the updated identity
    let updated_identity = IdentityStore::find_by_id(DB::Conn(&state.db), &identity.id)
        .await?
        .ok_or_else(|| AppError::NotFound("Identity not found after update".to_string()))?;

    Ok(updated_identity)
}

fn decrypt_token(
    encryption: Option<&crate::encryption::EncryptionService>,
    identity_id: &str,
    encrypted_field: &'static str,
    plaintext: &Option<String>,
    encrypted: &Option<Vec<u8>>,
) -> Result<Option<String>> {
    if let Some(encryption) = encryption {
        if plaintext.is_some() {
            return Err(AppError::InternalServerError(
                "Provider token requires migration; run rewrap-secrets --apply".to_string(),
            ));
        }
        if let Some(encrypted_token) = encrypted {
            let decrypted = encryption
                .decrypt_with_context(
                    encrypted_token,
                    crate::encryption::EncryptionContext::new(
                        "identities",
                        identity_id,
                        encrypted_field,
                    ),
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to decrypt token: {}", e))
                })?;
            return Ok(Some(decrypted));
        }
        return Ok(None);
    }

    // Plaintext compatibility is confined to the explicitly unencrypted
    // development mode. Production startup always supplies encryption and
    // performs a complete maintenance-readiness scan before routing traffic.
    Ok(plaintext.clone())
}

fn parse_scopes(scopes_json: &Option<String>) -> Vec<String> {
    scopes_json
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

async fn acquire_refresh_lock(
    pool: &DatabaseConnection,
    lock_key: &str,
    timeout_seconds: i64,
) -> Result<bool> {
    TokenRefreshLockStore::acquire_lock(DB::Conn(pool), lock_key, timeout_seconds).await
}

async fn release_refresh_lock(pool: &DatabaseConnection, lock_key: &str) -> Result<()> {
    TokenRefreshLockStore::release_lock(DB::Conn(pool), lock_key).await
}

#[cfg(test)]
mod token_storage_tests {
    use super::*;

    fn encryption() -> crate::encryption::EncryptionService {
        crate::encryption::EncryptionService::from_keyring_values("active", &"11".repeat(32), None)
            .unwrap()
    }

    #[test]
    fn configured_encryption_rejects_identity_plaintext_and_reads_exact_v2_field() {
        let encryption = encryption();
        let plaintext = Some("identity-plaintext-canary".to_string());
        let error = decrypt_token(
            Some(&encryption),
            "identity-a",
            "access_token_encrypted",
            &plaintext,
            &None,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("requires migration"));
        assert!(!message.contains("identity-plaintext-canary"));

        assert_eq!(
            decrypt_token(
                None,
                "identity-a",
                "access_token_encrypted",
                &plaintext,
                &None,
            )
            .unwrap(),
            plaintext
        );

        let ciphertext = encryption
            .encrypt_with_context(
                "identity-v2-canary",
                crate::encryption::EncryptionContext::new(
                    "identities",
                    "identity-a",
                    "access_token_encrypted",
                ),
            )
            .unwrap();
        assert_eq!(
            decrypt_token(
                Some(&encryption),
                "identity-a",
                "access_token_encrypted",
                &None,
                &Some(ciphertext),
            )
            .unwrap()
            .as_deref(),
            Some("identity-v2-canary")
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtService;
    use crate::auth::sso::{OAuthClient, Provider};
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::entities::users;
    use crate::middleware::AuthUser;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        audit_actor::AuditHandle, events::EventDispatcher, metrics::MfaMetricsService,
        risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{organizations::OrganizationStore, users::UserStore, DB};
    use axum::extract::Path;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    fn test_config() -> Config {
        Config {
            database_url: "sqlite::memory:".to_string(),
            jwt_expiration_hours: 24,
            db_max_connections: 5,
            db_min_connections: 1,
            db_acquire_timeout_secs: 30,
            db_idle_timeout_secs: 600,
            db_max_lifetime_secs: 1800,
            platform_github_client_id: None,
            platform_github_client_secret: None,
            platform_github_redirect_uri: None,
            platform_google_client_id: None,
            platform_google_client_secret: None,
            platform_google_redirect_uri: None,
            platform_microsoft_client_id: None,
            platform_microsoft_client_secret: None,
            platform_microsoft_redirect_uri: None,
            platform_github_auth_url: None,
            platform_github_token_url: None,
            platform_github_user_api_url: None,
            platform_google_auth_url: None,
            platform_google_token_url: None,
            platform_google_user_api_url: None,
            platform_microsoft_auth_url: None,
            platform_microsoft_token_url: None,
            platform_microsoft_user_api_url: None,
            stripe_secret_key: None,
            stripe_webhook_secret: None,
            stripe_api_base_url: None,
            server_host: "127.0.0.1".to_string(),
            server_port: 3001,
            base_url: "http://localhost:3001".to_string(),
            platform_dashboard_base_url: "http://localhost:3001".to_string(),
            full_web_client_base_url: None,
            platform_owner_email: None,
            platform_owner_password: None,
            managed_config_path: None,
            managed_state_path: None,
            managed_status_path: None,
            managed_request_path: None,
            disable_rate_limiting: true,
            job_processor_interval_secs: 10,
            job_processor_batch_size: 10,
        }
    }

    struct Fixture {
        state: AppState,
        // JWT scoped to org+service (service context).
        service_scoped: AuthUser,
        // JWT without any service context.
        context_free: AuthUser,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let mut config = test_config();
        config.platform_github_client_id = Some("cid".to_string());
        config.platform_github_client_secret = Some("csecret".to_string());
        let jwt_service = Arc::new({
            let rsa = GeneratedKey::generate().expect("rsa");
            JwtService::new(
                &STANDARD.encode(rsa.private_key_pem().expect("pem")),
                &STANDARD.encode(rsa.public_key_pem().expect("pem")),
                config.jwt_expiration_hours,
                "test-key",
                &config.base_url,
            )
            .expect("jwt")
        });

        let user = UserStore::create(DB::Conn(&db), "pt@example.test", None, false)
            .await
            .expect("create user");
        let (org, _) =
            OrganizationStore::create_with_owner(DB::Conn(&db), "acme", "Acme", &user.id, None)
                .await
                .expect("create org");
        drop(org);

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("oauth")),
            jwt_service: jwt_service.clone(),
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("risk")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        };

        let auth_user_for = |user: &users::Model, service: Option<&str>| -> AuthUser {
            let token = jwt_service
                .create_token(&user.id, &user.email, false, Some("acme"), service)
                .expect("token");
            AuthUser {
                claims: jwt_service.validate_token(&token).expect("claims"),
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "provider-token-test".to_string(),
                current_session_id: None,
            }
        };

        Fixture {
            service_scoped: auth_user_for(&user, Some("portal")),
            context_free: auth_user_for(&user, None),
            state,
        }
    }

    #[tokio::test]
    async fn tokens_require_a_service_context() {
        let f = fixture().await;
        match get_provider_token(
            State(f.state.clone()),
            Path("github".to_string()),
            f.context_free.clone(),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("service context"))
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_providers_are_refused_before_context_checks() {
        let f = fixture().await;
        match get_provider_token(
            State(f.state.clone()),
            Path("aol".to_string()),
            f.service_scoped.clone(),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("Invalid provider")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }
}
