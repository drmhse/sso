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
                &state,
                &refreshed_identity.access_token,
                &refreshed_identity.access_token_encrypted,
            )?;
            let refresh_token = decrypt_token(
                &state,
                &refreshed_identity.refresh_token,
                &refreshed_identity.refresh_token_encrypted,
            )?;
            return Ok(Json(ProviderTokenResponse {
                access_token: access_token.unwrap_or_default(),
                refresh_token,
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
        &state,
        &identity.access_token,
        &identity.access_token_encrypted,
    )?;
    let refresh_token = decrypt_token(
        &state,
        &identity.refresh_token,
        &identity.refresh_token_encrypted,
    )?;

    Ok(Json(ProviderTokenResponse {
        access_token: access_token.unwrap_or_default(),
        refresh_token,
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
    let lock_acquired = acquire_refresh_lock(&state.db, &identity.user_id, lock_timeout).await?;

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
    let _ = release_refresh_lock(&state.db, &identity.user_id).await;

    result
}

async fn refresh_provider_token(
    state: &AppState,
    identity: &identities::Model,
) -> Result<identities::Model> {
    let provider = Provider::from_str(&identity.provider)?;

    let refresh_token = identity
        .refresh_token
        .as_ref()
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
            .decrypt(&creds.client_secret_encrypted)
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
            token_refresher::refresh_microsoft_token(refresh_token, &client_id, &client_secret)
                .await
                .map_err(|e| AppError::OAuth(format!("Token refresh failed: {}", e)))?
        }
        Provider::Google => {
            let config = crate::config::Config::from_env()
                .map_err(|e| AppError::InternalServerError(e.to_string()))?;
            token_refresher::refresh_google_token(
                refresh_token,
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
            ))
        }
    };

    // Update identity in database
    let expires_at_naive = new_token.expires_at.map(|dt| dt.naive_utc());

    IdentityStore::update_tokens(
        DB::Conn(&state.db),
        &identity.id,
        Some(&new_token.access_token),
        new_token.refresh_token.as_deref(),
        expires_at_naive,
    )
    .await?;

    // Fetch the updated identity
    let updated_identity = IdentityStore::find_by_id(DB::Conn(&state.db), &identity.id)
        .await?
        .ok_or_else(|| AppError::NotFound("Identity not found after update".to_string()))?;

    Ok(updated_identity)
}

fn decrypt_token(
    state: &AppState,
    plaintext: &Option<String>,
    encrypted: &Option<Vec<u8>>,
) -> Result<Option<String>> {
    // If plaintext exists, use it (backwards compatibility)
    if let Some(token) = plaintext {
        return Ok(Some(token.clone()));
    }

    // Otherwise, decrypt the encrypted version
    if let Some(encrypted_token) = encrypted {
        if let Some(encryption) = &state.encryption {
            let decrypted = encryption.decrypt(encrypted_token).map_err(|e| {
                AppError::InternalServerError(format!("Failed to decrypt token: {}", e))
            })?;
            return Ok(Some(decrypted));
        }
    }

    // No token available
    Ok(None)
}

fn parse_scopes(scopes_json: &Option<String>) -> Vec<String> {
    scopes_json
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

async fn acquire_refresh_lock(
    pool: &DatabaseConnection,
    user_id: &str,
    timeout_seconds: i64,
) -> Result<bool> {
    TokenRefreshLockStore::acquire_lock(DB::Conn(pool), user_id, timeout_seconds).await
}

async fn release_refresh_lock(pool: &DatabaseConnection, user_id: &str) -> Result<()> {
    TokenRefreshLockStore::release_lock(DB::Conn(pool), user_id).await
}
