use crate::auth::sso::Provider;
use crate::error::{AppError, Result};
use crate::handlers::auth::{create_custom_oauth_client, get_authorization_url_for_client, get_provider_scopes, AppState};
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Serialize)]
pub struct IdentityResponse {
    pub provider: String,
}

#[derive(Debug, Serialize)]
pub struct StartLinkResponse {
    pub authorization_url: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)] // Currently unused, kept for potential future API compatibility
pub struct UnlinkRequest {
    pub provider: String,
}

/// Helper function to determine the identity context (org_id and service_id) from auth user claims
/// Returns (issuing_org_id, issuing_service_id) based on the authentication context
async fn get_identity_context(
    pool: &SqlitePool,
    auth_user: &crate::middleware::AuthUser,
) -> Result<(Option<String>, Option<String>)> {
    if let (Some(org_slug), Some(service_slug)) = (&auth_user.claims.org, &auth_user.claims.service) {
        // Service context - get org_id and service_id
        let service = sqlx::query_as::<_, crate::db::models::Service>(
            "SELECT s.* FROM services s
             JOIN organizations o ON s.org_id = o.id
             WHERE o.slug = ? AND s.slug = ?",
        )
        .bind(org_slug)
        .bind(service_slug)
        .fetch_one(pool)
        .await?;

        Ok((Some(service.org_id), Some(service.id)))
    } else {
        // Platform context
        Ok((None, None))
    }
}

/// GET /api/user/identities - List all linked identities for the authenticated user
pub async fn list_identities(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<Vec<IdentityResponse>>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Get identity context (org_id and service_id) for proper isolation
    let (issuing_org_id, issuing_service_id) = get_identity_context(&state.pool, &auth_user).await?;

    // Fetch identities filtered by context
    let identities = if issuing_service_id.is_some() {
        // Service context: filter by both org_id and service_id
        sqlx::query_as::<_, crate::db::models::Identity>(
            "SELECT * FROM identities
             WHERE user_id = ?
             AND issuing_org_id = ?
             AND issuing_service_id = ?",
        )
        .bind(&auth_user.user.id)
        .bind(&issuing_org_id)
        .bind(&issuing_service_id)
        .fetch_all(&state.pool)
        .await?
    } else {
        // Platform context: filter by both NULL
        sqlx::query_as::<_, crate::db::models::Identity>(
            "SELECT * FROM identities
             WHERE user_id = ?
             AND issuing_org_id IS NULL
             AND issuing_service_id IS NULL",
        )
        .bind(&auth_user.user.id)
        .fetch_all(&state.pool)
        .await?
    };

    let response: Vec<IdentityResponse> = identities
        .into_iter()
        .map(|identity| IdentityResponse {
            provider: identity.provider,
        })
        .collect();

    Ok(Json(response))
}

/// POST /api/user/identities/:provider/link - Start linking a new social account
///
/// This endpoint initiates OAuth flow to link a provider account to the authenticated user.
/// After OAuth completes, the user will be redirected to the service's redirect_uri with:
/// - ?status=success&provider={provider}&action=link (on success)
/// - ?status=error&error={message}&action=link (on failure)
pub async fn start_link(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<StartLinkResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    let provider = Provider::from_str(&provider_str)?;

    // Detect authentication context to determine linking strategy
    let is_service_level = matches!(
        (&auth_user.claims.org, &auth_user.claims.service),
        (Some(org), Some(service)) if !(org == "platform" && service == "admin-cli")
    );

    let (_scopes, is_admin_flow, org_slug, service_slug, service_id, redirect_uri, auth_url, csrf_token, pkce_verifier) = if is_service_level {
        // Service-level linking: Read scopes and redirect_uris from service configuration
        let org = auth_user.claims.org.as_ref().unwrap();
        let service_slug = auth_user.claims.service.as_ref().unwrap();

        let service = sqlx::query_as::<_, crate::db::models::Service>(
            "SELECT s.* FROM services s
             JOIN organizations o ON s.org_id = o.id
             WHERE o.slug = ? AND s.slug = ?",
        )
        .bind(org)
        .bind(service_slug)
        .fetch_one(&state.pool)
        .await?;

        let service_id = service.id.clone();
        let scopes = get_provider_scopes(&service, provider);

        // Parse redirect_uris to get the primary redirect
        let redirect_uris: Vec<String> = service.redirect_uris
            .as_ref()
            .and_then(|uris| serde_json::from_str(uris).ok())
            .unwrap_or_default();

        let base_redirect = redirect_uris.first()
            .ok_or_else(|| AppError::InternalServerError(
                "Service has no redirect_uris configured".to_string()
            ))?;

        // Build redirect URL with query params for linking flow
        let redirect_uri = format!(
            "{}?status=success&provider={}&action=link",
            base_redirect,
            provider.as_str()
        );

        // Check if org has BYOO credentials for this provider
        let provider_str = provider.as_str();
        let org_credentials = sqlx::query!(
            "SELECT client_id, client_secret_encrypted, encryption_key_id
             FROM organization_oauth_credentials
             WHERE org_id = ? AND provider = ?",
            service.org_id,
            provider_str
        )
        .fetch_optional(&state.pool)
        .await?;

        let (auth_url, csrf_token, pkce_verifier) = if let Some(creds) = org_credentials {
            // Use BYOO credentials
            let encryption = crate::encryption::EncryptionService::new()
                .map_err(|e| AppError::InternalServerError(format!("Encryption unavailable: {}", e)))?;

            let client_secret = encryption
                .decrypt(&creds.client_secret_encrypted)
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to decrypt secret: {}", e))
                })?;

            let config = crate::config::Config::from_env()
                .map_err(|e| AppError::InternalServerError(e.to_string()))?;

            let custom_client = create_custom_oauth_client(
                &config,
                provider,
                &creds.client_id,
                &client_secret
            )?;

            get_authorization_url_for_client(&custom_client, provider, scopes.clone())
        } else {
            // Use platform credentials
            state.oauth_client.get_authorization_url_with_pkce(provider, scopes.clone())
        };

        (scopes, false, Some(org.clone()), Some(service_slug.clone()), Some(service_id), redirect_uri, auth_url, csrf_token, pkce_verifier)
    } else {
        // Platform-level linking: Use provider default scopes
        let default_scopes = match provider {
            Provider::Github => vec!["user:email".to_string()],
            Provider::Microsoft => vec!["User.Read".to_string(), "offline_access".to_string()],
            Provider::Google => vec!["openid".to_string(), "email".to_string(), "profile".to_string()],
        };

        // Generate OAuth authorization URL with platform credentials
        let (auth_url, csrf_token, pkce_verifier) = state
            .oauth_client
            .get_authorization_url_with_pkce(provider, default_scopes.clone());

        // For platform-level linking, use base_url + settings page
        let redirect_uri = format!(
            "{}/settings/connections?status=success&provider={}&action=link",
            state.base_url,
            provider.as_str()
        );

        (default_scopes, true, None, None, None, redirect_uri, auth_url, csrf_token, pkce_verifier)
    };

    // Store OAuth state with user_id_for_linking set
    let expires_at = Utc::now() + chrono::Duration::minutes(10);
    let pkce_value = if provider == Provider::Microsoft && !pkce_verifier.is_empty() {
        Some(pkce_verifier)
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO oauth_states (state, pkce_verifier, service_id, redirect_uri, org_slug, service_slug, is_admin_flow, user_id_for_linking, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)",
    )
    .bind(csrf_token.secret())
    .bind(pkce_value)
    .bind(service_id) // service_id for proper service-level isolation during linking
    .bind(&redirect_uri) // Use service redirect_uri with query params
    .bind(org_slug)
    .bind(service_slug)
    .bind(is_admin_flow)
    .bind(&auth_user.user.id) // Set user_id_for_linking
    .bind(expires_at)
    .execute(&state.pool)
    .await?;

    Ok(Json(StartLinkResponse {
        authorization_url: auth_url,
    }))
}

/// DELETE /api/user/identities/:provider - Unlink a social account
pub async fn unlink_identity(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<axum::http::StatusCode> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    let provider = Provider::from_str(&provider_str)?;

    // Get identity context (org_id and service_id) for proper isolation
    let (issuing_org_id, issuing_service_id) = get_identity_context(&state.pool, &auth_user).await?;

    // Count and delete identities filtered by context
    let (_identity_count, result) = if issuing_service_id.is_some() {
        // Service context: count and delete service-scoped identities
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM identities
             WHERE user_id = ?
             AND issuing_org_id = ?
             AND issuing_service_id = ?",
        )
        .bind(&auth_user.user.id)
        .bind(&issuing_org_id)
        .bind(&issuing_service_id)
        .fetch_one(&state.pool)
        .await?;

        // Prevent account lockout by ensuring at least one identity remains in this context
        if count <= 1 {
            return Err(AppError::BadRequest(
                "Cannot unlink last identity. At least one identity must remain.".to_string(),
            ));
        }

        let delete_result = sqlx::query(
            "DELETE FROM identities
             WHERE user_id = ?
             AND provider = ?
             AND issuing_org_id = ?
             AND issuing_service_id = ?",
        )
        .bind(&auth_user.user.id)
        .bind(provider.as_str())
        .bind(&issuing_org_id)
        .bind(&issuing_service_id)
        .execute(&state.pool)
        .await?;

        (count, delete_result)
    } else {
        // Platform context: count and delete platform-scoped identities
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM identities
             WHERE user_id = ?
             AND issuing_org_id IS NULL
             AND issuing_service_id IS NULL",
        )
        .bind(&auth_user.user.id)
        .fetch_one(&state.pool)
        .await?;

        // Prevent account lockout by ensuring at least one identity remains in this context
        if count <= 1 {
            return Err(AppError::BadRequest(
                "Cannot unlink last identity. At least one identity must remain.".to_string(),
            ));
        }

        let delete_result = sqlx::query(
            "DELETE FROM identities
             WHERE user_id = ?
             AND provider = ?
             AND issuing_org_id IS NULL
             AND issuing_service_id IS NULL",
        )
        .bind(&auth_user.user.id)
        .bind(provider.as_str())
        .execute(&state.pool)
        .await?;

        (count, delete_result)
    };

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Identity for provider '{}' not found",
            provider.as_str()
        )));
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}
