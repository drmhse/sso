use crate::auth::sso::Provider;
use crate::error::{AppError, Result};
use crate::handlers::auth::AppState;
use axum::{
    extract::{Path, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

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

/// GET /api/user/identities - List all linked identities for the authenticated user
pub async fn list_identities(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<Vec<IdentityResponse>>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    let identities = sqlx::query_as::<_, crate::db::models::Identity>(
        "SELECT * FROM identities WHERE user_id = ?",
    )
    .bind(&auth_user.user.id)
    .fetch_all(&state.pool)
    .await?;

    let response: Vec<IdentityResponse> = identities
        .into_iter()
        .map(|identity| IdentityResponse {
            provider: identity.provider,
        })
        .collect();

    Ok(Json(response))
}

/// POST /api/user/identities/:provider/link - Start linking a new social account
pub async fn start_link(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<StartLinkResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    let provider = Provider::from_str(&provider_str)?;

    // Use default scopes for linking
    let scopes = vec!["user:email".to_string()];

    // Generate OAuth authorization URL
    let (auth_url, csrf_token, pkce_verifier) = state
        .oauth_client
        .get_authorization_url_with_pkce(provider, scopes);

    // Store OAuth state with user_id_for_linking set
    let expires_at = Utc::now() + chrono::Duration::minutes(10);
    let pkce_value = if provider == Provider::Microsoft && !pkce_verifier.is_empty() {
        Some(pkce_verifier)
    } else {
        None
    };

    sqlx::query(
        "INSERT INTO oauth_states (state, pkce_verifier, service_id, redirect_uri, org_slug, service_slug, is_admin_flow, user_id_for_linking, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?, datetime('now'), ?)",
    )
    .bind(csrf_token.secret())
    .bind(pkce_value)
    .bind(Option::<String>::None)
    .bind(Option::<String>::None)
    .bind(Option::<String>::None)
    .bind(Option::<String>::None)
    .bind(&auth_user.user.id) // Set user_id_for_linking
    .bind(&expires_at)
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

    // Check how many identities the user has
    let identity_count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM identities WHERE user_id = ?",
    )
    .bind(&auth_user.user.id)
    .fetch_one(&state.pool)
    .await?;

    // Prevent account lockout by ensuring at least one identity remains
    if identity_count <= 1 {
        return Err(AppError::BadRequest(
            "Cannot unlink last identity. At least one identity must remain.".to_string(),
        ));
    }

    // Delete the identity
    let result = sqlx::query(
        "DELETE FROM identities WHERE user_id = ? AND provider = ?",
    )
    .bind(&auth_user.user.id)
    .bind(provider.as_str())
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Identity for provider '{}' not found",
            provider.as_str()
        )));
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}
