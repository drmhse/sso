use crate::auth::jwt::JwtService;
use crate::db::models::User;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::store::{DB, services::ServiceStore, sessions::SessionStore, users::UserStore};
use axum::{Json, extract::State, response::IntoResponse};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Re-export common types
pub use crate::error::Json400;

// Refresh Token Request
#[derive(Debug, Deserialize)]
pub struct RefreshTokenRequest {
    pub refresh_token: String,
}

// Refresh Token Response
#[derive(Debug, Serialize)]
pub struct RefreshTokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// Refresh Token: Exchange a refresh token for a new access token
/// Implements token rotation for enhanced security
pub async fn refresh_token(
    State(state): State<AppState>,
    Json400(req): Json400<RefreshTokenRequest>,
) -> Result<Json<RefreshTokenResponse>> {
    // Validate refresh token format (non-empty, reasonable length)
    if req.refresh_token.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Refresh token cannot be empty".to_string(),
        ));
    }

    if req.refresh_token.len() > 1000 {
        return Err(AppError::BadRequest("Refresh token too long".to_string()));
    }

    // Find the session by refresh token
    let session = SessionStore::find_by_refresh_token(DB::Conn(&state.db), &req.refresh_token)
        .await?
        .map(crate::db::models::Session::from)
        .ok_or_else(|| AppError::Unauthorized("Invalid refresh token".to_string()))?;

    // Check if refresh token has expired
    if let Some(refresh_expires_at) = &session.refresh_token_expires_at {
        if *refresh_expires_at < Utc::now() {
            // Token expired, clean up and deny
            SessionStore::delete(DB::Conn(&state.db), &session.id).await?;
            return Err(AppError::Unauthorized("Refresh token expired".to_string()));
        }
    } else {
        // No expiration set - invalid session
        return Err(AppError::Unauthorized("Invalid session".to_string()));
    }

    // Get the user
    let user = UserStore::find_by_id(DB::Conn(&state.db), &session.user_id)
        .await?
        .map(User::from)
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Reconstruct JWT with original session context
    // If service_id is present, get full service details
    let service_slug = if let Some(ref svc_id) = session.service_id {
        let service = ServiceStore::find_by_id(DB::Conn(&state.db), svc_id)
            .await?
            .map(crate::db::models::Service::from);

        service.map(|svc| svc.slug)
    } else {
        None
    };

    // Create new access token with preserved context
    let new_access_token = state.jwt_service.create_token(
        &user.id,
        &user.email,
        user.is_platform_owner,
        session.org_slug.as_deref(),
        service_slug.as_deref(),
    )?;

    // Implement token rotation: generate new refresh token
    let new_refresh_token = Uuid::new_v4().to_string();
    let new_token_hash = JwtService::hash_token(&new_access_token);
    let new_access_expires_at =
        Utc::now() + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let new_refresh_expires_at = Utc::now() + chrono::Duration::days(30);

    // Update session with new tokens (token rotation)
    SessionStore::update_tokens(
        DB::Conn(&state.db),
        &session.id,
        &req.refresh_token,
        &new_token_hash,
        new_access_expires_at.naive_utc(),
        &new_refresh_token,
        new_refresh_expires_at.naive_utc(),
    )
    .await?
    .then_some(())
    .ok_or_else(|| AppError::Unauthorized("Invalid refresh token".to_string()))?;

    Ok(Json(RefreshTokenResponse {
        access_token: new_access_token,
        refresh_token: new_refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
    }))
}

/// Logout: Invalidate JWT session
pub async fn logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse> {
    // Extract token from Authorization header
    let token = headers
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer "))
        .ok_or_else(|| {
            AppError::Unauthorized("Missing or invalid Authorization header".to_string())
        })?;

    // Hash token
    let token_hash = JwtService::hash_token(token);

    // Check for SAML SLO before deleting the session
    // Decode JWT to get claims and check for SAML state
    if let Ok(claims) = state.jwt_service.validate_token(token) {
        if let Some(saml_state_id) = &claims.saml_state {
            tracing::info!("User logout with SAML state detected, initiating SLO");

            // Retrieve SAML state information
            if let Ok(Some(saml_state)) =
                crate::store::saml_states::SamlStateStore::find_by_state_id(
                    crate::store::DB::Conn(&state.db),
                    saml_state_id,
                )
                .await
            {
                // Get service information to check for SLO configuration
                if let Ok(Some(service)) = crate::store::services::ServiceStore::find_by_id(
                    crate::store::DB::Conn(&state.db),
                    &saml_state.service_id,
                )
                .await
                {
                    // Check if service has SLO URL configured
                    if let Some(slo_url) = &service.saml_slo_url {
                        tracing::warn!(
                            slo_url = %slo_url,
                            user_id = %claims.sub,
                            "SAML SLO not implemented - user logged out locally but may remain authenticated at IdP. Full SLO requires SAML LogoutRequest generation and signing."
                        );
                    } else {
                        tracing::debug!(
                            "Service {} has SAML but no SLO URL configured",
                            service.id
                        );
                    }
                } else {
                    tracing::warn!(
                        "Service not found for SAML state: {}",
                        saml_state.service_id
                    );
                }
            } else {
                tracing::warn!("SAML state not found: {}", saml_state_id);
            }
        }
    }

    // Delete the session
    SessionStore::delete_by_token_hash(DB::Conn(&state.db), &token_hash).await?;

    Ok(Json(serde_json::json!({
        "message": "Logged out successfully"
    })))
}

// OAuth 2.0 Token Revocation Request (RFC 7009)
#[derive(Debug, Deserialize)]
pub struct RevokeTokenRequest {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>, // "access_token" or "refresh_token"
}

/// OAuth 2.0 Token Revocation Endpoint (RFC 7009)
/// Revokes access tokens or refresh tokens
/// Returns 200 OK regardless of token validity for security
pub async fn revoke_token(
    State(state): State<AppState>,
    axum::Form(req): axum::Form<RevokeTokenRequest>,
) -> impl IntoResponse {
    // Validate token format
    if req.token.trim().is_empty() || req.token.len() > 1000 {
        // RFC 7009: Return 200 OK even for invalid tokens to prevent token scanning
        return axum::http::StatusCode::OK;
    }

    // Determine token type from hint or try both
    let token_type = req.token_type_hint.as_deref().unwrap_or("access_token");

    match token_type {
        "refresh_token" => {
            // Try to revoke as refresh token
            if let Ok(Some(session)) =
                SessionStore::find_by_refresh_token(DB::Conn(&state.db), &req.token).await
            {
                let _ = SessionStore::delete(DB::Conn(&state.db), &session.id).await;
                tracing::info!(session_id = %session.id, "Refresh token revoked via RFC 7009");
            }
        }
        _ => {
            // Default: treat as access_token (JWT)
            let token_hash = JwtService::hash_token(&req.token);
            if let Ok(Some(_)) =
                SessionStore::find_by_token_hash(DB::Conn(&state.db), &token_hash).await
            {
                let _ = SessionStore::delete_by_token_hash(DB::Conn(&state.db), &token_hash).await;
                tracing::info!(token_hash = %token_hash, "Access token revoked via RFC 7009");
            }
        }
    }

    // Always return 200 OK per RFC 7009 (prevent token scanning attacks)
    axum::http::StatusCode::OK
}
