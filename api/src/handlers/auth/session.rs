use crate::auth::jwt::JwtService;
use crate::db::models::User;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::store::{services::ServiceStore, sessions::SessionStore, users::UserStore, DB};
use axum::{extract::State, response::IntoResponse, Json};
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
    let new_access_token = state.jwt_service.create_token_with_resource(
        &user.id,
        &user.email,
        user.is_platform_owner,
        session.org_slug.as_deref(),
        service_slug.as_deref(),
        session.resource.as_deref(),
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
                tracing::info!("Access token revoked via RFC 7009");
            }
        }
    }

    // Always return 200 OK per RFC 7009 (prevent token scanning attacks)
    axum::http::StatusCode::OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sso::OAuthClient;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::services::{
        audit_actor::AuditHandle, events::EventDispatcher, metrics::MfaMetricsService,
        risk_engine::RiskEngine,
    };
    use crate::store::{
        organizations::OrganizationStore,
        services::ServiceStore,
        sessions::SessionStore,
        users::{UserCreationOptions, UserStore},
    };
    use axum::extract::State;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use openssl::rsa::Rsa;
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

    fn test_jwt_service(config: &Config) -> JwtService {
        let rsa = Rsa::generate(2048).expect("generate test rsa key");
        let private_key = STANDARD.encode(
            rsa.private_key_to_pem()
                .expect("encode private key pem for tests"),
        );
        let public_key = STANDARD.encode(
            rsa.public_key_to_pem()
                .expect("encode public key pem for tests"),
        );

        JwtService::new(
            &private_key,
            &public_key,
            config.jwt_expiration_hours,
            "test-key",
            &config.base_url,
        )
        .expect("create test jwt service")
    }

    async fn setup_state() -> AppState {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));

        AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client,
            jwt_service,
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("create risk engine")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        }
    }

    #[tokio::test]
    async fn refresh_preserves_session_resource_audience() {
        let state = setup_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "resource-user@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            "acme",
            "Acme",
            &user.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create org");
        let service = ServiceStore::create(
            DB::Conn(&state.db),
            &org.id,
            "portal",
            "Portal",
            "web",
            "client-portal",
        )
        .await
        .expect("create service");
        let resource = "https://api.example.com/mcp";
        let access_token = state
            .jwt_service
            .create_token_with_resource(
                &user.id,
                &user.email,
                user.is_platform_owner,
                Some(&org.slug),
                Some(&service.slug),
                Some(resource),
            )
            .expect("create access token");
        let refresh = Uuid::new_v4().to_string();
        let now = Utc::now();
        SessionStore::create(
            DB::Conn(&state.db),
            &user.id,
            &JwtService::hash_token(&access_token),
            (now + chrono::Duration::hours(1)).naive_utc(),
            Some(&refresh),
            Some((now + chrono::Duration::days(30)).naive_utc()),
            Some(&org.slug),
            Some(&service.id),
            Some(resource),
            None,
            None,
        )
        .await
        .expect("create session");

        let Json(response) = refresh_token(
            State(state.clone()),
            Json400(RefreshTokenRequest {
                refresh_token: refresh,
            }),
        )
        .await
        .expect("refresh token");

        let claims = state
            .jwt_service
            .validate_token(&response.access_token)
            .expect("validate refreshed token");
        assert_eq!(claims.org.as_deref(), Some("acme"));
        assert_eq!(claims.service.as_deref(), Some("portal"));
        assert_eq!(claims.aud.as_deref(), Some(resource));
    }
}
