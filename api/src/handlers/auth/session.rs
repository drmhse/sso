use crate::auth::jwt::JwtService;
use crate::error::{with_retrying_transaction, AppError, Result};
use crate::state::AppState;
use crate::store::{
    identities::IdentityStore,
    memberships::MembershipStore,
    organizations::OrganizationStore,
    services::ServiceStore,
    sessions::{RefreshRotationOutcome, SessionStore},
    users::UserStore,
    DB,
};
use axum::{extract::State, response::IntoResponse, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};

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

async fn validate_refresh_authority(
    db: DB<'_>,
    session: &crate::entities::sessions::Model,
) -> Result<(crate::entities::users::Model, Option<String>)> {
    let denied = || AppError::Unauthorized("Invalid refresh token".to_string());
    if session
        .refresh_token_expires_at
        .is_none_or(|expires_at| expires_at <= Utc::now().naive_utc())
    {
        return Err(denied());
    }
    let user = UserStore::find_by_id(db.clone(), &session.user_id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(denied)?;

    match (session.org_slug.as_deref(), session.service_id.as_deref()) {
        (None, None) => {
            if session.resource.is_some() {
                return Err(denied());
            }
            Ok((user, None))
        }
        (None, Some(_)) => Err(denied()),
        (Some(org_slug), service_id) => {
            let org = OrganizationStore::find_by_slug(db.clone(), org_slug)
                .await?
                .filter(|org| org.status == "active")
                .ok_or_else(denied)?;
            if let Some(service_id) = service_id {
                let service = ServiceStore::find_by_id(db.clone(), service_id)
                    .await?
                    .filter(|service| service.org_id == org.id)
                    .ok_or_else(denied)?;
                if !user.is_platform_owner
                    && !IdentityStore::exists_for_user_and_service_context(
                        db.clone(),
                        &user.id,
                        &org.id,
                        &service.id,
                    )
                    .await?
                {
                    return Err(denied());
                }
                if let Some(resource) = session.resource.as_deref() {
                    crate::utils::resource_indicators::validate_requested_resource(
                        Some(resource),
                        service.resource_uris.as_deref(),
                    )
                    .map_err(|_| denied())?;
                }
                Ok((user, Some(service.slug)))
            } else {
                if session.resource.is_some()
                    || (!user.is_platform_owner
                        && MembershipStore::find_by_org_and_user(db.clone(), &org.id, &user.id)
                            .await?
                            .is_none())
                {
                    return Err(denied());
                }
                Ok((user, None))
            }
        }
    }
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
    let session = match SessionStore::find_by_refresh_token(DB::Conn(&state.db), &req.refresh_token)
        .await?
    {
        Some(session) => session,
        None => {
            // An ancestor hash identifies its session family without retaining
            // any bearer value. Replaying it revokes the family's current token.
            SessionStore::revoke_if_consumed_refresh_token(DB::Conn(&state.db), &req.refresh_token)
                .await?;
            return Err(AppError::Unauthorized("Invalid refresh token".to_string()));
        }
    };

    // Check if refresh token has expired
    if let Some(refresh_expires_at) = &session.refresh_token_expires_at {
        if *refresh_expires_at < Utc::now().naive_utc() {
            // Token expired, clean up and deny
            SessionStore::delete(DB::Conn(&state.db), &session.id).await?;
            return Err(AppError::Unauthorized("Refresh token expired".to_string()));
        }
    } else {
        // No expiration set - invalid session
        return Err(AppError::Unauthorized("Invalid session".to_string()));
    }

    // Re-read live authority and rotate in the same database transaction. A
    // denied context leaves the refresh family unchanged; a concurrent winner
    // still triggers the existing reuse-detection family revocation.
    let session_id = session.id.clone();
    let presented_refresh_token = req.refresh_token.clone();
    let (rotation, response) = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "refresh_session_with_live_authority",
        |db| {
            let session_id = session_id.clone();
            let presented_refresh_token = presented_refresh_token.clone();
            let jwt_service = state.jwt_service.clone();
            let expiration_hours = state.config.jwt_expiration_hours;
            Box::pin(async move {
                let current_session = SessionStore::find_by_id(db.clone(), &session_id)
                    .await?
                    .ok_or_else(|| AppError::Unauthorized("Invalid refresh token".to_string()))?;
                let (user, service_slug) =
                    validate_refresh_authority(db.clone(), &current_session).await?;
                let access_token = jwt_service.create_token_with_resource(
                    &user.id,
                    &user.email,
                    user.is_platform_owner,
                    current_session.org_slug.as_deref(),
                    service_slug.as_deref(),
                    current_session.resource.as_deref(),
                )?;
                let refresh_token = crate::auth::refresh_tokens::generate();
                let token_hash = JwtService::hash_token(&access_token);
                let access_expires_at = Utc::now() + chrono::Duration::hours(expiration_hours);
                let refresh_expires_at = Utc::now() + chrono::Duration::days(30);
                let rotation = SessionStore::update_tokens(
                    db,
                    &current_session.id,
                    &presented_refresh_token,
                    &token_hash,
                    access_expires_at.naive_utc(),
                    &refresh_token,
                    refresh_expires_at.naive_utc(),
                )
                .await?;
                let response =
                    (rotation == RefreshRotationOutcome::Rotated).then_some(RefreshTokenResponse {
                        access_token,
                        refresh_token,
                        expires_in: expiration_hours * 3600,
                    });
                Ok((rotation, response))
            })
        },
    )
    .await?;
    if rotation == RefreshRotationOutcome::ReuseDetected {
        return Err(AppError::Unauthorized("Invalid refresh token".to_string()));
    }
    Ok(Json(response.ok_or_else(|| {
        AppError::Unauthorized("Invalid refresh token".to_string())
    })?))
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
    if let Ok(claims) = state.jwt_service.validate_authos_token(token) {
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
            } else {
                // A consumed ancestor still identifies and revokes its current
                // family without revealing whether the token was recognized.
                let _ =
                    SessionStore::revoke_if_consumed_refresh_token(DB::Conn(&state.db), &req.token)
                        .await;
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
        identities::IdentityStore,
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

    struct RefreshFixture {
        user: crate::entities::users::Model,
        org: crate::entities::organizations::Model,
        service: crate::entities::services::Model,
        identity_id: String,
        refresh_token: String,
        session_id: String,
    }

    async fn service_refresh_fixture(
        state: &AppState,
        suffix: &str,
        email: &str,
    ) -> RefreshFixture {
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            email,
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .unwrap()
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            &format!("org-{suffix}"),
            &format!("Org {suffix}"),
            &user.id,
            Some("tier_enterprise"),
        )
        .await
        .unwrap();
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .unwrap();
        let service = ServiceStore::create(
            DB::Conn(&state.db),
            &org.id,
            &format!("service-{suffix}"),
            &format!("Service {suffix}"),
            "web",
            &format!("client-{suffix}"),
        )
        .await
        .unwrap();
        let resource = format!("https://api.example.test/{suffix}");
        let resources = serde_json::to_string(&vec![resource.as_str()]).unwrap();
        ServiceStore::update_dynamic(
            DB::Conn(&state.db),
            &org.id,
            &service.slug,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&resources),
        )
        .await
        .unwrap();
        let identity = IdentityStore::create(
            DB::Conn(&state.db),
            &user.id,
            "oauth",
            &format!("provider-user-{suffix}"),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org.id),
            Some(&service.id),
        )
        .await
        .unwrap();
        let access_token = state
            .jwt_service
            .create_token_with_resource(
                &user.id,
                &user.email,
                user.is_platform_owner,
                Some(&org.slug),
                Some(&service.slug),
                Some(&resource),
            )
            .unwrap();
        let refresh_token = crate::auth::refresh_tokens::generate();
        let now = Utc::now();
        let session = SessionStore::create(
            DB::Conn(&state.db),
            &user.id,
            &JwtService::hash_token(&access_token),
            (now + chrono::Duration::hours(1)).naive_utc(),
            Some(&refresh_token),
            Some((now + chrono::Duration::days(30)).naive_utc()),
            Some(&org.slug),
            Some(&service.id),
            Some(&resource),
            None,
            None,
        )
        .await
        .unwrap();
        RefreshFixture {
            user,
            org,
            service,
            identity_id: identity.id,
            refresh_token,
            session_id: session.id,
        }
    }

    async fn assert_refresh_denied_without_rotation(state: &AppState, fixture: &RefreshFixture) {
        let before = SessionStore::find_by_id(DB::Conn(&state.db), &fixture.session_id)
            .await
            .unwrap()
            .unwrap();
        let denied = refresh_token(
            State(state.clone()),
            Json400(RefreshTokenRequest {
                refresh_token: fixture.refresh_token.clone(),
            }),
        )
        .await;
        assert!(matches!(denied, Err(AppError::Unauthorized(_))));
        let after =
            SessionStore::find_by_refresh_token(DB::Conn(&state.db), &fixture.refresh_token)
                .await
                .unwrap()
                .expect("denied refresh leaves current family unchanged");
        assert_eq!(after.id, before.id);
        assert_eq!(after.token_hash, before.token_hash);
        assert_eq!(after.refresh_token_hash, before.refresh_token_hash);
    }

    #[tokio::test]
    async fn refresh_revalidates_every_live_tenant_resource_binding() {
        use sea_orm::{ActiveModelTrait, EntityTrait, Set};

        let state = setup_state().await;

        let removed = service_refresh_fixture(&state, "removed", "removed@example.test").await;
        crate::entities::identities::Entity::delete_by_id(&removed.identity_id)
            .exec(&state.db)
            .await
            .unwrap();
        assert_refresh_denied_without_rotation(&state, &removed).await;

        let suspended =
            service_refresh_fixture(&state, "suspended", "suspended@example.test").await;
        OrganizationStore::update_status(DB::Conn(&state.db), &suspended.org.id, "suspended")
            .await
            .unwrap();
        assert_refresh_denied_without_rotation(&state, &suspended).await;

        let reparented =
            service_refresh_fixture(&state, "reparented", "reparented@example.test").await;
        let (other_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            "other-parent",
            "Other Parent",
            &reparented.user.id,
            Some("tier_enterprise"),
        )
        .await
        .unwrap();
        let mut moved: crate::entities::services::ActiveModel = reparented.service.clone().into();
        moved.org_id = Set(other_org.id);
        moved.update(&state.db).await.unwrap();
        assert_refresh_denied_without_rotation(&state, &reparented).await;

        let deregistered =
            service_refresh_fixture(&state, "deregistered", "deregistered@example.test").await;
        ServiceStore::update_dynamic(
            DB::Conn(&state.db),
            &deregistered.org.id,
            &deregistered.service.slug,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some("[]"),
        )
        .await
        .unwrap();
        assert_refresh_denied_without_rotation(&state, &deregistered).await;

        let same_email = service_refresh_fixture(&state, "same-email", "shared@example.test").await;
        let (sibling_org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            "sibling-org",
            "Sibling Org",
            &same_email.user.id,
            Some("tier_enterprise"),
        )
        .await
        .unwrap();
        let sibling = UserStore::create_with_org_id(
            DB::Conn(&state.db),
            &same_email.user.email,
            None,
            &sibling_org.id,
        )
        .await
        .unwrap();
        let Json(rotated) = refresh_token(
            State(state.clone()),
            Json400(RefreshTokenRequest {
                refresh_token: same_email.refresh_token,
            }),
        )
        .await
        .expect("same-email sibling cannot replace session subject");
        let claims = state
            .jwt_service
            .validate_token_for_audience(
                &rotated.access_token,
                "https://api.example.test/same-email",
            )
            .unwrap();
        assert_eq!(claims.sub, same_email.user.id);
        assert_ne!(claims.sub, sibling.id);
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
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .expect("activate org");
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
        let resources = serde_json::to_string(&vec![resource]).unwrap();
        ServiceStore::update_dynamic(
            DB::Conn(&state.db),
            &org.id,
            &service.slug,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&resources),
        )
        .await
        .expect("register resource");
        IdentityStore::create(
            DB::Conn(&state.db),
            &user.id,
            "oauth",
            "resource-user",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org.id),
            Some(&service.id),
        )
        .await
        .expect("create exact service identity");
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
        let refresh = crate::auth::refresh_tokens::generate();
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
                refresh_token: refresh.clone(),
            }),
        )
        .await
        .expect("refresh token");

        let claims = state
            .jwt_service
            .validate_token_for_audience(&response.access_token, resource)
            .expect("validate refreshed token");
        assert_eq!(claims.org.as_deref(), Some("acme"));
        assert_eq!(claims.service.as_deref(), Some("portal"));
        assert_eq!(claims.aud.as_deref(), Some(resource));

        let rotated =
            SessionStore::find_by_refresh_token(DB::Conn(&state.db), &response.refresh_token)
                .await
                .unwrap()
                .expect("rotated session");
        assert_eq!(rotated.refresh_token, None);
        assert_eq!(
            rotated.refresh_token_hash.as_deref(),
            Some(crate::auth::refresh_tokens::hash(&response.refresh_token).as_str())
        );

        let replay = refresh_token(
            State(state.clone()),
            Json400(RefreshTokenRequest {
                refresh_token: refresh,
            }),
        )
        .await;
        assert!(matches!(replay, Err(AppError::Unauthorized(_))));
        assert!(
            SessionStore::find_by_refresh_token(DB::Conn(&state.db), &response.refresh_token,)
                .await
                .unwrap()
                .is_none()
        );

        let expired_access = state
            .jwt_service
            .create_token(&user.id, &user.email, false, Some(&org.slug), None)
            .unwrap();
        let expired_refresh = crate::auth::refresh_tokens::generate();
        let expired_session = SessionStore::create(
            DB::Conn(&state.db),
            &user.id,
            &JwtService::hash_token(&expired_access),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            Some(&expired_refresh),
            Some((Utc::now() - chrono::Duration::seconds(1)).naive_utc()),
            Some(&org.slug),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let expired = refresh_token(
            State(state.clone()),
            Json400(RefreshTokenRequest {
                refresh_token: expired_refresh,
            }),
        )
        .await;
        assert!(matches!(
            expired,
            Err(AppError::Unauthorized(ref message)) if message.contains("expired")
        ));
        assert!(
            SessionStore::find_by_id(DB::Conn(&state.db), &expired_session.id)
                .await
                .unwrap()
                .is_none()
        );

        let logout_access = state
            .jwt_service
            .create_token(&user.id, &user.email, false, Some(&org.slug), None)
            .unwrap();
        let logout_refresh = crate::auth::refresh_tokens::generate();
        let logout_session = SessionStore::create(
            DB::Conn(&state.db),
            &user.id,
            &JwtService::hash_token(&logout_access),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            Some(&logout_refresh),
            Some((Utc::now() + chrono::Duration::days(30)).naive_utc()),
            Some(&org.slug),
            None,
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {logout_access}").parse().unwrap(),
        );
        logout(State(state.clone()), headers).await.unwrap();
        assert!(
            SessionStore::find_by_id(DB::Conn(&state.db), &logout_session.id)
                .await
                .unwrap()
                .is_none()
        );
    }
}
