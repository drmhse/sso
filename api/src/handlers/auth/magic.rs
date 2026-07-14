use crate::error::{with_retrying_transaction, AppError, Result};
use crate::handlers::auth::email_delivery::ensure_email_delivery_configured;
use crate::handlers::auth::password::reject_upstream_only_local_auth;
use crate::middleware::RequestInfo;
use crate::state::AppState;
use crate::store::{
    magic_links::MagicLinksStore, memberships::MembershipStore, organizations::OrganizationStore,
    services::ServiceStore, sessions::SessionStore, users::UserStore, DB,
};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

// Import session response type
pub use super::session::RefreshTokenResponse;

// Magic Link Request
#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
    pub org_slug: Option<String>, // Optional: for organization context
    pub service_slug: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

// Magic Link Response
#[derive(Debug, Serialize)]
pub struct MagicLinkResponse {
    pub message: String,
}

// Verify Magic Link Query
#[derive(Debug, Deserialize)]
pub struct VerifyMagicLinkQuery {
    pub token: String,
    #[allow(dead_code)]
    pub redirect_uri: Option<String>, // Optional: where to redirect after success
    pub state: Option<String>,
}

fn build_magic_context(
    org_slug: Option<&str>,
    service_slug: Option<&str>,
    redirect_uri: Option<&str>,
    state: Option<&str>,
) -> String {
    if org_slug.is_none() && service_slug.is_none() && redirect_uri.is_none() && state.is_none() {
        return "default".to_string();
    }

    serde_json::json!({
        "org_slug": org_slug,
        "service_slug": service_slug,
        "redirect_uri": redirect_uri,
        "state": state,
    })
    .to_string()
}

fn parse_magic_context(
    context: &str,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    if context == "default" || context.is_empty() {
        return (None, None, None, None);
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(context) {
        let org_slug = value
            .get("org_slug")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let service_slug = value
            .get("service_slug")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let redirect_uri = value
            .get("redirect_uri")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let state = value
            .get("state")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        return (org_slug, service_slug, redirect_uri, state);
    }

    // Backward compatibility for older tokens where context was just org_slug.
    (Some(context.to_string()), None, None, None)
}

type BoundMagicContext = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn validate_magic_callback(
    context: &str,
    query: &VerifyMagicLinkQuery,
) -> Result<BoundMagicContext> {
    let (org_slug, service_slug, context_redirect_uri, context_state) =
        parse_magic_context(context);
    let redirect_uri = match (
        context_redirect_uri.as_deref(),
        query.redirect_uri.as_deref(),
    ) {
        (Some(bound), Some(requested)) if requested != bound => {
            return Err(AppError::BadRequest(
                "redirect_uri does not match the issued magic link".to_string(),
            ));
        }
        (Some(bound), _) => Some(bound.to_string()),
        (None, requested) => requested.map(str::to_string),
    };
    let callback_state = match (context_state.as_deref(), query.state.as_deref()) {
        (Some(bound), Some(requested)) if requested != bound => {
            return Err(AppError::BadRequest(
                "state does not match the issued magic link".to_string(),
            ));
        }
        (Some(bound), _) => Some(bound.to_string()),
        (None, requested) => requested.map(str::to_string),
    };
    Ok((org_slug, service_slug, redirect_uri, callback_state))
}

fn validate_service_redirect_uri(
    service: &crate::entities::services::Model,
    redirect_uri: &str,
) -> Result<()> {
    let allowed_uris_json = service.redirect_uris.as_ref().ok_or_else(|| {
        AppError::BadRequest("No redirect URIs are registered for this service".to_string())
    })?;

    let allowed_uris: Vec<String> = serde_json::from_str(allowed_uris_json)
        .map_err(|e| AppError::InternalServerError(format!("Invalid redirect_uris JSON: {}", e)))?;

    if allowed_uris.is_empty() {
        return Err(AppError::BadRequest(
            "No redirect URIs are registered for this service".to_string(),
        ));
    }

    if !allowed_uris.iter().any(|allowed| allowed == redirect_uri) {
        return Err(AppError::BadRequest(format!(
            "redirect_uri '{}' is not registered for this service",
            redirect_uri
        )));
    }

    Ok(())
}

async fn resolve_magic_service_context(
    db: &sea_orm::DatabaseConnection,
    org_slug: Option<&str>,
    service_slug: Option<&str>,
    redirect_uri: Option<&str>,
) -> Result<(
    Option<crate::entities::organizations::Model>,
    Option<crate::entities::services::Model>,
)> {
    if service_slug.is_some() && org_slug.is_none() {
        return Err(AppError::BadRequest(
            "service_slug requires org_slug".to_string(),
        ));
    }

    if redirect_uri.is_some() && service_slug.is_none() {
        return Err(AppError::BadRequest(
            "redirect_uri requires org_slug and service_slug".to_string(),
        ));
    }

    let Some(org_slug) = org_slug else {
        return Ok((None, None));
    };

    let org = OrganizationStore::find_by_slug(DB::Conn(db), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let org = crate::handlers::organizations::ensure_organization_active(db, &org.id).await?;

    if let Some(service_slug) = service_slug {
        let service = ServiceStore::find_by_org_and_slug(DB::Conn(db), &org.id, service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

        if let Some(redirect_uri) = redirect_uri {
            validate_service_redirect_uri(&service, redirect_uri)?;
        }

        return Ok((Some(org), Some(service)));
    }

    Ok((Some(org), None))
}

async fn validate_magic_scope_at_consume(
    db: DB<'_>,
    user: &crate::entities::users::Model,
    org_id: Option<&str>,
    service_id: Option<&str>,
) -> Result<()> {
    let user = UserStore::find_by_id(db.clone(), &user.id)
        .await?
        .filter(|user| user.deleted_at.is_none())
        .ok_or_else(|| AppError::BadRequest("Invalid or expired magic link".to_string()))?;
    let Some(org_id) = org_id else {
        if service_id.is_some() {
            return Err(AppError::BadRequest(
                "Magic link service context is missing its organization".to_string(),
            ));
        }
        return Ok(());
    };
    let org = OrganizationStore::find_by_id(db.clone(), org_id)
        .await?
        .filter(|org| org.status == "active")
        .ok_or_else(|| AppError::Forbidden("Organization is not active".to_string()))?;
    if let Some(service_id) = service_id {
        let service = ServiceStore::find_by_id(db.clone(), service_id)
            .await?
            .filter(|service| service.org_id == org.id)
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
        if !user.is_platform_owner {
            use crate::entities::{identities, prelude::Identities};
            use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
            if Identities::find()
                .filter(identities::Column::UserId.eq(&user.id))
                .filter(identities::Column::IssuingOrgId.eq(&org.id))
                .filter(identities::Column::IssuingServiceId.eq(&service.id))
                .one(&db)
                .await?
                .is_none()
            {
                return Err(AppError::Forbidden(
                    "You do not have access to this service".to_string(),
                ));
            }
        }
    } else if !user.is_platform_owner {
        MembershipStore::find_by_org_and_user(db.clone(), &org.id, &user.id)
            .await?
            .ok_or_else(|| {
                AppError::Forbidden("You are not a member of this organization".to_string())
            })?;
    }
    Ok(())
}

async fn consume_magic_link(
    state: &AppState,
    token: &str,
    user: &crate::entities::users::Model,
    org_id: Option<&str>,
    service_id: Option<&str>,
) -> Result<()> {
    let token = token.to_string();
    let user = user.clone();
    let org_id = org_id.map(str::to_string);
    let service_id = service_id.map(str::to_string);
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "consume_magic_link",
        |db| {
            let token = token.clone();
            let user = user.clone();
            let org_id = org_id.clone();
            let service_id = service_id.clone();
            Box::pin(async move {
                validate_magic_scope_at_consume(
                    db.clone(),
                    &user,
                    org_id.as_deref(),
                    service_id.as_deref(),
                )
                .await?;
                if !MagicLinksStore::delete(db, &token).await? {
                    return Err(AppError::BadRequest(
                        "Invalid or expired magic link".to_string(),
                    ));
                }
                Ok(())
            })
        },
    )
    .await
}

async fn ensure_magic_context_access(
    db: &sea_orm::DatabaseConnection,
    user: &crate::entities::users::Model,
    org: Option<&crate::entities::organizations::Model>,
    service: Option<&crate::entities::services::Model>,
) -> Result<()> {
    let Some(org) = org else {
        return Ok(());
    };
    if user.is_platform_owner {
        return Ok(());
    }
    if let Some(service) = service {
        use crate::entities::{identities, prelude::Identities};
        use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
        if Identities::find()
            .filter(identities::Column::UserId.eq(&user.id))
            .filter(identities::Column::IssuingOrgId.eq(&org.id))
            .filter(identities::Column::IssuingServiceId.eq(&service.id))
            .one(db)
            .await?
            .is_none()
        {
            return Err(AppError::Forbidden(
                "You do not have access to this service".to_string(),
            ));
        }
    } else {
        MembershipStore::find_by_org_and_user(DB::Conn(db), &org.id, &user.id)
            .await?
            .ok_or_else(|| {
                AppError::Forbidden("You are not a member of this organization".to_string())
            })?;
    }
    Ok(())
}

/// POST /api/auth/magic-link/request - Request a magic link
///
/// This endpoint generates a magic link token and sends it to the user's email.
/// For security, it always returns success regardless of whether the email exists.
#[axum::debug_handler]
pub async fn request_magic_link(
    State(state): State<AppState>,
    Extension(_request_info): Extension<RequestInfo>,
    Json(req): Json<MagicLinkRequest>,
) -> Result<Json<MagicLinkResponse>> {
    ensure_email_delivery_configured(&state, "magic-link sign-in")?;

    // Validate email format
    if req.email.is_empty() || !req.email.contains('@') {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Check rate limiting (only if rate limiting is enabled)
    // Rate limiting is disabled when DISABLE_RATE_LIMITING=true is set
    if std::env::var("DISABLE_RATE_LIMITING")
        .unwrap_or_default()
        .to_lowercase()
        != "true"
        && crate::middleware::EMAIL_RATE_LIMITER
            .is_rate_limited_email(&req.email)
            .await
    {
        return Err(AppError::TooManyRequests(
            "Too many magic link requests. Please try again later.".to_string(),
        ));
    }

    let context = build_magic_context(
        req.org_slug.as_deref(),
        req.service_slug.as_deref(),
        req.redirect_uri.as_deref(),
        req.state.as_deref(),
    );
    let (issuing_org, _issuing_service) = resolve_magic_service_context(
        &state.db,
        req.org_slug.as_deref(),
        req.service_slug.as_deref(),
        req.redirect_uri.as_deref(),
    )
    .await?;
    let issuing_org_id = issuing_org.as_ref().map(|org| org.id.as_str());
    reject_upstream_only_local_auth(&state, &req.email, issuing_org_id, "Magic-link sign-in")
        .await?;

    // Service-scoped magic links must resolve the tenant user, not a same-email
    // platform or sibling-organization user.
    let user = if issuing_org_id.is_some() {
        UserStore::find_by_email_with_context(DB::Conn(&state.db), &req.email, issuing_org_id)
            .await?
    } else {
        UserStore::find_by_email_with_context(DB::Conn(&state.db), &req.email, None).await?
    };

    // Generate magic link token
    let token = MagicLinksStore::create(
        DB::Conn(&state.db),
        &req.email,
        user.as_ref().map(|u| u.id.as_str()),
        &context,
    )
    .await?;

    // Send magic link email via job queue
    let magic_link_url = {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params.append_pair("token", &token);
        if let Some(redirect_uri) = req.redirect_uri.as_deref() {
            params.append_pair("redirect_uri", redirect_uri);
        }
        if let Some(org_slug) = req.org_slug.as_deref() {
            params.append_pair("org", org_slug);
        }
        if let Some(service_slug) = req.service_slug.as_deref() {
            params.append_pair("service", service_slug);
        }
        if let Some(state) = req.state.as_deref() {
            params.append_pair("state", state);
        }

        format!(
            "{}/auth/magic-link/verify?{}",
            state.web_client_url.trim_end_matches('/'),
            params.finish()
        )
    };
    let email_subject = "Your Magic Sign-In Link".to_string();
    let email_body = format!(
        "Click the link below to sign in:\n\n{}\n\n\
         This link will expire in 15 minutes.\n\n\
         If you didn't request this link, you can safely ignore this email.",
        magic_link_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &req.email,
        &email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::warn!(
            user_id = ?user.as_ref().map(|u| u.id.as_str()),
            error = %e,
            "Failed to enqueue magic link email"
        );
    } else {
        tracing::info!(
            user_id = ?user.as_ref().map(|u| u.id.as_str()),
            "Magic link email enqueued successfully"
        );
    }

    // Always return success to avoid leaking whether email exists
    Ok(Json(MagicLinkResponse {
        message: "If the email exists, a magic link has been sent.".to_string(),
    }))
}

/// GET /api/auth/magic-link/verify - Verify a magic link token
///
/// This endpoint validates a magic link token, runs risk assessment,
/// and issues a JWT token on success.
#[axum::debug_handler]
pub async fn verify_magic_link(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Query(query): Query<VerifyMagicLinkQuery>,
) -> Result<impl IntoResponse> {
    // Find the magic link token
    let magic_link = MagicLinksStore::find_by_token(DB::Conn(&state.db), &query.token)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid or expired magic link".to_string()))?;

    // Check if token is expired
    let expires_at: chrono::DateTime<Utc> =
        chrono::DateTime::from_naive_utc_and_offset(magic_link.expires_at, chrono::Utc);

    if expires_at < Utc::now() {
        // Delete expired token
        let _ = MagicLinksStore::delete(DB::Conn(&state.db), &query.token).await;
        return Err(AppError::BadRequest("Magic link has expired".to_string()));
    }

    // Find or create user
    let user = if let Some(user_id) = &magic_link.user_id {
        UserStore::find_by_id(DB::Conn(&state.db), user_id)
            .await?
            .filter(|user| user.deleted_at.is_none())
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
    } else {
        // Auto-create user if email verification is not required
        // For now, we require the user to exist
        return Err(AppError::BadRequest(
            "User not found. Please register first.".to_string(),
        ));
    };

    let (org_slug_owned, service_slug_owned, redirect_uri_owned, callback_state_owned) =
        validate_magic_callback(&magic_link.context, &query)?;
    let org_slug = org_slug_owned.as_deref();
    let service_slug = service_slug_owned.as_deref();
    let redirect_uri = redirect_uri_owned.as_deref();
    let callback_state = callback_state_owned.as_deref();

    let (resolved_org, resolved_service) =
        resolve_magic_service_context(&state.db, org_slug, service_slug, redirect_uri).await?;
    let resolved_org_id = resolved_org.as_ref().map(|org| org.id.as_str());

    reject_upstream_only_local_auth(
        &state,
        &user.email,
        resolved_org_id.or(user.org_id.as_deref()),
        "Magic-link sign-in",
    )
    .await?;

    ensure_magic_context_access(
        &state.db,
        &user,
        resolved_org.as_ref(),
        resolved_service.as_ref(),
    )
    .await?;

    // All callback, tenant, service, local-auth, and access checks are complete
    // before risk evaluation and the one-time consume boundary.
    use crate::services::risk_engine::RiskContext;
    let risk_ctx = RiskContext {
        user_id: &user.id,
        org_id: resolved_org_id,
        ip_address: &request_info.ip_address,
        user_agent: &request_info.user_agent,
        device_cookie: None,
    };
    let risk_assessment = state
        .risk_engine
        .evaluate(DB::Conn(&state.db), risk_ctx)
        .await?;

    tracing::info!(
        user_id = %user.id,
        risk_score = risk_assessment.score,
        risk_action = ?risk_assessment.action,
        risk_factors = ?risk_assessment.factors,
        "Magic link authentication risk assessment"
    );

    let service_id = resolved_service.as_ref().map(|service| service.id.as_str());

    // Take action based on risk
    use crate::services::risk_engine::RiskAction;
    match risk_assessment.action {
        RiskAction::Allow | RiskAction::LogOnly => {
            // Generate JWT token with org context from magic link (Security Audit Item 4)
            let token = state.jwt_service.create_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                org_slug,
                service_slug,
            )?;

            // Create session with refresh token
            let token_hash = hash_token(&token);
            let refresh_token = crate::auth::refresh_tokens::generate();
            let now = Utc::now();
            let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
            let refresh_expires_at = now + chrono::Duration::days(30);

            // Generate device trust cookie
            let device_token = state.risk_engine.generate_device_token(&user.id);
            let device_cookie_value = format!(
                "device_token={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
                device_token,
                90 * 24 * 3600 // 90 days in seconds
            );

            // Store device in database
            use crate::store::user_devices::UserDevicesStore;
            use sha2::{Digest, Sha256};

            let mut hasher = Sha256::new();
            hasher.update(device_token.as_bytes());
            let device_token_hash = hex::encode(hasher.finalize());
            let device_expires_at = (Utc::now() + chrono::Duration::days(90)).naive_utc();

            // Consume, session creation, and device trust creation commit as
            // one unit. Any database failure rolls the token consumption back,
            // while concurrent verification still has exactly one winner.
            let magic_token = query.token.clone();
            let user_id = user.id.clone();
            let user_for_tx = user.clone();
            let session_token_hash = token_hash.clone();
            let refresh_token_for_tx = refresh_token.clone();
            let org_slug_for_tx = org_slug_owned.clone();
            let service_id_for_tx = service_id.map(str::to_string);
            let org_id_for_tx = resolved_org_id.map(str::to_string);
            let device_token_hash_for_tx = device_token_hash.clone();
            let request_ip = request_info.ip_address.clone();
            with_retrying_transaction(
                &state.db,
                #[cfg(feature = "db_sqlite")]
                &state.db_writer,
                "complete_magic_link",
                |db| {
                    let magic_token = magic_token.clone();
                    let user_id = user_id.clone();
                    let user = user_for_tx.clone();
                    let session_token_hash = session_token_hash.clone();
                    let refresh_token = refresh_token_for_tx.clone();
                    let org_slug = org_slug_for_tx.clone();
                    let service_id = service_id_for_tx.clone();
                    let org_id = org_id_for_tx.clone();
                    let device_token_hash = device_token_hash_for_tx.clone();
                    let request_ip = request_ip.clone();
                    Box::pin(async move {
                        validate_magic_scope_at_consume(
                            db.clone(),
                            &user,
                            org_id.as_deref(),
                            service_id.as_deref(),
                        )
                        .await?;
                        if !MagicLinksStore::delete(db.clone(), &magic_token).await? {
                            return Err(AppError::BadRequest(
                                "Invalid or expired magic link".to_string(),
                            ));
                        }
                        SessionStore::create(
                            db.clone(),
                            &user_id,
                            &session_token_hash,
                            expires_at.naive_utc(),
                            Some(&refresh_token),
                            Some(refresh_expires_at.naive_utc()),
                            org_slug.as_deref(),
                            service_id.as_deref(),
                            None,
                            None,
                            None,
                        )
                        .await?;
                        UserDevicesStore::create(
                            db,
                            &user_id,
                            &device_token_hash,
                            "Magic Link Device",
                            Some(request_ip),
                            device_expires_at,
                        )
                        .await?;
                        Ok(())
                    })
                },
            )
            .await?;

            tracing::info!(
                user_id = %user.id,
                risk_score = risk_assessment.score,
                risk_factors = ?risk_assessment.factors,
                ip_address = %request_info.ip_address,
                "Magic link authentication successful"
            );

            // Return token as JSON (with Set-Cookie header for device trust)
            let response = Json(RefreshTokenResponse {
                access_token: token,
                refresh_token,
                expires_in: state.config.jwt_expiration_hours * 3600,
            });

            Ok((
                StatusCode::OK,
                [(header::SET_COOKIE, device_cookie_value)],
                response,
            )
                .into_response())
        }

        RiskAction::ChallengeMFA => {
            // Issue pre-auth token requiring MFA
            let preauth_token = state.jwt_service.create_mfa_preauth_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                org_slug,
                service_slug,
                None,
            )?;
            consume_magic_link(&state, &query.token, &user, resolved_org_id, service_id).await?;

            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "requires_mfa": true,
                    "preauth_token": preauth_token,
                    "state": callback_state,
                    "message": "Additional verification required"
                })),
            )
                .into_response())
        }

        RiskAction::Block => {
            consume_magic_link(&state, &query.token, &user, resolved_org_id, service_id).await?;
            tracing::warn!(
                user_id = %user.id,
                risk_score = risk_assessment.score,
                factors = ?risk_assessment.factors,
                "Magic link authentication blocked by risk engine"
            );

            Err(AppError::Forbidden(
                "Suspicious login detected. Please contact support.".to_string(),
            ))
        }
    }
}

/// Helper function to hash JWT tokens for session tracking
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::identities;
    use crate::store::users::{UserCreationOptions, UserStore};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, Set};
    use uuid::Uuid;

    async fn setup_magic_scope() -> (
        sea_orm::DatabaseConnection,
        crate::entities::organizations::Model,
        crate::entities::users::Model,
    ) {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "magic-owner@example.com",
            UserCreationOptions::default(),
        )
        .await
        .expect("create owner")
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "magic-org",
            "Magic Org",
            &owner.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        let user =
            UserStore::create_with_org_id(DB::Conn(&db), "magic-user@example.com", None, &org.id)
                .await
                .expect("create tenant user");
        MembershipStore::create(DB::Conn(&db), &org.id, &user.id, "member")
            .await
            .expect("create membership");
        (db, org, user)
    }

    #[tokio::test]
    async fn malformed_callback_and_suspension_after_issuance_preserve_magic_link() {
        let (db, org, user) = setup_magic_scope().await;
        let context = build_magic_context(Some(&org.slug), None, None, Some("bound-state"));
        let token = MagicLinksStore::create(DB::Conn(&db), &user.email, Some(&user.id), &context)
            .await
            .expect("issue magic link");
        let wrong_callback = VerifyMagicLinkQuery {
            token: token.clone(),
            redirect_uri: None,
            state: Some("wrong-state".to_string()),
        };
        assert!(matches!(
            validate_magic_callback(&context, &wrong_callback),
            Err(AppError::BadRequest(_))
        ));
        assert!(MagicLinksStore::find_by_token(DB::Conn(&db), &token)
            .await
            .expect("reload after malformed callback")
            .is_some());

        resolve_magic_service_context(&db, Some(&org.slug), None, None)
            .await
            .expect("active scope resolves");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend after issuance");
        assert!(matches!(
            resolve_magic_service_context(&db, Some(&org.slug), None, None).await,
            Err(AppError::Forbidden(_))
        ));
        assert!(MagicLinksStore::find_by_token(DB::Conn(&db), &token)
            .await
            .expect("reload after suspended verification")
            .is_some());
    }

    #[tokio::test]
    async fn same_email_and_cross_service_context_cannot_select_or_consume_wrong_identity() {
        let (db, org, tenant_user) = setup_magic_scope().await;
        let platform_user = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            &tenant_user.email,
            UserCreationOptions::default(),
        )
        .await
        .expect("create same-email platform user")
        .0;
        let selected =
            UserStore::find_by_email_with_context(DB::Conn(&db), &tenant_user.email, Some(&org.id))
                .await
                .expect("select tenant user")
                .expect("tenant user exists");
        assert_eq!(selected.id, tenant_user.id);
        assert_ne!(selected.id, platform_user.id);

        let service_a = ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "service-a",
            "Service A",
            "web",
            "magic-client-a",
        )
        .await
        .expect("create service A");
        let service_b = ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "service-b",
            "Service B",
            "web",
            "magic-client-b",
        )
        .await
        .expect("create service B");
        identities::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(tenant_user.id.clone()),
            provider: Set("google".to_string()),
            provider_user_id: Set("magic-provider-user".to_string()),
            issuing_org_id: Set(Some(org.id.clone())),
            issuing_service_id: Set(Some(service_b.id.clone())),
            created_at: Set(Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .expect("create service B identity");
        let context = build_magic_context(Some(&org.slug), Some(&service_a.slug), None, None);
        let token = MagicLinksStore::create(
            DB::Conn(&db),
            &tenant_user.email,
            Some(&tenant_user.id),
            &context,
        )
        .await
        .expect("issue service A link");
        assert!(matches!(
            ensure_magic_context_access(&db, &tenant_user, Some(&org), Some(&service_a)).await,
            Err(AppError::Forbidden(_))
        ));
        assert!(MagicLinksStore::find_by_token(DB::Conn(&db), &token)
            .await
            .expect("reload cross-service denied token")
            .is_some());
    }
}
