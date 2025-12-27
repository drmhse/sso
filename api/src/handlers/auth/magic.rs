use crate::constants::JWT_EXPIRE_HOURS;
use crate::error::{AppError, Result};
use crate::middleware::RequestInfo;
use crate::state::AppState;
use crate::store::{magic_links::MagicLinksStore, sessions::SessionStore, users::UserStore, DB};
use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Import session response type
pub use super::session::RefreshTokenResponse;

// Magic Link Request
#[derive(Debug, Deserialize)]
pub struct MagicLinkRequest {
    pub email: String,
    pub org_slug: Option<String>, // Optional: for organization context
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

    // Find user by email
    let user = UserStore::find_by_email(DB::Conn(&state.db), &req.email).await?;

    // Generate magic link token
    let token = MagicLinksStore::create(
        DB::Conn(&state.db),
        &req.email,
        user.as_ref().map(|u| u.id.as_str()),
        req.org_slug.as_deref().unwrap_or("default"),
    )
    .await?;

    // Send magic link email via job queue
    let magic_link_url = format!(
        "{}/auth/magic-link/verify?token={}",
        state.web_client_url, token
    );
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
            email = %req.email,
            error = %e,
            "Failed to enqueue magic link email"
        );
    } else {
        tracing::info!(
            email = %req.email,
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
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
    } else {
        // Auto-create user if email verification is not required
        // For now, we require the user to exist
        return Err(AppError::BadRequest(
            "User not found. Please register first.".to_string(),
        ));
    };

    // Delete the magic link token (one-time use)
    MagicLinksStore::delete(DB::Conn(&state.db), &query.token).await?;

    // Run risk engine evaluation
    use crate::services::risk_engine::RiskContext;

    let risk_ctx = RiskContext {
        user_id: &user.id,
        org_id: None, // Magic links don't have org context yet
        ip_address: &request_info.ip_address,
        user_agent: &request_info.user_agent,
        device_cookie: None, // No device cookie on magic link auth
    };

    let risk_assessment = state
        .risk_engine
        .evaluate(DB::Conn(&state.db), risk_ctx)
        .await?;

    // Log risk assessment
    tracing::info!(
        user_id = %user.id,
        email = %user.email,
        risk_score = risk_assessment.score,
        risk_action = ?risk_assessment.action,
        risk_factors = ?risk_assessment.factors,
        "Magic link authentication risk assessment"
    );

    // Log the successful authentication with risk data
    tracing::info!(
        user_id = %user.id,
        email = %user.email,
        risk_score = risk_assessment.score,
        risk_factors = ?risk_assessment.factors,
        ip_address = %request_info.ip_address,
        "Magic link authentication successful"
    );

    // Take action based on risk
    use crate::services::risk_engine::RiskAction;
    match risk_assessment.action {
        RiskAction::Allow | RiskAction::LogOnly => {
            // Generate JWT token
            let token = state.jwt_service.create_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                None, // No org context
                None, // No service context
            )?;

            // Create session with refresh token
            let token_hash = hash_token(&token);
            let refresh_token = Uuid::new_v4().to_string();
            let now = Utc::now();
            let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
            let refresh_expires_at = now + chrono::Duration::days(30);

            SessionStore::create(
                DB::Conn(&state.db),
                &user.id,
                &token_hash,
                expires_at.naive_utc(),
                Some(&refresh_token),
                Some(refresh_expires_at.naive_utc()),
                None, // No org context
                None, // No service context
                None,
                None,
            )
            .await?;

            // Generate device trust cookie
            let device_token = state.risk_engine.generate_device_token(&user.id);
            let device_cookie_value = format!(
                "{}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
                device_token,
                90 * 24 * 3600 // 90 days in seconds
            );

            // Store device in database
            use crate::store::user_devices::UserDevicesStore;
            use sha2::{Digest, Sha256};

            let mut hasher = Sha256::new();
            hasher.update(device_token.as_bytes());
            let token_hash = hex::encode(hasher.finalize());

            let expires_at = (Utc::now() + chrono::Duration::days(90)).naive_utc();

            UserDevicesStore::create(
                DB::Conn(&state.db),
                &user.id,
                &token_hash,
                "Magic Link Device", // Device name
                Some(request_info.ip_address.clone()),
                expires_at,
            )
            .await?;

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
            let preauth_token = state.jwt_service.create_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                None,
                None,
            )?;

            Ok((
                StatusCode::OK,
                Json(serde_json::json!({
                    "requires_mfa": true,
                    "preauth_token": preauth_token,
                    "message": "Additional verification required"
                })),
            )
                .into_response())
        }

        RiskAction::Block => {
            tracing::warn!(
                user_id = %user.id,
                email = %user.email,
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
