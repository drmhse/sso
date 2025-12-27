use crate::constants::JWT_EXPIRE_HOURS;
use crate::error::{with_retrying_transaction, AppError, Result};
use crate::middleware::RequestInfo;
use crate::state::AppState;
use crate::store::{
    email_verification::EmailVerificationStore, invitations::InvitationStore,
    memberships::MembershipStore, password_reset::PasswordResetStore, sessions::SessionStore,
    totp::TotpStore, users::UserStore, DB,
};
use axum::{
    extract::{Query, State},
    response::Html,
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Argon2 password hashing imports
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

// Helper function to hash JWT tokens for session tracking
pub fn hash_token(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

// Re-export common types
pub use crate::error::Json400;

// Re-export RefreshTokenResponse from session module for use in login/register flows
pub use super::session::RefreshTokenResponse;

// Register Request
#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
    pub org_slug: Option<String>, // Optional: use organization-specific SMTP
}

// Register Response
#[derive(Debug, Serialize)]
pub struct RegisterResponse {
    pub message: String,
}

// Verify Email Query
#[derive(Debug, Deserialize)]
pub struct VerifyEmailQuery {
    pub token: String,
}

// Login Request
#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
    pub org_slug: Option<String>, // Optional: for organization management context
    pub saml_state: Option<String>,
}

// Forgot Password Request
#[derive(Debug, Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
    pub org_slug: Option<String>, // Optional: use organization-specific SMTP
}

// Forgot Password Response
#[derive(Debug, Serialize)]
pub struct ForgotPasswordResponse {
    pub message: String,
}

// Reset Password Request
#[derive(Debug, Deserialize)]
pub struct ResetPasswordRequest {
    pub token: String,
    pub new_password: String,
}

// Reset Password Response
#[derive(Debug, Serialize)]
pub struct ResetPasswordResponse {
    pub message: String,
}

// Resend Verification Request
#[derive(Debug, Deserialize)]
pub struct ResendVerificationRequest {
    pub email: String,
}

// Resend Verification Response
#[derive(Debug, Serialize)]
pub struct ResendVerificationResponse {
    pub message: String,
}

/// POST /api/auth/register - Register a new user with email and password
pub async fn register(
    State(state): State<AppState>,
    Json400(req): Json400<RegisterRequest>,
) -> Result<Json<RegisterResponse>> {
    // Check email rate limit BEFORE processing the request (only if rate limiting is enabled)
    // Rate limiting is disabled when DISABLE_RATE_LIMITING=true is set
    if std::env::var("DISABLE_RATE_LIMITING")
        .unwrap_or_default()
        .to_lowercase()
        != "true"
        && crate::middleware::EMAIL_RATE_LIMITER
            .is_rate_limited_email(&req.email)
            .await
    {
        tracing::warn!("Registration request rate limited for email: {}", req.email);
        return Err(AppError::TooManyRequests(
            "Too many registration attempts. Please try again later.".to_string(),
        ));
    }

    // Validate email format
    if !req.email.contains('@') {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Validate password strength (minimum 8 characters)
    if req.password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    // Check if user already exists
    let existing_user = UserStore::find_by_email(DB::Conn(&state.db), &req.email).await?;

    if existing_user.is_some() {
        return Err(AppError::BadRequest(
            "User with this email already exists".to_string(),
        ));
    }

    // Hash password using Argon2
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(req.password.as_bytes(), &salt)
        .map_err(|e| AppError::InternalServerError(format!("Failed to hash password: {}", e)))?
        .to_string();

    // Clone values needed inside the closure
    let email = req.email.clone();
    let is_platform_owner = state.config.platform_owner_email.as_ref() == Some(&email);
    let verification_token = Uuid::new_v4().to_string();

    // Execute transaction with automatic retry on database contention
    let _user_id = with_retrying_transaction(&state.db, #[cfg(feature = "db_sqlite")] &state.db_writer, "register_user", |db| {
        let email = email.clone();
        let password_hash = password_hash.clone();
        let verification_token = verification_token.clone();
        Box::pin(async move {
            // Create user within the transaction
            let user =
                UserStore::create(db.clone(), &email, Some(password_hash), is_platform_owner)
                    .await?;
            let user_id = user.id.clone();

            // Automatically accept any pending invitations for this email
            InvitationStore::accept_all_pending_for_email(db.clone(), &email, &user_id).await?;

            // Generate email verification token
            let token_hash = hash_token(&verification_token);
            let expires_at = Utc::now() + chrono::Duration::hours(24);

            EmailVerificationStore::create(
                db.clone(),
                &user_id,
                &token_hash,
                &expires_at.naive_utc(),
            )
            .await?;

            Ok(user_id)
        })
    })
    .await?;

    // Enqueue verification email to job queue (non-blocking)
    let verification_url = format!(
        "{}/verify-email?token={}",
        state.web_client_url, verification_token
    );
    let email_subject = "Verify Your Email Address";
    let email_body = format!(
        "Welcome to our platform!\n\n\
        Please verify your email address by clicking the link below:\n\n\
        {}\n\n\
        This link will expire in 24 hours.\n\n\
        If you didn't create an account, you can safely ignore this email.",
        verification_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &email,
        email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::error!("Failed to enqueue verification email: {}", e);
        // Don't fail registration if email enqueueing fails - user can request resend
    }

    Ok(Json(RegisterResponse {
        message: "Registration successful. Please check your email to verify your account."
            .to_string(),
    }))
}

/// GET /auth/verify-email - Verify email address
pub async fn verify_email(
    State(state): State<AppState>,
    Query(query): Query<VerifyEmailQuery>,
) -> Result<Html<String>> {
    let token_hash = hash_token(&query.token);

    // Find and validate token
    let token_record = EmailVerificationStore::find_by_token_hash(DB::Conn(&state.db), &token_hash)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid verification token".to_string()))?;

    if token_record.used {
        return Err(AppError::BadRequest(
            "Verification token has already been used".to_string(),
        ));
    }

    let expires_at: chrono::DateTime<Utc> =
        chrono::DateTime::from_naive_utc_and_offset(token_record.expires_at, Utc);

    if expires_at < Utc::now() {
        return Err(AppError::BadRequest(
            "Verification token has expired".to_string(),
        ));
    }

    // Mark email as verified
    UserStore::verify_email(DB::Conn(&state.db), &token_record.user_id).await?;

    // Mark token as used
    EmailVerificationStore::mark_as_used(DB::Conn(&state.db), &token_hash).await?;

    Ok(Html(
        "<html><body><h1>Email Verified!</h1><p>Your email has been verified successfully. You can now log in.</p></body></html>".to_string()
    ))
}

/// POST /api/auth/login - Login with email and password
pub async fn login(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Json400(req): Json400<LoginRequest>,
) -> Result<Json<RefreshTokenResponse>> {
    // Find user by email
    let user = UserStore::find_by_email(DB::Conn(&state.db), &req.email)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

    // Check if user has a password set
    let password_hash = user.password_hash.as_ref().ok_or_else(|| {
        AppError::Unauthorized(
            "Password login not available for this account. Please use OAuth login.".to_string(),
        )
    })?;

    // Verify password using spawn_blocking to avoid blocking the async runtime
    // Argon2 is CPU-intensive (~50-100ms), so we offload to the blocking thread pool
    use crate::services::concurrency::ARGON2_SEMAPHORE;
    
    let password_hash_clone = password_hash.clone();
    let password_input = req.password.clone();

    // Acquire semaphore permit to limit concurrent hash operations
    // This prevents exhausting Tokio's blocking thread pool under login floods
    let _permit = ARGON2_SEMAPHORE.acquire().await.map_err(|_| {
        AppError::InternalServerError("Password verification unavailable".to_string())
    })?;

    // Offload to blocking thread pool - frees async runtime for other requests
    let is_valid = tokio::task::spawn_blocking(move || {
        // Handle corrupt hash gracefully instead of panicking
        let parsed_hash = match PasswordHash::new(&password_hash_clone) {
            Ok(h) => h,
            Err(e) => {
                tracing::error!("Corrupted password hash in database: {}", e);
                return false;
            }
        };
        Argon2::default()
            .verify_password(password_input.as_bytes(), &parsed_hash)
            .is_ok()
    })
    .await
    .map_err(|e| AppError::InternalServerError(format!("Password verification failed: {}", e)))?;

    if !is_valid {
        return Err(AppError::Unauthorized("Invalid email or password".to_string()));
    }

    // Check if email is verified
    if user.email_verified_at.is_none() {
        return Err(AppError::Unauthorized(
            "Please verify your email address before logging in".to_string(),
        ));
    }

    // Run risk engine evaluation
    use crate::services::risk_engine::RiskContext;
    let risk_ctx = RiskContext {
        user_id: &user.id,
        org_id: None, // Will be set after org verification
        ip_address: &request_info.ip_address,
        user_agent: &request_info.user_agent,
        device_cookie: None, // No device cookie available during login
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
        "Password login risk assessment"
    );

    // Check if MFA is enabled for this user
    let mfa_enabled = TotpStore::is_enabled(DB::Conn(&state.db), &user.id).await?;

    // If MFA is enabled or risk engine requires it, return pre-auth token
    if mfa_enabled
        || matches!(
            risk_assessment.action,
            crate::services::risk_engine::RiskAction::ChallengeMFA
        )
    {
        // If org_slug is provided, verify membership before MFA
        if let Some(org_slug) = &req.org_slug {
            let _membership =
                MembershipStore::find_by_org_slug_and_user(DB::Conn(&state.db), org_slug, &user.id)
                    .await?
                    .ok_or_else(|| {
                        AppError::Forbidden("You are not a member of this organization".to_string())
                    })?;
        }

        let preauth_token = state.jwt_service.create_mfa_preauth_token(
            &user.id,
            &user.email,
            user.is_platform_owner,
            req.org_slug.as_deref(),
            None,
            req.saml_state.as_deref(),
        )?;

        return Ok(Json(RefreshTokenResponse {
            access_token: preauth_token,
            refresh_token: String::new(),
            expires_in: 300, // 5 minutes
        }));
    }

    // Handle risk engine actions
    use crate::services::risk_engine::RiskAction;
    match risk_assessment.action {
        RiskAction::Allow | RiskAction::LogOnly => {
            // Continue with normal login flow
        }
        RiskAction::ChallengeMFA => {
            // Risk engine demands MFA challenge
            if let Some(org_slug) = &req.org_slug {
                let _membership = MembershipStore::find_by_org_slug_and_user(
                    DB::Conn(&state.db),
                    org_slug,
                    &user.id,
                )
                .await?
                .ok_or_else(|| {
                    AppError::Forbidden("You are not a member of this organization".to_string())
                })?;
            }

            let preauth_token = state.jwt_service.create_mfa_preauth_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                req.org_slug.as_deref(),
                None,
                req.saml_state.as_deref(),
            )?;

            return Ok(Json(RefreshTokenResponse {
                access_token: preauth_token,
                refresh_token: String::new(),
                expires_in: 300, // 5 minutes
            }));
        }
        RiskAction::Block => {
            tracing::warn!(
                user_id = %user.id,
                email = %user.email,
                risk_score = risk_assessment.score,
                factors = ?risk_assessment.factors,
                "Password login blocked by risk engine"
            );

            return Err(AppError::Forbidden(
                "Suspicious login detected. Please contact support.".to_string(),
            ));
        }
    }

    // Note: Direct password login with SAML state (no MFA) is not supported via JSON API
    // SAML flows should use the HTML authentication page at /saml/:org/:service/authenticate
    // which redirects through OAuth providers or handles password+MFA properly

    // Check MAU limit for organization logins (billing enforcement)
    if let Some(ref org_slug) = req.org_slug {
        // Fetch org to get org_id for MAU check
        let org = crate::store::organizations::OrganizationStore::find_by_slug(
            DB::Conn(&state.db),
            org_slug,
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        crate::services::tier_enforcement::TierService::check_mau_limit(
            DB::Conn(&state.db),
            &org.id,
        )
        .await?;
    }

    // Generate JWT based on context (org_slug or platform owner)
    let token = if let Some(org_slug) = &req.org_slug {
        // Organization management login - verify membership
        let _membership =
            MembershipStore::find_by_org_slug_and_user(DB::Conn(&state.db), org_slug, &user.id)
                .await?
                .ok_or_else(|| {
                    AppError::Forbidden("You are not a member of this organization".to_string())
                })?;

        state.jwt_service.create_token(
            &user.id,
            &user.email,
            user.is_platform_owner,
            Some(org_slug),
            None,
        )?
    } else {
        // Platform-level login (for platform owners or users without org context)
        state
            .jwt_service
            .create_token(&user.id, &user.email, user.is_platform_owner, None, None)?
    };

    // Create session with refresh token
    let token_hash = hash_token(&token);
    let refresh_token = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    // Clones for transaction
    let helper_user_id = user.id.clone();
    let helper_token_hash = token_hash.clone();
    let helper_refresh_token = refresh_token.clone();
    let helper_org_slug = req.org_slug.clone();
    let helper_ip = request_info.ip_address.clone();
    let helper_risk_action = risk_assessment.action.clone();
    
    // Generate device token outside transaction to avoid recreating it on retry if possible
    let device_token = state.risk_engine.generate_device_token(&user.id);
    let helper_device_token = device_token.clone();

    // Execute session and device creation in retrying transaction
    let _device_cookie = with_retrying_transaction(&state.db, #[cfg(feature = "db_sqlite")] &state.db_writer, "login_session_create", |db| {
        let user_id = helper_user_id.clone();
        let token_hash = helper_token_hash.clone();
        let refresh_token = helper_refresh_token.clone();
        let org_slug = helper_org_slug.clone();
        let ip_address = helper_ip.clone();
        let risk_action = helper_risk_action.clone();
        let device_token = helper_device_token.clone();
        
        // Capture time/expirations for inside transaction consistency
        let now = Utc::now();
        let expires_at_naive = expires_at.naive_utc();
        let refresh_expires_at_naive = refresh_expires_at.naive_utc();

        Box::pin(async move {
            SessionStore::create(
                db.clone(),
                &user_id,
                &token_hash,
                expires_at_naive,
                Some(&refresh_token),
                Some(refresh_expires_at_naive),
                org_slug.as_deref(),
                None,
                None,
                None,
            )
            .await?;

            // Generate device trust cookie if risk assessment allows
            if matches!(risk_action, RiskAction::Allow) {
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
                let token_hash = hex::encode(hasher.finalize());

                let device_expires = (now + chrono::Duration::days(90)).naive_utc();

                UserDevicesStore::create(
                    db.clone(),
                    &user_id,
                    &token_hash,
                    "Password Login Device",
                    Some(ip_address),
                    device_expires,
                )
                .await?;

                Ok(Some(device_cookie_value))
            } else {
                Ok(None)
            }
        })
    })
    .await?;

    // Publish login success event for webhooks (password login, no org/service context)
    crate::handlers::auth::oauth::publish_login_event(
        &state.event_dispatcher,
        &user.id,
        &user.email,
        None,
        None,
        Some("password"),
    )
    .await;

    Ok(Json(RefreshTokenResponse {
        access_token: token,
        refresh_token,
        expires_in: state.config.jwt_expiration_hours * 3600,
    }))
}

/// POST /api/auth/forgot-password - Request password reset
pub async fn forgot_password(
    State(state): State<AppState>,
    Json(req): Json<ForgotPasswordRequest>,
) -> Result<Json<ForgotPasswordResponse>> {
    // Check email rate limit BEFORE processing the request (only if rate limiting is enabled)
    // Rate limiting is disabled when DISABLE_RATE_LIMITING=true is set
    if std::env::var("DISABLE_RATE_LIMITING")
        .unwrap_or_default()
        .to_lowercase()
        != "true"
        && crate::middleware::EMAIL_RATE_LIMITER
            .is_rate_limited_email(&req.email)
            .await
    {
        tracing::warn!(
            "Password reset request rate limited for email: {}",
            req.email
        );
        return Err(AppError::TooManyRequests(
            "Too many password reset requests. Please try again later.".to_string(),
        ));
    }

    // Find user by email
    let user = UserStore::find_by_email(DB::Conn(&state.db), &req.email).await?;

    // Always return success to prevent email enumeration
    if user.is_none() {
        return Ok(Json(ForgotPasswordResponse {
            message: "If an account with that email exists, a password reset link has been sent."
                .to_string(),
        }));
    }

    let user = user.unwrap();

    // Check if user has a password (can't reset if they only use OAuth)
    if user.password_hash.is_none() {
        return Ok(Json(ForgotPasswordResponse {
            message: "If an account with that email exists, a password reset link has been sent."
                .to_string(),
        }));
    }

    // Generate password reset token
    let reset_token = Uuid::new_v4().to_string();
    let token_hash = hash_token(&reset_token);
    let expires_at = Utc::now() + chrono::Duration::hours(1);

    PasswordResetStore::create(
        DB::Conn(&state.db),
        &user.id,
        &token_hash,
        &expires_at.naive_utc(),
    )
    .await?;

    // Enqueue password reset email to job queue (non-blocking)
    let reset_url = format!(
        "{}/auth/reset-password?token={}",
        state.base_url, reset_token
    );
    let email_subject = "Reset Your Password";
    let email_body = format!(
        "We received a request to reset your password.\n\n\
        Click the link below to reset your password:\n\n\
        {}\n\n\
        This link will expire in 1 hour.\n\n\
        If you didn't request a password reset, you can safely ignore this email.",
        reset_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &user.email,
        email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::error!("Failed to enqueue password reset email: {}", e);
        // Don't fail the request - we don't want to leak info about email existence
    }

    Ok(Json(ForgotPasswordResponse {
        message: "If an account with that email exists, a password reset link has been sent."
            .to_string(),
    }))
}

/// POST /api/auth/reset-password - Reset password with token
pub async fn reset_password(
    State(state): State<AppState>,
    Json400(req): Json400<ResetPasswordRequest>,
) -> Result<Json<ResetPasswordResponse>> {
    // Validate password strength
    if req.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "Password must be at least 8 characters long".to_string(),
        ));
    }

    let token_hash = hash_token(&req.token);

    // Find and validate token
    let token_record = PasswordResetStore::find_by_token_hash(DB::Conn(&state.db), &token_hash)
        .await?
        .ok_or_else(|| AppError::BadRequest("Invalid reset token".to_string()))?;

    if token_record.used {
        return Err(AppError::BadRequest(
            "Reset token has already been used".to_string(),
        ));
    }

    let expires_at: chrono::DateTime<Utc> =
        chrono::DateTime::from_naive_utc_and_offset(token_record.expires_at, Utc);

    if expires_at < Utc::now() {
        return Err(AppError::BadRequest("Reset token has expired".to_string()));
    }

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(req.new_password.as_bytes(), &salt)
        .map_err(|e| AppError::InternalServerError(format!("Failed to hash password: {}", e)))?
        .to_string();

    // Update user's password
    UserStore::update_password_hash(DB::Conn(&state.db), &token_record.user_id, &password_hash)
        .await?;

    // Mark token as used
    PasswordResetStore::mark_as_used(DB::Conn(&state.db), &token_hash).await?;

    // Revoke all existing sessions for security
    SessionStore::delete_all_for_user(DB::Conn(&state.db), &token_record.user_id).await?;

    Ok(Json(ResetPasswordResponse {
        message: "Password has been reset successfully. Please log in with your new password."
            .to_string(),
    }))
}

/// POST /api/auth/resend-verification - Resend verification email
pub async fn resend_verification(
    State(state): State<AppState>,
    Json(req): Json<ResendVerificationRequest>,
) -> Result<Json<ResendVerificationResponse>> {
    // Check email rate limit
    if std::env::var("DISABLE_RATE_LIMITING")
        .unwrap_or_default()
        .to_lowercase()
        != "true"
        && crate::middleware::EMAIL_RATE_LIMITER
            .is_rate_limited_email(&req.email)
            .await
    {
        tracing::warn!(
            "Resend verification request rate limited for email: {}",
            req.email
        );
        return Err(AppError::TooManyRequests(
            "Too many requests. Please try again later.".to_string(),
        ));
    }

    // Find user by email
    let user = UserStore::find_by_email(DB::Conn(&state.db), &req.email).await?;

    // If user not found, return generic success to avoid enumeration
    if user.is_none() {
        return Ok(Json(ResendVerificationResponse {
            message: "If an account with that email exists and is not verified, a verification link has been sent."
                .to_string(),
        }));
    }

    let user = user.unwrap();

    // If already verified, return generic success
    if user.email_verified_at.is_some() {
        return Ok(Json(ResendVerificationResponse {
            message: "If an account with that email exists and is not verified, a verification link has been sent."
                .to_string(),
        }));
    }

    // Generate new verification token
    let verification_token = Uuid::new_v4().to_string();
    let token_hash = hash_token(&verification_token);
    let expires_at = Utc::now() + chrono::Duration::hours(24);

    // Create new verification record
    EmailVerificationStore::create(
        DB::Conn(&state.db),
        &user.id,
        &token_hash,
        &expires_at.naive_utc(),
    )
    .await?;

    // Enqueue verification email
    let verification_url = format!(
        "{}/verify-email?token={}",
        state.web_client_url, verification_token
    );
    let email_subject = "Verify Your Email Address";
    let email_body = format!(
        "Welcome back!\n\n\
        You requested a new verification link. Please verify your email address by clicking the link below:\n\n\
        {}\n\n\
        This link will expire in 24 hours.\n\n\
        If you didn't request this email, you can safely ignore it.",
        verification_url
    );

    use crate::services::job_queue::JobQueueService;
    if let Err(e) = JobQueueService::enqueue_email(
        DB::Conn(&state.db),
        &req.email,
        email_subject,
        &email_body,
        None, // No HTML version
    )
    .await
    {
        tracing::error!("Failed to enqueue verification email: {}", e);
    }

    Ok(Json(ResendVerificationResponse {
        message: "If an account with that email exists and is not verified, a verification link has been sent."
            .to_string(),
    }))
}
