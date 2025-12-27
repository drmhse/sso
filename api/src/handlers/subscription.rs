use crate::auth::jwt::Claims;
use crate::constants::DEFAULT_TIER_NAME;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, sessions::SessionStore, subscriptions::SubscriptionStore,
    users::UserStore, DB,
};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub org: String,
    pub service: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub service: String,
    pub plan: String,
    pub features: Vec<String>,
    pub status: String,
    pub current_period_end: String,
}

/// Get current user info
pub async fn get_user(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<UserResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Verify user is member of org if org claim exists
    if let Some(ref org_slug) = auth_user.claims.org {
        let membership = MembershipStore::find_by_org_slug_and_user(
            DB::Conn(&state.db),
            org_slug,
            &auth_user.claims.sub,
        )
        .await?;

        if membership.is_none() {
            return Err(AppError::Forbidden(
                "User is not a member of this organization".to_string(),
            ));
        }
    }

    Ok(Json(UserResponse {
        id: auth_user.user.id.clone(),
        email: auth_user.user.email.clone(),
        org: auth_user.claims.org.unwrap_or_default(),
        service: auth_user.claims.service.unwrap_or_default(),
    }))
}

/// Get current subscription
pub async fn get_subscription(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
) -> Result<Json<SubscriptionResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Extract org and service from claims
    let org_slug = auth_user
        .claims
        .org
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Missing org in token".to_string()))?;
    let service_slug = auth_user
        .claims
        .service
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Missing service in token".to_string()))?;

    // Get subscription info
    let result = SubscriptionStore::get_subscription_by_user_org_service(
        DB::Conn(&state.db),
        &auth_user.claims.sub,
        org_slug,
        service_slug,
    )
    .await?;

    if let Some(result) = result {
        let features: Vec<String> = result
            .features
            .as_ref()
            .and_then(|f| serde_json::from_str(f).ok())
            .unwrap_or_default();

        Ok(Json(SubscriptionResponse {
            service: result.service_slug,
            plan: result.plan_name,
            features,
            status: result.status,
            current_period_end: result.current_period_end.to_string(),
        }))
    } else {
        // No active subscription, return free plan
        Ok(Json(SubscriptionResponse {
            service: service_slug.to_string(),
            plan: DEFAULT_TIER_NAME.to_string(),
            features: vec![],
            status: "active".to_string(),
            current_period_end: "N/A".to_string(),
        }))
    }
}

#[allow(dead_code)]
pub fn validate_claims_match_path(
    claims: &Claims,
    org_slug: &str,
    service_slug: &str,
) -> Result<()> {
    if claims.org.as_deref() != Some(org_slug) || claims.service.as_deref() != Some(service_slug) {
        return Err(AppError::Forbidden(
            "Token does not match requested resource".to_string(),
        ));
    }
    Ok(())
}

#[allow(dead_code)]
pub fn has_feature(_claims: &Claims, _feature: &str) -> bool {
    // Feature checks have been removed from JWT claims
    // Features are now managed through subscriptions and permissions
    false
}

/// Update user profile
pub async fn update_user(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Get current user
    let mut user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Update email if provided
    if let Some(new_email) = req.email {
        // Validate email format
        validate_email_format(&new_email)?;

        // Check if email is already taken
        let is_taken = UserStore::is_email_taken(DB::Conn(&state.db), &new_email, &user.id).await?;

        if is_taken {
            return Err(AppError::BadRequest("Email already in use".to_string()));
        }

        // Update email
        user = UserStore::update_email(DB::Conn(&state.db), &user.id, &new_email).await?;
    }

    // Verify user is still member of org if org claim exists
    if let Some(ref org_slug) = auth_user.claims.org {
        let membership = MembershipStore::find_by_org_slug_and_user(
            DB::Conn(&state.db),
            org_slug,
            &auth_user.claims.sub,
        )
        .await?;

        if membership.is_none() {
            return Err(AppError::Forbidden(
                "User is not a member of this organization".to_string(),
            ));
        }
    }

    Ok(Json(UserResponse {
        id: user.id,
        email: user.email,
        org: auth_user.claims.org.unwrap_or_default(),
        service: auth_user.claims.service.unwrap_or_default(),
    }))
}

// ============================================================================
// PASSWORD MANAGEMENT
// ============================================================================

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};

#[derive(Debug, Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize)]
pub struct ChangePasswordResponse {
    pub message: String,
}

/// POST /api/user/change-password - Change user's password
pub async fn change_password(
    State(state): State<AppState>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<ChangePasswordResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // Validate new password strength
    if req.new_password.len() < 8 {
        return Err(AppError::BadRequest(
            "New password must be at least 8 characters long".to_string(),
        ));
    }

    // Get current user
    let user = UserStore::find_by_id(DB::Conn(&state.db), &auth_user.claims.sub)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Check if user has a password set
    let current_password_hash = user.password_hash.as_ref().ok_or_else(|| {
        AppError::BadRequest(
            "Cannot change password for OAuth-only accounts. Please set a password first."
                .to_string(),
        )
    })?;

    // Verify current password using spawn_blocking to avoid blocking the async runtime
    use crate::services::concurrency::ARGON2_SEMAPHORE;
    
    let password_hash_clone = current_password_hash.clone();
    let password_input = req.current_password.clone();

    // Acquire semaphore permit to limit concurrent hash operations
    let _permit = ARGON2_SEMAPHORE.acquire().await.map_err(|_| {
        AppError::InternalServerError("Password verification unavailable".to_string())
    })?;

    // Offload to blocking thread pool
    let is_valid = tokio::task::spawn_blocking(move || {
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
        return Err(AppError::Unauthorized("Current password is incorrect".to_string()));
    }

    // Hash new password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let new_password_hash = argon2
        .hash_password(req.new_password.as_bytes(), &salt)
        .map_err(|e| AppError::InternalServerError(format!("Failed to hash password: {}", e)))?
        .to_string();

    // Update password
    UserStore::update_password_hash(DB::Conn(&state.db), &user.id, &new_password_hash).await?;

    // Optionally revoke all other sessions for security
    SessionStore::delete_all_except_current(DB::Conn(&state.db), &user.id, &auth_user.claims.sub)
        .await?;

    Ok(Json(ChangePasswordResponse {
        message: "Password changed successfully".to_string(),
    }))
}

// ============================================================================
// STRIPE CHECKOUT
// ============================================================================

use crate::store::{organizations::OrganizationStore, plans::PlanStore, services::ServiceStore};
use axum::extract::Path;

#[derive(Debug, Deserialize)]
pub struct CreateCheckoutRequest {
    pub plan_id: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Debug, Serialize)]
pub struct CreateCheckoutResponse {
    pub checkout_url: String,
    pub session_id: String,
}

/// POST /api/organizations/:org_slug/services/:service_slug/checkout
/// Create a Stripe checkout session for the authenticated user to subscribe to a plan
pub async fn create_checkout(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: Option<axum::extract::Extension<crate::middleware::AuthUser>>,
    Json(req): Json<CreateCheckoutRequest>,
) -> Result<Json<CreateCheckoutResponse>> {
    let auth_user = auth_user
        .ok_or_else(|| AppError::Unauthorized("Not authenticated".to_string()))?
        .0;

    // 1. Verify user is member of the organization
    let membership = MembershipStore::find_by_org_slug_and_user(
        DB::Conn(&state.db),
        &org_slug,
        &auth_user.claims.sub,
    )
    .await?;

    if membership.is_none() {
        return Err(AppError::Forbidden(
            "User is not a member of this organization".to_string(),
        ));
    }

    // 2. Find the organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // 3. Find the service
    let service =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &organization.id, &service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    // 4. Find the plan and verify it has a Stripe price ID
    let plan = PlanStore::find_by_id(DB::Conn(&state.db), &req.plan_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Plan not found".to_string()))?;

    // Verify plan belongs to the service
    if plan.service_id != service.id {
        return Err(AppError::BadRequest(
            "Plan does not belong to this service".to_string(),
        ));
    }

    // Verify plan has a billing price ID (use stripe_price_id for backwards compatibility)
    let price_id = plan.stripe_price_id.as_ref().ok_or_else(|| {
        AppError::BadRequest(
            "This plan is not available for purchase (no price configured)".to_string(),
        )
    })?;

    // 5. Get or create billing customer for the organization
    use crate::handlers::organizations::create_billing_customer;

    let org_id = organization.id.clone();
    let org_name = organization.name.clone();
    let billing_customer = create_billing_customer(&state, &org_id, &org_name).await?;

    // 6. Create checkout session with metadata
    use crate::billing::CreateCheckoutRequest as BillingCheckoutRequest;

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("user_id".to_string(), auth_user.user.id.clone());
    metadata.insert("service_id".to_string(), service.id.clone());
    metadata.insert("plan_id".to_string(), req.plan_id.clone());
    metadata.insert("org_id".to_string(), org_id);

    let checkout_result = state
        .billing_provider
        .create_checkout_session(BillingCheckoutRequest {
            external_customer_id: billing_customer.external_customer_id,
            price_id: price_id.clone(),
            success_url: req.success_url.clone(),
            cancel_url: req.cancel_url.clone(),
            metadata,
        })
        .await?;

    Ok(Json(CreateCheckoutResponse {
        checkout_url: checkout_result.url,
        session_id: checkout_result.session_id,
    }))
}

/// Validate email format
fn validate_email_format(email: &str) -> Result<()> {
    if email.is_empty() {
        return Err(AppError::BadRequest("Email cannot be empty".to_string()));
    }

    // Basic email validation regex
    let email_regex = regex::Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
        .map_err(|_| AppError::InternalServerError("Invalid email validation regex".to_string()))?;

    if !email_regex.is_match(email) {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Additional checks for specific invalid patterns
    if email.starts_with('.') || email.ends_with('.') || email.contains("..") {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    Ok(())
}
