#![allow(dead_code)]

use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::store::{memberships::MembershipStore, subscriptions::SubscriptionStore, DB};
use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SubscriptionResponse {
    pub service: String,
    pub plan: String,
    pub features: Vec<String>,
    pub status: String,
    pub current_period_end: String,
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
        use crate::constants::DEFAULT_TIER_NAME;
        Ok(Json(SubscriptionResponse {
            service: service_slug.to_string(),
            plan: DEFAULT_TIER_NAME.to_string(),
            features: vec![],
            status: "active".to_string(),
            current_period_end: "N/A".to_string(),
        }))
    }
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
    let organization =
        crate::handlers::organizations::ensure_organization_active(&state.db, &organization.id)
            .await?;

    // 3. Find the service
    let service =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &organization.id, &service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    // 4. Find the plan and verify it has a Stripe price ID
    let plan = PlanStore::find_by_id_and_service(DB::Conn(&state.db), &req.plan_id, &service.id)
        .await?
        .ok_or_else(|| AppError::NotFound("Plan not found".to_string()))?;

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
