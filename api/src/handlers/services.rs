use crate::constants::{DEFAULT_MAX_SERVICES, DEFAULT_TIER_NAME, VALID_SERVICE_TYPES};
use crate::db::models::{Plan, ServiceResponse};
use crate::entities::{organizations, plans};
use crate::error::{with_retrying_transaction, Result};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::state::AppState;
use crate::store::{
    memberships::MembershipStore, organizations::OrganizationStore, plans::PlanStore,
    services::ServiceStore, subscriptions::SubscriptionStore, DB,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use base64::{engine::general_purpose, Engine as _};
use chrono::Utc;
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::task::JoinSet;
use uuid::Uuid;

/// Hash a client secret using SHA-256
fn hash_client_secret(client_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(client_secret.as_bytes());
    let hash = hasher.finalize();
    general_purpose::STANDARD.encode(hash)
}

#[derive(Debug, Deserialize)]
pub struct CreateServiceRequest {
    pub slug: String,
    pub name: String,
    pub service_type: String, // 'web', 'mobile', 'desktop', 'api'
    pub github_scopes: Option<Vec<String>>,
    pub microsoft_scopes: Option<Vec<String>>,
    pub google_scopes: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub device_activation_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateServiceRequest {
    pub name: Option<String>,
    pub service_type: Option<String>,
    pub github_scopes: Option<Vec<String>>,
    pub microsoft_scopes: Option<Vec<String>>,
    pub google_scopes: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub device_activation_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceWithGrantsResponse {
    pub service: ServiceResponse,
    pub default_plan: Plan,
    pub usage: ServiceUsageInfo,
}

#[derive(Debug, Serialize)]
pub struct ServiceUsageInfo {
    pub current_services: i64,
    pub max_services: i64,
    pub tier: String,
}

#[derive(Debug, Serialize)]
pub struct ServiceListResponse {
    pub services: Vec<ServiceWithDetails>,
    pub usage: ServiceUsageInfo,
}

#[derive(Debug, Serialize)]
pub struct ServiceWithDetails {
    #[serde(flatten)]
    pub service: ServiceResponse,
    pub plan_count: i64,
    pub subscription_count: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListServicesQuery {
    #[allow(dead_code)]
    pub status: Option<String>,
    pub service_type: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct CreatePlanRequest {
    pub name: String,
    pub price_cents: i64,
    pub currency: String,
    pub features: Option<Vec<String>>,
    pub stripe_price_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePlanRequest {
    pub name: Option<String>,
    pub price_cents: Option<i64>,
    pub currency: Option<String>,
    pub features: Option<Vec<String>>,
    pub stripe_price_id: Option<Option<String>>,
}

#[derive(Debug, Serialize)]
pub struct PlanResponse {
    pub plan: Plan,
    pub subscription_count: i64,
}

// Helper function to check if user has permission to manage services
async fn can_manage_service(state: &AppState, user_id: &str, org_id: &str) -> Result<bool> {
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), org_id, user_id).await?;

    Ok(membership
        .map(|m| m.role == "owner" || m.role == "admin")
        .unwrap_or(false))
}

// Helper function to calculate service limits
async fn get_service_limits(state: &AppState, org: &organizations::Model) -> Result<(i64, String)> {
    use crate::store::organization_tiers::OrganizationTierStore;

    let max_services = if let Some(custom_limit) = org.max_services {
        custom_limit as i64
    } else {
        // Get tier default
        let tier_name = if let Some(tier_id) = &org.tier_id {
            OrganizationTierStore::find_by_id(DB::Conn(&state.db), tier_id)
                .await?
                .map(|t| t.name)
                .unwrap_or_else(|| DEFAULT_TIER_NAME.to_string())
        } else {
            DEFAULT_TIER_NAME.to_string()
        };

        OrganizationTierStore::find_by_name(DB::Conn(&state.db), &tier_name)
            .await?
            .map(|t| t.default_max_services as i64)
            .unwrap_or(DEFAULT_MAX_SERVICES)
    };

    let tier_display = if let Some(tier_id) = &org.tier_id {
        OrganizationTierStore::find_by_id(DB::Conn(&state.db), tier_id)
            .await?
            .map(|t| t.display_name)
            .unwrap_or_else(|| "Free Tier".to_string())
    } else {
        "Free Tier".to_string()
    };

    Ok((max_services, tier_display))
}

// Create service with auto-provisioning (Phase 5 enhancement)
pub async fn create_service(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreateServiceRequest>,
) -> Result<Json<ServiceWithGrantsResponse>> {
    // Validate service type
    if !VALID_SERVICE_TYPES.contains(&req.service_type.as_str()) {
        return Err(crate::error::AppError::BadRequest(format!(
            "Invalid service type. Must be one of: {}",
            VALID_SERVICE_TYPES.join(", ")
        )));
    }

    // 1. AUTHENTICATE: Extract user from JWT (handled by middleware)

    // 2. LOAD & VALIDATE: organization by org_slug and ensure it's active
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    let org =
        crate::handlers::organizations::ensure_organization_active(&state.db, &org.id).await?;

    // 4. AUTHORIZE: user is member with role in ('owner', 'admin')
    if !can_manage_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to create services".to_string(),
        ));
    }

    // 5. CHECK LIMIT: current services < max_services
    let current_service_count =
        ServiceStore::count_by_org(DB::Conn(&state.db), &org.id).await? as i64;

    let (max_services, tier_name) = get_service_limits(&state, &org).await?;

    if current_service_count >= max_services {
        return Err(crate::error::AppError::BadRequest(format!(
            "Organization has reached maximum service limit ({}/{})",
            current_service_count, max_services
        )));
    }

    // 7. PREPARE transaction data
    let service_id = Uuid::new_v4().to_string();
    let client_id = Uuid::new_v4().to_string();
    let client_secret = Uuid::new_v4().to_string();
    let client_secret_hash = hash_client_secret(&client_secret);
    let plan_id = Uuid::new_v4().to_string();

    let github_scopes_json = req
        .github_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let microsoft_scopes_json = req
        .microsoft_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let google_scopes_json = req
        .google_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let redirect_uris_json = req
        .redirect_uris
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());

    // Log service creation
    tracing::info!(
        service_slug = %req.slug,
        org_slug = %org_slug,
        user_id = %auth_user.user.id,
        service_type = %req.service_type,
        "Creating new service"
    );

    // Clone values needed inside the closure
    let slug = req.slug.clone();
    let name = req.name.clone();
    let service_type = req.service_type.clone();
    let device_activation_uri = req.device_activation_uri.clone();
    let org_id = org.id.clone();

    // 8. Execute transaction with automatic retry on database contention
    let (service, default_plan) = with_retrying_transaction(&state.db, #[cfg(feature = "db_sqlite")] &state.db_writer, "create_service", |db| {
        let service_id = service_id.clone();
        let org_id = org_id.clone();
        let slug = slug.clone();
        let name = name.clone();
        let service_type = service_type.clone();
        let client_id = client_id.clone();
        let client_secret_hash = client_secret_hash.clone();
        let github_scopes_json = github_scopes_json.clone();
        let microsoft_scopes_json = microsoft_scopes_json.clone();
        let google_scopes_json = google_scopes_json.clone();
        let redirect_uris_json = redirect_uris_json.clone();
        let device_activation_uri = device_activation_uri.clone();
        let plan_id = plan_id.clone();
        Box::pin(async move {
            // Create service using ServiceStore
            let service = ServiceStore::create_with_options(
                db.clone(),
                &service_id,
                &org_id,
                &slug,
                &name,
                &service_type,
                &client_id,
                &client_secret_hash,
                github_scopes_json.as_deref(),
                microsoft_scopes_json.as_deref(),
                google_scopes_json.as_deref(),
                redirect_uris_json.as_deref(),
                device_activation_uri.as_deref(),
            )
            .await?;

            // AUTO-CREATE default plan
            let now = Utc::now().naive_utc();
            let features_json = serde_json::to_string::<Vec<String>>(&vec![]).unwrap();

            PlanStore::create(
                db.clone(),
                &plan_id,
                &service_id,
                DEFAULT_TIER_NAME,
                0,
                "usd",
                &features_json,
                None, // No Stripe price ID for default free plan
                now,
            )
            .await?;

            // Fetch the created plan
            let default_plan_entity = plans::Entity::find_by_id(plan_id.clone())
                .one(&db)
                .await?
                .ok_or_else(|| {
                    crate::error::AppError::InternalServerError("Failed to create plan".to_string())
                })?;

            // Convert plan entity to Plan model
            let default_plan = Plan {
                id: default_plan_entity.id,
                service_id: default_plan_entity.service_id,
                name: default_plan_entity.name,
                price_cents: default_plan_entity.price_cents as i64,
                currency: default_plan_entity.currency,
                features: default_plan_entity.features,
                stripe_price_id: default_plan_entity.stripe_price_id,
                created_at: chrono::DateTime::from_naive_utc_and_offset(
                    default_plan_entity.created_at,
                    Utc,
                ),
            };

            Ok((service, default_plan))
        })
    })
    .await?;

    // Non-blocking audit via actor
    let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.user.id), "service.created")
        .target("service", &service_id)
        .success(true)
        .details_json(Some(json!({
            "service_slug": req.slug,
            "service_name": req.name,
            "service_type": req.service_type,
            "client_id": client_id
        })))
        .build();
    state.audit_actor.log_org(event).await;

    // 10. RETURN response matching architecture document
    let usage = ServiceUsageInfo {
        current_services: current_service_count + 1,
        max_services,
        tier: tier_name,
    };

    Ok(Json(ServiceWithGrantsResponse {
        service: ServiceResponse::with_client_secret(service, client_secret),
        default_plan,
        usage,
    }))
}

// List organization services with usage information
pub async fn list_organization_services(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    auth_user: axum::Extension<AuthUser>,
    Query(query): Query<ListServicesQuery>,
) -> Result<Json<ServiceListResponse>> {
    // Get organization and verify membership
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    let _membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::Forbidden("Not a member of this organization".to_string())
            })?;

    // Get services with filters using ServiceStore
    let services = ServiceStore::list_with_filters(
        DB::Conn(&state.db),
        &org.id,
        query.service_type.as_deref(),
        query.limit,
        query.offset,
    )
    .await?;

    // Get detailed information for each service
    let mut join_set = JoinSet::new();
    for service in services {
        let db = state.db.clone();
        let service_id = service.id.clone();
        join_set.spawn(async move {
            let plan_count = PlanStore::count_by_service(DB::Conn(&db), &service_id)
                .await
                .unwrap_or(0);

            let subscription_count =
                SubscriptionStore::count_active_by_service(DB::Conn(&db), &service_id)
                    .await
                    .unwrap_or(0);

            ServiceWithDetails {
                service: ServiceResponse::from(service),
                plan_count,
                subscription_count,
            }
        });
    }

    let services_with_details: Vec<ServiceWithDetails> = join_set.join_all().await;

    // Get usage information
    let current_services = services_with_details.len() as i64;
    let (max_services, tier_name) = get_service_limits(&state, &org).await?;

    Ok(Json(ServiceListResponse {
        services: services_with_details,
        usage: ServiceUsageInfo {
            current_services,
            max_services,
            tier: tier_name,
        },
    }))
}

// Get service details
pub async fn get_service(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<ServiceResponse>> {
    // Get organization and verify membership
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    let _membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::Forbidden("Not a member of this organization".to_string())
            })?;

    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    Ok(Json(ServiceResponse::from(service)))
}

// Update service configuration
pub async fn update_service(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<UpdateServiceRequest>,
) -> Result<Json<ServiceResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user has permission
    if !can_manage_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to update services".to_string(),
        ));
    }

    // Validate service type if provided
    if let Some(service_type) = &req.service_type {
        if !VALID_SERVICE_TYPES.contains(&service_type.as_str()) {
            return Err(crate::error::AppError::BadRequest(format!(
                "Invalid service type. Must be one of: {}",
                VALID_SERVICE_TYPES.join(", ")
            )));
        }
    }

    // Check if there are any fields to update
    if req.name.is_none()
        && req.service_type.is_none()
        && req.github_scopes.is_none()
        && req.microsoft_scopes.is_none()
        && req.google_scopes.is_none()
        && req.redirect_uris.is_none()
        && req.device_activation_uri.is_none()
    {
        return Err(crate::error::AppError::BadRequest(
            "No fields to update".to_string(),
        ));
    }

    // Convert scopes to JSON strings
    let github_scopes_json = req
        .github_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let microsoft_scopes_json = req
        .microsoft_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let google_scopes_json = req
        .google_scopes
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());
    let redirect_uris_json = req
        .redirect_uris
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap());

    // Update service using ServiceStore
    let updated_service = ServiceStore::update_dynamic(
        DB::Conn(&state.db),
        &org.id,
        &service_slug,
        req.name.as_deref(),
        req.service_type.as_deref(),
        github_scopes_json.as_deref(),
        microsoft_scopes_json.as_deref(),
        google_scopes_json.as_deref(),
        redirect_uris_json.as_deref(),
        req.device_activation_uri.as_deref(),
    )
    .await?;

    Ok(Json(ServiceResponse::from(updated_service)))
}

// Delete service
pub async fn delete_service(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner (only owners can delete services)
    let membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?;

    if membership.map(|m| m.role != "owner").unwrap_or(true) {
        return Err(crate::error::AppError::Forbidden(
            "Only organization owners can delete services".to_string(),
        ));
    }

    // Check if service has active subscriptions
    let subscription_count = SubscriptionStore::count_active_by_service_lookup(
        DB::Conn(&state.db),
        &org.id,
        &service_slug,
    )
    .await?;

    if subscription_count > 0 {
        return Err(crate::error::AppError::BadRequest(
            "Cannot delete service with active subscriptions".to_string(),
        ));
    }

    // Delete service using ServiceStore
    let rows_affected =
        ServiceStore::delete_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug).await?;

    if rows_affected == 0 {
        return Err(crate::error::AppError::NotFound(
            "Service not found".to_string(),
        ));
    }

    Ok(StatusCode::NO_CONTENT)
}

// Create plan for service
pub async fn create_plan(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreatePlanRequest>,
) -> Result<Json<PlanResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user has permission
    if !can_manage_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to create plans".to_string(),
        ));
    }

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    let id = Uuid::new_v4().to_string();
    let features_json = req
        .features
        .map(|f| serde_json::to_string(&f).unwrap())
        .unwrap_or_else(|| serde_json::to_string::<Vec<String>>(&vec![]).unwrap());
    let now = Utc::now().naive_utc();

    // Create plan using PlanStore
    PlanStore::create(
        DB::Conn(&state.db),
        &id,
        &service.id,
        &req.name,
        req.price_cents,
        &req.currency,
        &features_json,
        req.stripe_price_id.as_deref(),
        now,
    )
    .await?;

    // Fetch the created plan
    let plan_entity = plans::Entity::find_by_id(id.clone())
        .one(&state.db)
        .await?
        .ok_or_else(|| {
            crate::error::AppError::InternalServerError("Failed to create plan".to_string())
        })?;

    // Convert to Plan model
    let plan = Plan {
        id: plan_entity.id.clone(),
        service_id: plan_entity.service_id,
        name: plan_entity.name,
        price_cents: plan_entity.price_cents as i64,
        currency: plan_entity.currency,
        features: plan_entity.features,
        stripe_price_id: plan_entity.stripe_price_id,
        created_at: chrono::DateTime::from_naive_utc_and_offset(plan_entity.created_at, Utc),
    };

    // Get subscription count (should be 0 for new plan)
    let subscription_count =
        SubscriptionStore::count_active_by_plan(DB::Conn(&state.db), &plan_entity.id).await?;

    Ok(Json(PlanResponse {
        plan,
        subscription_count,
    }))
}

// List plans for service
pub async fn list_service_plans(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<Vec<PlanResponse>>> {
    // Get organization and verify membership
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    let _membership =
        MembershipStore::find_by_org_and_user(DB::Conn(&state.db), &org.id, &auth_user.user.id)
            .await?
            .ok_or_else(|| {
                crate::error::AppError::Forbidden("Not a member of this organization".to_string())
            })?;

    // Get service
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    // Get all plans for this service using PlanStore
    let plan_entities = PlanStore::find_by_service(DB::Conn(&state.db), &service.id).await?;

    let mut responses = Vec::new();

    for plan_entity in plan_entities {
        let subscription_count =
            SubscriptionStore::count_active_by_plan(DB::Conn(&state.db), &plan_entity.id).await?;

        // Convert to Plan model
        let plan = Plan {
            id: plan_entity.id,
            service_id: plan_entity.service_id,
            name: plan_entity.name,
            price_cents: plan_entity.price_cents as i64,
            currency: plan_entity.currency,
            features: plan_entity.features,
            stripe_price_id: plan_entity.stripe_price_id,
            created_at: chrono::DateTime::from_naive_utc_and_offset(plan_entity.created_at, Utc),
        };

        responses.push(PlanResponse {
            plan,
            subscription_count,
        });
    }

    Ok(Json(responses))
}

// Update plan
pub async fn update_plan(
    State(state): State<AppState>,
    Path((org_slug, service_slug, plan_id)): Path<(String, String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<UpdatePlanRequest>,
) -> Result<Json<PlanResponse>> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user has permission (admin or owner)
    if !can_manage_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to update plans".to_string(),
        ));
    }

    // Get service to verify it belongs to the organization
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    // Verify the plan belongs to this service
    let existing_plan = PlanStore::find_by_id(DB::Conn(&state.db), &plan_id)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Plan not found".to_string()))?;

    if existing_plan.service_id != service.id {
        return Err(crate::error::AppError::NotFound(
            "Plan not found".to_string(),
        ));
    }

    // Check if there are any fields to update
    if req.name.is_none()
        && req.price_cents.is_none()
        && req.currency.is_none()
        && req.features.is_none()
    {
        return Err(crate::error::AppError::BadRequest(
            "No fields to update".to_string(),
        ));
    }

    // Convert features to JSON string if provided
    let features_json = req
        .features
        .as_ref()
        .map(|f| serde_json::to_string(f).unwrap());

    // Convert stripe_price_id Option<Option<String>> to Option<Option<&str>>
    let stripe_price_id_update = req.stripe_price_id.as_ref().map(|opt| opt.as_deref());

    // Update plan using PlanStore
    let updated_plan_entity = PlanStore::update(
        DB::Conn(&state.db),
        &plan_id,
        req.name.as_deref(),
        req.price_cents,
        req.currency.as_deref(),
        features_json.as_deref(),
        stripe_price_id_update,
    )
    .await?;

    // Convert to Plan model
    let plan = Plan {
        id: updated_plan_entity.id.clone(),
        service_id: updated_plan_entity.service_id,
        name: updated_plan_entity.name,
        price_cents: updated_plan_entity.price_cents as i64,
        currency: updated_plan_entity.currency,
        features: updated_plan_entity.features,
        stripe_price_id: updated_plan_entity.stripe_price_id,
        created_at: chrono::DateTime::from_naive_utc_and_offset(
            updated_plan_entity.created_at,
            Utc,
        ),
    };

    // Get subscription count
    let subscription_count =
        SubscriptionStore::count_active_by_plan(DB::Conn(&state.db), &plan.id).await?;

    Ok(Json(PlanResponse {
        plan,
        subscription_count,
    }))
}

// Delete plan
pub async fn delete_plan(
    State(state): State<AppState>,
    Path((org_slug, service_slug, plan_id)): Path<(String, String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user has permission (admin or owner)
    if !can_manage_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to delete plans".to_string(),
        ));
    }

    // Get service to verify it belongs to the organization
    let service = ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    // Verify the plan exists and belongs to this service
    let existing_plan = PlanStore::find_by_id(DB::Conn(&state.db), &plan_id)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Plan not found".to_string()))?;

    if existing_plan.service_id != service.id {
        return Err(crate::error::AppError::NotFound(
            "Plan not found".to_string(),
        ));
    }

    // Check if plan has active subscriptions
    let subscription_count =
        SubscriptionStore::count_active_by_plan(DB::Conn(&state.db), &plan_id).await?;

    if subscription_count > 0 {
        return Err(crate::error::AppError::BadRequest(
            "Cannot delete plan with active subscriptions".to_string(),
        ));
    }

    // Delete plan using PlanStore
    PlanStore::delete(DB::Conn(&state.db), &plan_id).await?;

    Ok(StatusCode::NO_CONTENT)
}
