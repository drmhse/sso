use crate::constants::{DEFAULT_MAX_SERVICES, DEFAULT_TIER_NAME, VALID_SERVICE_TYPES};
use crate::db::models::{Membership, Organization, Plan, ProviderTokenGrant, Service, ServiceResponse};
use crate::error::Result;
use crate::handlers::auth::AppState;
use crate::middleware::AuthUser;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use uuid::Uuid;

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
    pub provider_grants: Vec<ProviderTokenGrant>,
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
}


#[derive(Debug, Serialize)]
pub struct PlanResponse {
    pub plan: Plan,
    pub subscription_count: i64,
}

// Helper function to check if user has permission to manage services
async fn can_manage_service(state: &AppState, user_id: &str, org_id: &str) -> Result<bool> {
    let membership = sqlx::query_as::<_, Membership>(
        r#"
        SELECT m.* FROM memberships m
        WHERE m.org_id = ? AND m.user_id = ?
        "#,
    )
    .bind(org_id)
    .bind(user_id)
    .fetch_optional(&state.pool)
    .await?;

    Ok(membership
        .map(|m| m.role == "owner" || m.role == "admin")
        .unwrap_or(false))
}

// Helper function to calculate service limits
async fn get_service_limits(state: &AppState, org: &Organization) -> Result<(i64, String)> {
    let max_services = if let Some(custom_limit) = org.max_services {
        custom_limit
    } else {
        // Get tier default
        let tier_name = if let Some(tier_id) = &org.tier_id {
            sqlx::query_scalar::<_, String>("SELECT name FROM organization_tiers WHERE id = ?")
                .bind(tier_id)
                .fetch_one(&state.pool)
                .await
                .unwrap_or_else(|_| DEFAULT_TIER_NAME.to_string())
        } else {
            DEFAULT_TIER_NAME.to_string()
        };

        let tier_default = sqlx::query_scalar::<_, i64>(
            "SELECT default_max_services FROM organization_tiers WHERE name = ?",
        )
        .bind(&tier_name)
        .fetch_one(&state.pool)
        .await
        .unwrap_or(DEFAULT_MAX_SERVICES); // Fallback to default if tier not found

        tier_default
    };

    let tier_display =
        sqlx::query_scalar::<_, String>("SELECT display_name FROM organization_tiers WHERE id = ?")
            .bind(&org.tier_id)
            .fetch_one(&state.pool)
            .await
            .unwrap_or_else(|_| "Free Tier".to_string());

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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    let org =
        crate::handlers::organizations::ensure_organization_active(&state.pool, &org.id).await?;

    // 4. AUTHORIZE: user is member with role in ('owner', 'admin')
    if !can_manage_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to create services".to_string(),
        ));
    }

    // 5. CHECK LIMIT: current services < max_services
    let current_service_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM services WHERE org_id = ?")
            .bind(&org.id)
            .fetch_one(&state.pool)
            .await?;

    let (max_services, tier_name) = get_service_limits(&state, &org).await?;

    if current_service_count >= max_services {
        return Err(crate::error::AppError::BadRequest(format!(
            "Organization has reached maximum service limit ({}/{})",
            current_service_count, max_services
        )));
    }

    // 6. BEGIN TRANSACTION
    let mut tx = state.pool.begin().await?;

    // 7. CREATE service
    let service_id = Uuid::new_v4().to_string();
    let client_id = Uuid::new_v4().to_string();

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

    let service = sqlx::query_as::<_, Service>(
        r#"
        INSERT INTO services (
            id, org_id, slug, name, service_type, client_id,
            github_scopes, microsoft_scopes, google_scopes, redirect_uris, device_activation_uri, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        RETURNING *
        "#,
    )
    .bind(&service_id)
    .bind(&org.id)
    .bind(&req.slug)
    .bind(&req.name)
    .bind(&req.service_type)
    .bind(&client_id)
    .bind(&github_scopes_json)
    .bind(&microsoft_scopes_json)
    .bind(&google_scopes_json)
    .bind(&redirect_uris_json)
    .bind(&req.device_activation_uri)
    .bind(Utc::now())
    .fetch_one(&mut *tx)
    .await?;

    // 8. AUTO-CREATE provider_token_grants
    let mut provider_grants = Vec::new();

    if req.github_scopes.is_some() {
        let grant_id = Uuid::new_v4().to_string();
        let grant = sqlx::query_as::<_, ProviderTokenGrant>(
            r#"
            INSERT INTO provider_token_grants (id, service_id, provider, required, created_at)
            VALUES (?, ?, ?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(&grant_id)
        .bind(&service_id)
        .bind("github")
        .bind(false)
        .bind(Utc::now())
        .fetch_one(&mut *tx)
        .await?;
        provider_grants.push(grant);
    }

    if req.microsoft_scopes.is_some() {
        let grant_id = Uuid::new_v4().to_string();
        let grant = sqlx::query_as::<_, ProviderTokenGrant>(
            r#"
            INSERT INTO provider_token_grants (id, service_id, provider, required, created_at)
            VALUES (?, ?, ?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(&grant_id)
        .bind(&service_id)
        .bind("microsoft")
        .bind(false)
        .bind(Utc::now())
        .fetch_one(&mut *tx)
        .await?;
        provider_grants.push(grant);
    }

    if req.google_scopes.is_some() {
        let grant_id = Uuid::new_v4().to_string();
        let grant = sqlx::query_as::<_, ProviderTokenGrant>(
            r#"
            INSERT INTO provider_token_grants (id, service_id, provider, required, created_at)
            VALUES (?, ?, ?, ?, ?)
            RETURNING *
            "#,
        )
        .bind(&grant_id)
        .bind(&service_id)
        .bind("google")
        .bind(false)
        .bind(Utc::now())
        .fetch_one(&mut *tx)
        .await?;
        provider_grants.push(grant);
    }

    // 9. AUTO-CREATE default plan
    let plan_id = Uuid::new_v4().to_string();
    let default_plan = sqlx::query_as::<_, Plan>(
        r#"
        INSERT INTO plans (id, service_id, name, price_cents, currency, features, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING *
        "#,
    )
    .bind(&plan_id)
    .bind(&service_id)
    .bind(DEFAULT_TIER_NAME)
    .bind(0)
    .bind("usd")
    .bind(serde_json::to_string::<Vec<String>>(&vec![]).unwrap()) // Empty features array
    .bind(Utc::now())
    .fetch_one(&mut *tx)
    .await?;

    // 10. COMMIT
    tx.commit().await?;

    // 11. RETURN response matching architecture document
    let usage = ServiceUsageInfo {
        current_services: current_service_count + 1,
        max_services,
        tier: tier_name,
    };

    Ok(Json(ServiceWithGrantsResponse {
        service: ServiceResponse::from(service),
        provider_grants,
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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    let _membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&org.id)
    .bind(&auth_user.user.id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        crate::error::AppError::Forbidden("Not a member of this organization".to_string())
    })?;

    // Build query with filters
    let mut sql = "SELECT * FROM services WHERE org_id = ?".to_string();

    if let Some(_status) = &query.status {
        // Note: status field not in current schema, adding as placeholder for future enhancement
        // sql.push_str(" AND status = ?");
        // params.push(status);
    }

    if let Some(_service_type) = &query.service_type {
        sql.push_str(" AND service_type = ?");
    }

    sql.push_str(" ORDER BY created_at DESC");

    if let Some(_limit) = query.limit {
        sql.push_str(" LIMIT ?");
    }

    if let Some(_offset) = query.offset {
        sql.push_str(" OFFSET ?");
    }

    // Execute query
    let mut query_builder = sqlx::query_as::<_, Service>(&sql);
    query_builder = query_builder.bind(&org.id);

    if let Some(service_type) = &query.service_type {
        query_builder = query_builder.bind(service_type);
    }

    if let Some(limit) = query.limit {
        query_builder = query_builder.bind(limit);
    }

    if let Some(offset) = query.offset {
        query_builder = query_builder.bind(offset);
    }

    let services = query_builder.fetch_all(&state.pool).await?;

    // Get detailed information for each service
    let mut join_set = JoinSet::new();
    for service in services {
        let pool = state.pool.clone();
        let service_id = service.id.clone();
        join_set.spawn(async move {
            let plan_count: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM plans WHERE service_id = ?")
                    .bind(&service_id)
                    .fetch_one(&pool)
                    .await
                    .unwrap_or(0);

            let subscription_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM subscriptions WHERE service_id = ? AND status = 'active'",
            )
            .bind(&service_id)
            .fetch_one(&pool)
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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    let _membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&org.id)
    .bind(&auth_user.user.id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        crate::error::AppError::Forbidden("Not a member of this organization".to_string())
    })?;

    let service =
        sqlx::query_as::<_, Service>("SELECT * FROM services WHERE org_id = ? AND slug = ?")
            .bind(&org.id)
            .bind(&service_slug)
            .fetch_optional(&state.pool)
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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user has permission
    if !can_manage_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to update services".to_string(),
        ));
    }

    // Get existing service
    let _existing_service =
        sqlx::query_as::<_, Service>("SELECT * FROM services WHERE org_id = ? AND slug = ?")
            .bind(&org.id)
            .bind(&service_slug)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    let mut updates = Vec::new();
    let mut values = Vec::new();
    let mut scope_strings = Vec::new(); // To store the JSON strings with proper lifetime

    if let Some(name) = &req.name {
        updates.push("name = ?");
        values.push(name.clone());
    }

    if let Some(service_type) = &req.service_type {
        if !VALID_SERVICE_TYPES.contains(&service_type.as_str()) {
            return Err(crate::error::AppError::BadRequest(format!(
                "Invalid service type. Must be one of: {}",
                VALID_SERVICE_TYPES.join(", ")
            )));
        }
        updates.push("service_type = ?");
        values.push(service_type.clone());
    }

    if let Some(github_scopes) = &req.github_scopes {
        updates.push("github_scopes = ?");
        let scopes_json = serde_json::to_string(github_scopes).unwrap();
        values.push(scopes_json.clone());
        scope_strings.push(scopes_json);
    }

    if let Some(microsoft_scopes) = &req.microsoft_scopes {
        updates.push("microsoft_scopes = ?");
        let scopes_json = serde_json::to_string(microsoft_scopes).unwrap();
        values.push(scopes_json.clone());
        scope_strings.push(scopes_json);
    }

    if let Some(google_scopes) = &req.google_scopes {
        updates.push("google_scopes = ?");
        let scopes_json = serde_json::to_string(google_scopes).unwrap();
        values.push(scopes_json.clone());
        scope_strings.push(scopes_json);
    }

    if let Some(redirect_uris) = &req.redirect_uris {
        updates.push("redirect_uris = ?");
        let uris_json = serde_json::to_string(redirect_uris).unwrap();
        values.push(uris_json.clone());
        scope_strings.push(uris_json);
    }

    if let Some(device_activation_uri) = &req.device_activation_uri {
        updates.push("device_activation_uri = ?");
        values.push(device_activation_uri.clone());
    }

    if updates.is_empty() {
        return Err(crate::error::AppError::BadRequest(
            "No fields to update".to_string(),
        ));
    }

    let set_clause = updates.join(", ");

    let sql = format!(
        "UPDATE services SET {} WHERE org_id = ? AND slug = ?",
        set_clause
    );

    let mut query = sqlx::query(&sql);
    for value in &values {
        query = query.bind(value);
    }
    query = query.bind(&org.id).bind(&service_slug);

    query.execute(&state.pool).await?;

    // Fetch the updated service
    let updated_service =
        sqlx::query_as::<_, Service>("SELECT * FROM services WHERE org_id = ? AND slug = ?")
            .bind(&org.id)
            .bind(&service_slug)
            .fetch_one(&state.pool)
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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is owner (only owners can delete services)
    let membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&org.id)
    .bind(&auth_user.user.id)
    .fetch_optional(&state.pool)
    .await?;

    if membership.map(|m| m.role != "owner").unwrap_or(true) {
        return Err(crate::error::AppError::Forbidden(
            "Only organization owners can delete services".to_string(),
        ));
    }

    // Check if service has active subscriptions
    let subscription_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subscriptions WHERE service_id = (SELECT id FROM services WHERE org_id = ? AND slug = ?) AND status = 'active'",
    )
    .bind(&org.id)
    .bind(&service_slug)
    .fetch_one(&state.pool)
    .await?;

    if subscription_count > 0 {
        return Err(crate::error::AppError::BadRequest(
            "Cannot delete service with active subscriptions".to_string(),
        ));
    }

    let result = sqlx::query("DELETE FROM services WHERE org_id = ? AND slug = ?")
        .bind(&org.id)
        .bind(&service_slug)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user has permission
    if !can_manage_service(&state, &auth_user.user.id, &org.id).await? {
        return Err(crate::error::AppError::Forbidden(
            "Insufficient permissions to create plans".to_string(),
        ));
    }

    // Get service
    let service =
        sqlx::query_as::<_, Service>("SELECT * FROM services WHERE org_id = ? AND slug = ?")
            .bind(&org.id)
            .bind(&service_slug)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    let id = Uuid::new_v4().to_string();
    let features_json = req.features.map(|f| serde_json::to_string(&f).unwrap());

    let plan = sqlx::query_as::<_, Plan>(
        r#"
        INSERT INTO plans (
            id, service_id, name, price_cents, currency, features, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(&service.id)
    .bind(&req.name)
    .bind(req.price_cents)
    .bind(&req.currency)
    .bind(&features_json)
    .bind(Utc::now())
    .fetch_one(&state.pool)
    .await?;

    // Get subscription count (should be 0 for new plan)
    let subscription_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM subscriptions WHERE plan_id = ? AND status = 'active'",
    )
    .bind(&plan.id)
    .fetch_one(&state.pool)
    .await?;

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
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| crate::error::AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member
    let _membership = sqlx::query_as::<_, Membership>(
        "SELECT * FROM memberships WHERE org_id = ? AND user_id = ?",
    )
    .bind(&org.id)
    .bind(&auth_user.user.id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        crate::error::AppError::Forbidden("Not a member of this organization".to_string())
    })?;

    // Get service
    let service =
        sqlx::query_as::<_, Service>("SELECT * FROM services WHERE org_id = ? AND slug = ?")
            .bind(&org.id)
            .bind(&service_slug)
            .fetch_optional(&state.pool)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("Service not found".to_string()))?;

    let plans = sqlx::query_as::<_, Plan>(
        "SELECT * FROM plans WHERE service_id = ? ORDER BY price_cents ASC",
    )
    .bind(&service.id)
    .fetch_all(&state.pool)
    .await?;

    let mut responses = Vec::new();

    for plan in plans {
        // Get subscription count
        let subscription_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM subscriptions WHERE plan_id = ? AND status = 'active'",
        )
        .bind(&plan.id)
        .fetch_one(&state.pool)
        .await?;

        responses.push(PlanResponse {
            plan,
            subscription_count,
        });
    }

    Ok(Json(responses))
}
