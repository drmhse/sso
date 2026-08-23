use crate::error::{AppError, Result};
use crate::middleware::ServicePrincipal;
use crate::state::AppState;
use crate::store::{
    identities::IdentityStore, login_events::LoginEventStore,
    provider_token_requests::ProviderTokenRequestStore, services::ServiceStore,
    subscriptions::SubscriptionStore, users::UserStore, DB,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Helper to check if ServicePrincipal has required permission
fn check_permission(principal: &ServicePrincipal, required: &str) -> Result<()> {
    if !principal.permissions.contains(&required.to_string()) {
        return Err(AppError::Forbidden(format!(
            "Missing required permission: {}",
            required
        )));
    }
    Ok(())
}

async fn service_linked_user(
    state: &AppState,
    principal: &ServicePrincipal,
    user_id: &str,
) -> Result<crate::entities::users::Model> {
    let has_authenticated = IdentityStore::user_has_authenticated_with_org_service(
        DB::Conn(&state.db),
        user_id,
        &principal.service.org_id,
        &principal.service_id,
    )
    .await?;

    if !has_authenticated {
        return Err(AppError::NotFound(
            "User not found or has not authenticated with this service".to_string(),
        ));
    }

    let user = UserStore::find_by_id(DB::Conn(&state.db), user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if user.org_id.as_deref() != Some(principal.service.org_id.as_str()) {
        return Err(AppError::NotFound(
            "User not found or has not authenticated with this service".to_string(),
        ));
    }

    Ok(user)
}

/// Response for a user in the service API
#[derive(Debug, Serialize)]
pub struct ServiceApiUser {
    pub id: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

/// Query parameters for listing users
#[derive(Debug, Deserialize)]
pub struct ListUsersQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for listing users
#[derive(Debug, Serialize)]
pub struct ListUsersResponse {
    pub users: Vec<ServiceApiUser>,
    pub total: i64,
}

/// List all users who have authenticated with this service
/// Requires 'read:users' permission
pub async fn list_service_users(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Query(query): Query<ListUsersQuery>,
) -> Result<Json<ListUsersResponse>> {
    check_permission(&principal, "read:users")?;

    let (limit, offset) =
        crate::utils::pagination::signed_limit_offset(query.limit, query.offset, 50, 100);

    // Get total count of users who have authenticated with this service
    let total = IdentityStore::count_users_by_org_service(
        DB::Conn(&state.db),
        &principal.service.org_id,
        &principal.service_id,
    )
    .await? as i64;

    let users = IdentityStore::list_user_details_by_org_service(
        DB::Conn(&state.db),
        &principal.service.org_id,
        &principal.service_id,
        limit,
        offset,
    )
    .await?;

    let service_users: Vec<ServiceApiUser> = users
        .into_iter()
        .map(|u| ServiceApiUser {
            id: u.id,
            email: u.email,
            created_at: DateTime::from_naive_utc_and_offset(u.created_at, Utc),
        })
        .collect();

    Ok(Json(ListUsersResponse {
        users: service_users,
        total,
    }))
}

/// Get a specific user by ID
/// Requires 'read:users' permission
pub async fn get_service_user(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Path(user_id): Path<String>,
) -> Result<Json<ServiceApiUser>> {
    check_permission(&principal, "read:users")?;

    let user = service_linked_user(&state, &principal, &user_id).await?;

    Ok(Json(ServiceApiUser {
        id: user.id,
        email: user.email,
        created_at: DateTime::from_naive_utc_and_offset(user.created_at, Utc),
    }))
}

/// Response for a subscription in the service API
#[derive(Debug, Serialize)]
pub struct ServiceApiSubscription {
    pub id: String,
    pub user_id: String,
    pub plan_id: String,
    pub plan_name: String,
    pub status: String,
    pub current_period_end: DateTime<Utc>,
}

/// Query parameters for listing subscriptions
#[derive(Debug, Deserialize)]
pub struct ListSubscriptionsQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Response for listing subscriptions
#[derive(Debug, Serialize)]
pub struct ListSubscriptionsResponse {
    pub subscriptions: Vec<ServiceApiSubscription>,
    pub total: i64,
}

/// List all subscriptions for this service
/// Requires 'read:subscriptions' permission
pub async fn list_service_subscriptions(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Query(query): Query<ListSubscriptionsQuery>,
) -> Result<Json<ListSubscriptionsResponse>> {
    check_permission(&principal, "read:subscriptions")?;

    let (limit, offset) =
        crate::utils::pagination::signed_limit_offset(query.limit, query.offset, 50, 100);

    // Get total count with optional status filter
    let total = SubscriptionStore::count_by_service_with_status(
        DB::Conn(&state.db),
        &principal.service_id,
        query.status.as_deref(),
    )
    .await?;

    // Get subscriptions with plan details
    let rows = SubscriptionStore::list_by_service_with_plan_details(
        DB::Conn(&state.db),
        &principal.service_id,
        query.status.as_deref(),
        limit,
        offset,
    )
    .await?;

    let subscriptions: Vec<ServiceApiSubscription> = rows
        .into_iter()
        .map(|row| {
            // Parse the datetime string
            let current_period_end = chrono::DateTime::parse_from_rfc3339(&row.current_period_end)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now());

            ServiceApiSubscription {
                id: row.id,
                user_id: row.user_id,
                plan_id: row.plan_id,
                plan_name: row.plan_name,
                status: row.status,
                current_period_end,
            }
        })
        .collect();

    Ok(Json(ListSubscriptionsResponse {
        subscriptions,
        total,
    }))
}

/// Get subscription status for a specific user
/// Requires 'read:subscriptions' permission
pub async fn get_user_subscription(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Path(user_id): Path<String>,
) -> Result<Json<ServiceApiSubscription>> {
    check_permission(&principal, "read:subscriptions")?;

    // Get subscription for user
    let row = SubscriptionStore::get_by_user_and_service(
        DB::Conn(&state.db),
        &user_id,
        &principal.service_id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Subscription not found for this user".to_string()))?;

    // Parse the datetime string
    let current_period_end = chrono::DateTime::parse_from_rfc3339(&row.current_period_end)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());

    Ok(Json(ServiceApiSubscription {
        id: row.id,
        user_id: row.user_id,
        plan_id: row.plan_id,
        plan_name: row.plan_name,
        status: row.status,
        current_period_end,
    }))
}

/// Response for service analytics
#[derive(Debug, Serialize)]
pub struct ServiceAnalyticsResponse {
    pub total_users: i64,
    pub total_subscriptions: i64,
    pub active_subscriptions: i64,
    pub total_logins_30d: i64,
    pub unique_users_30d: i64,
}

/// Get analytics for the service
/// Requires 'read:analytics' permission
pub async fn get_service_analytics(
    State(state): State<AppState>,
    principal: ServicePrincipal,
) -> Result<Json<ServiceAnalyticsResponse>> {
    check_permission(&principal, "read:analytics")?;

    // Get total users who have authenticated
    let total_users = IdentityStore::count_users_by_org_service(
        DB::Conn(&state.db),
        &principal.service.org_id,
        &principal.service_id,
    )
    .await? as i64;

    // Get total subscriptions
    let total_subscriptions =
        SubscriptionStore::count_by_service(DB::Conn(&state.db), &principal.service_id).await?;

    // Get active subscriptions
    let active_subscriptions =
        SubscriptionStore::count_active_by_service(DB::Conn(&state.db), &principal.service_id)
            .await?;

    // Calculate the datetime for 30 days ago
    let thirty_days_ago = (chrono::Utc::now() - chrono::Duration::days(30)).naive_utc();

    // Get login count in last 30 days
    let total_logins_30d = LoginEventStore::count_by_service_since(
        DB::Conn(&state.db),
        &principal.service_id,
        thirty_days_ago,
    )
    .await?;

    // Get unique users in last 30 days
    let unique_users_30d = LoginEventStore::count_distinct_users_by_service_since(
        DB::Conn(&state.db),
        &principal.service_id,
        thirty_days_ago,
    )
    .await?;

    Ok(Json(ServiceAnalyticsResponse {
        total_users,
        total_subscriptions,
        active_subscriptions,
        total_logins_30d,
        unique_users_30d,
    }))
}

/// Response for service info
#[derive(Debug, Serialize)]
pub struct ServiceInfoResponse {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub service_type: String,
    pub created_at: DateTime<Utc>,
}

/// Get information about the service
/// Requires 'read:service' permission
pub async fn get_service_info(
    State(state): State<AppState>,
    principal: ServicePrincipal,
) -> Result<Json<ServiceInfoResponse>> {
    check_permission(&principal, "read:service")?;

    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &principal.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    Ok(Json(ServiceInfoResponse {
        id: service.id,
        name: service.name,
        slug: service.slug,
        service_type: service.service_type,
        created_at: DateTime::from_naive_utc_and_offset(service.created_at, Utc),
    }))
}

// ===== WRITE OPERATIONS =====

/// Request body for creating a user
#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
}

/// Create a new user
/// Requires 'write:users' permission
///
/// Security Audit Item 3: Implements "Silent Invitation" pattern.
/// If email exists in another context, returns fake success and triggers invitation.
pub async fn create_user(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Json(payload): Json<CreateUserRequest>,
) -> Result<(axum::http::StatusCode, Json<ServiceApiUser>)> {
    check_permission(&principal, "write:users")?;

    // Validate email format
    if !payload.email.contains('@') {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Check if user already exists IN THIS ORGANIZATION
    let existing_user = UserStore::find_by_email_with_context(
        DB::Conn(&state.db),
        &payload.email,
        Some(&principal.service.org_id),
    )
    .await?;

    if let Some(user) = existing_user {
        // User exists in this Org - check if already linked to this specific Service
        let has_identity = IdentityStore::user_has_authenticated_with_org_service(
            DB::Conn(&state.db),
            &user.id,
            &principal.service.org_id,
            &principal.service_id,
        )
        .await?;

        if has_identity {
            // Already linked - return the existing user (idempotent)
            return Ok((
                axum::http::StatusCode::OK,
                Json(ServiceApiUser {
                    id: user.id,
                    email: user.email,
                    created_at: DateTime::from_naive_utc_and_offset(user.created_at, Utc),
                }),
            ));
        }

        // Link existing Org User to this Service
        IdentityStore::create(
            DB::Conn(&state.db),
            &user.id,
            "service_api",
            &user.email,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&principal.service.org_id),
            Some(&principal.service_id),
        )
        .await?;

        return Ok((
            axum::http::StatusCode::CREATED,
            Json(ServiceApiUser {
                id: user.id,
                email: user.email,
                created_at: DateTime::from_naive_utc_and_offset(user.created_at, Utc),
            }),
        ));
    }

    // User doesn't exist in this organization - create new tenant-scoped user
    let user = UserStore::create_with_org_id(
        DB::Conn(&state.db),
        &payload.email,
        None, // No password
        &principal.service.org_id,
    )
    .await?;

    // Link the user to this service via an identity record
    IdentityStore::create(
        DB::Conn(&state.db),
        &user.id,
        "service_api",
        &user.email,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        Some(&principal.service.org_id),
        Some(&principal.service_id),
    )
    .await?;

    // Publish signup event (new user created)
    use crate::services::events::{Event, EventType};
    use serde_json::json;

    let event = Event::builder(EventType::UserSignupSuccess)
        .actor_user_id(&user.id)
        .actor_email(&payload.email)
        .org_id(&principal.service.org_id)
        .detail("service_id", json!(&principal.service_id))
        .detail("api_key_method", json!(true))
        .build();

    let dispatcher = state.event_dispatcher.clone();
    tokio::spawn(async move {
        if let Err(e) = dispatcher.publish(event).await {
            tracing::error!("Failed to publish signup event: {}", e);
        }
    });

    Ok((
        axum::http::StatusCode::CREATED,
        Json(ServiceApiUser {
            id: user.id,
            email: user.email,
            created_at: DateTime::from_naive_utc_and_offset(user.created_at, Utc),
        }),
    ))
}

/// Request body for updating a user
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
}

/// Update user details
/// Requires 'write:users' permission
pub async fn update_user(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> Result<Json<ServiceApiUser>> {
    check_permission(&principal, "write:users")?;

    if payload.email.is_some() {
        return Err(AppError::Forbidden(
            "Service API keys cannot update organization user profile fields".to_string(),
        ));
    }

    let user = service_linked_user(&state, &principal, &user_id).await?;

    Ok(Json(ServiceApiUser {
        id: user.id,
        email: user.email,
        created_at: DateTime::from_naive_utc_and_offset(user.created_at, Utc),
    }))
}

/// Request body for creating a subscription
#[derive(Debug, Deserialize)]
pub struct CreateSubscriptionRequest {
    pub user_id: String,
    pub plan_id: String,
    pub status: Option<String>,
    pub current_period_end: Option<String>,
}

use crate::store::plans::PlanStore;

/// Create a new subscription
/// Requires 'write:subscriptions' permission
pub async fn create_subscription(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Json(payload): Json<CreateSubscriptionRequest>,
) -> Result<Json<ServiceApiSubscription>> {
    check_permission(&principal, "write:subscriptions")?;

    // Verify the plan belongs to this service
    let plan = PlanStore::find_by_id(DB::Conn(&state.db), &payload.plan_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Plan not found".to_string()))?;

    if plan.service_id != principal.service_id {
        return Err(AppError::Forbidden(
            "Plan does not belong to this service".to_string(),
        ));
    }

    let user = service_linked_user(&state, &principal, &payload.user_id).await?;

    // Set defaults
    let status = payload.status.unwrap_or_else(|| "active".to_string());
    let current_period_end = payload
        .current_period_end
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.naive_utc())
                .map_err(|e| AppError::BadRequest(format!("Invalid current_period_end: {}", e)))
        })
        .transpose()?
        .unwrap_or_else(|| (Utc::now() + chrono::Duration::days(30)).naive_utc());

    // Create the subscription
    let subscription = SubscriptionStore::create(
        DB::Conn(&state.db),
        &user.id,
        &principal.service_id,
        &payload.plan_id,
        &status,
        current_period_end,
    )
    .await?;

    // Parse the datetime string
    let period_end = DateTime::from_naive_utc_and_offset(subscription.current_period_end, Utc);

    Ok(Json(ServiceApiSubscription {
        id: subscription.id,
        user_id: subscription.user_id,
        plan_id: subscription.plan_id,
        plan_name: plan.name,
        status: subscription.status,
        current_period_end: period_end,
    }))
}

/// Request body for updating a subscription
#[derive(Debug, Deserialize)]
pub struct UpdateSubscriptionRequest {
    pub status: Option<String>,
    pub current_period_end: Option<String>,
}

/// Update subscription for a user
/// Requires 'write:subscriptions' permission
pub async fn update_subscription(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Path(user_id): Path<String>,
    Json(payload): Json<UpdateSubscriptionRequest>,
) -> Result<Json<ServiceApiSubscription>> {
    check_permission(&principal, "write:subscriptions")?;
    service_linked_user(&state, &principal, &user_id).await?;

    // Update the subscription
    let current_period_end = payload
        .current_period_end
        .as_ref()
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.naive_utc())
                .map_err(|e| AppError::BadRequest(format!("Invalid current_period_end: {}", e)))
        })
        .transpose()?;

    let subscription = SubscriptionStore::update(
        DB::Conn(&state.db),
        &user_id,
        &principal.service_id,
        payload.status.as_deref(),
        current_period_end,
    )
    .await?;

    // Get plan details
    let plan = PlanStore::find_by_id(DB::Conn(&state.db), &subscription.plan_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Plan not found".to_string()))?;

    // Parse the datetime string
    let period_end = DateTime::from_naive_utc_and_offset(subscription.current_period_end, Utc);

    Ok(Json(ServiceApiSubscription {
        id: subscription.id,
        user_id: subscription.user_id,
        plan_id: subscription.plan_id,
        plan_name: plan.name,
        status: subscription.status,
        current_period_end: period_end,
    }))
}

/// Request body for updating service info
#[derive(Debug, Deserialize)]
pub struct UpdateServiceInfoRequest {
    pub name: Option<String>,
}

/// Update service configuration
/// Requires 'write:service' permission
pub async fn update_service_info(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Json(payload): Json<UpdateServiceInfoRequest>,
) -> Result<Json<ServiceInfoResponse>> {
    check_permission(&principal, "write:service")?;

    // Update the service
    let service = if let Some(name) = payload.name {
        ServiceStore::update_name(DB::Conn(&state.db), &principal.service_id, &name).await?
    } else {
        // If no fields to update, just return the existing service
        ServiceStore::find_by_id(DB::Conn(&state.db), &principal.service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?
    };

    Ok(Json(ServiceInfoResponse {
        id: service.id,
        name: service.name,
        slug: service.slug,
        service_type: service.service_type,
        created_at: DateTime::from_naive_utc_and_offset(service.created_at, Utc),
    }))
}

// ===== DELETE OPERATIONS =====

/// Delete a user
/// Requires 'delete:users' permission
///
/// Security Audit Item 2: Only deletes the identity link to this service.
/// Does NOT delete the global user record (they may belong to other services).
pub async fn delete_user(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Path(user_id): Path<String>,
) -> Result<axum::http::StatusCode> {
    check_permission(&principal, "delete:users")?;

    service_linked_user(&state, &principal, &user_id).await?;

    // Security Audit Item 2: Delete only the identity link to this service
    // This prevents one service from deleting a user who belongs to multiple services
    IdentityStore::delete_by_user_and_service(DB::Conn(&state.db), &user_id, &principal.service_id)
        .await?;

    ProviderTokenRequestStore::cancel_pending_for_user_service(
        DB::Conn(&state.db),
        &user_id,
        &principal.service_id,
    )
    .await?;

    // Also delete any subscriptions for this user in this service
    let _ = SubscriptionStore::delete(DB::Conn(&state.db), &user_id, &principal.service_id).await;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Delete a subscription for a user
/// Requires 'delete:subscriptions' permission
pub async fn delete_subscription(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Path(user_id): Path<String>,
) -> Result<axum::http::StatusCode> {
    check_permission(&principal, "delete:subscriptions")?;
    service_linked_user(&state, &principal, &user_id).await?;

    // Delete the subscription for this user and service
    SubscriptionStore::delete(DB::Conn(&state.db), &user_id, &principal.service_id).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtService;
    use crate::auth::sso::OAuthClient;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::entities::services;
    use crate::middleware::ServicePrincipal;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        audit_actor::AuditHandle, events::EventDispatcher, metrics::MfaMetricsService,
        risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{organizations::OrganizationStore, plans::PlanStore, users::UserStore, DB};
    use axum::http::StatusCode;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;
    use uuid::Uuid;

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

    struct Fixture {
        state: AppState,
        principal: ServicePrincipal,
        other_principal: ServicePrincipal,
    }

    fn principal_for(service: &services::Model, permissions: &[&str]) -> ServicePrincipal {
        ServicePrincipal {
            api_key_id: "test-key".to_string(),
            service_id: service.id.clone(),
            service: service.clone(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
        }
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();

        let owner = UserStore::create(DB::Conn(&db), "service-api-owner@example.test", None, false)
            .await
            .expect("create owner");
        let (org, _) =
            OrganizationStore::create_with_owner(DB::Conn(&db), "acme", "Acme", &owner.id, None)
                .await
                .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");

        async fn make_service(
            db: &sea_orm::DatabaseConnection,
            org_id: &str,
            slug: &str,
        ) -> services::Model {
            ServiceStore::create_with_options(
                DB::Conn(db),
                &Uuid::new_v4().to_string(),
                org_id,
                slug,
                slug,
                "web",
                &Uuid::new_v4().to_string(),
                "unused-hash",
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .await
            .expect("create service")
        }
        let service = make_service(&db, &org.id, "portal").await;
        let other_service = make_service(&db, &org.id, "other").await;

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("create oauth client")),
            jwt_service: Arc::new({
                let rsa = GeneratedKey::generate().expect("generate test rsa key");
                JwtService::new(
                    &STANDARD.encode(rsa.private_key_pem().expect("private pem")),
                    &STANDARD.encode(rsa.public_key_pem().expect("public pem")),
                    config.jwt_expiration_hours,
                    "test-key",
                    &config.base_url,
                )
                .expect("create jwt service")
            }),
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
        };

        Fixture {
            principal: principal_for(
                &service,
                &[
                    "read:users",
                    "write:users",
                    "delete:users",
                    "read:subscriptions",
                    "write:subscriptions",
                    "delete:subscriptions",
                    "read:analytics",
                    "read:service",
                    "write:service",
                ],
            ),
            other_principal: principal_for(&other_service, &["read:users"]),
            state,
        }
    }

    /// Creates a user through the API itself, which also links the identity.
    async fn create_linked_user(f: &Fixture, email: &str) -> ServiceApiUser {
        let (status, Json(user)) = create_user(
            State(f.state.clone()),
            f.principal.clone(),
            Json(CreateUserRequest {
                email: email.to_string(),
            }),
        )
        .await
        .expect("create user");
        assert_eq!(status, StatusCode::CREATED);
        user
    }

    #[tokio::test]
    async fn missing_permissions_are_rejected_everywhere() {
        let f = fixture().await;
        // The other principal only carries read:users.
        match list_service_subscriptions(
            State(f.state.clone()),
            f.other_principal.clone(),
            Query(ListSubscriptionsQuery {
                status: None,
                limit: None,
                offset: None,
            }),
        )
        .await
        {
            Err(AppError::Forbidden(message)) => assert!(message.contains("permission")),
            other => panic!("expected forbidden, got {other:?}"),
        }
        match get_service_analytics(State(f.state.clone()), f.other_principal.clone()).await {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }
        match update_service_info(
            State(f.state.clone()),
            f.other_principal.clone(),
            Json(UpdateServiceInfoRequest {
                name: Some("x".to_string()),
            }),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_user_is_idempotent_per_service_and_validates_email() {
        let f = fixture().await;
        let (status, Json(first)) = create_user(
            State(f.state.clone()),
            f.principal.clone(),
            Json(CreateUserRequest {
                email: "new-user@example.test".to_string(),
            }),
        )
        .await
        .expect("create user");
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(first.email, "new-user@example.test");

        // Second creation returns 200 with the same identity.
        let (status, Json(second)) = create_user(
            State(f.state.clone()),
            f.principal.clone(),
            Json(CreateUserRequest {
                email: "new-user@example.test".to_string(),
            }),
        )
        .await
        .expect("re-create user");
        assert_eq!(status, StatusCode::OK);
        assert_eq!(second.id, first.id);

        match create_user(
            State(f.state.clone()),
            f.principal.clone(),
            Json(CreateUserRequest {
                email: "not-an-email".to_string(),
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("email")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn users_can_be_listed_fetched_and_unlinked() {
        let f = fixture().await;
        let user = create_linked_user(&f, "listed@example.test").await;

        let Json(list) = list_service_users(
            State(f.state.clone()),
            f.principal.clone(),
            Query(ListUsersQuery {
                limit: None,
                offset: None,
            }),
        )
        .await
        .expect("list users");
        assert_eq!(list.total, 1);
        assert_eq!(list.users[0].id, user.id);

        let Json(got) = get_service_user(
            State(f.state.clone()),
            f.principal.clone(),
            Path(user.id.clone()),
        )
        .await
        .expect("get user");
        assert_eq!(got.email, "listed@example.test");

        match get_service_user(
            State(f.state.clone()),
            f.principal.clone(),
            Path("missing".to_string()),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found, got {other:?}"),
        }

        // Deleting unlinks but does not remove the global user.
        let status = delete_user(
            State(f.state.clone()),
            f.principal.clone(),
            Path(user.id.clone()),
        )
        .await
        .expect("delete user");
        assert_eq!(status, StatusCode::NO_CONTENT);

        match get_service_user(State(f.state.clone()), f.principal.clone(), Path(user.id)).await {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found after unlink, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn profile_updates_via_service_keys_are_refused() {
        let f = fixture().await;
        let user = create_linked_user(&f, "profile@example.test").await;

        match update_user(
            State(f.state.clone()),
            f.principal.clone(),
            Path(user.id.clone()),
            Json(UpdateUserRequest {
                email: Some("new@example.test".to_string()),
            }),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }

        // An empty payload is a harmless read-shaped update.
        let Json(same) = update_user(
            State(f.state.clone()),
            f.principal.clone(),
            Path(user.id.clone()),
            Json(UpdateUserRequest { email: None }),
        )
        .await
        .expect("empty update");
        assert_eq!(same.id, user.id);
    }

    #[tokio::test]
    async fn subscription_lifecycle_scoped_to_the_owning_service() {
        let f = fixture().await;
        let user = create_linked_user(&f, "subscriber@example.test").await;

        // Create a plan on our service and one on the other service.
        let now_str = Utc::now().naive_utc();
        let plan_id = Uuid::new_v4().to_string();
        PlanStore::create(
            DB::Conn(&f.state.db),
            &plan_id,
            &f.principal.service_id,
            "Pro",
            None,
            1999,
            "usd",
            "[]",
            None,
            false,
            now_str,
        )
        .await
        .expect("create own plan");
        let foreign_plan_id = Uuid::new_v4().to_string();
        PlanStore::create(
            DB::Conn(&f.state.db),
            &foreign_plan_id,
            &f.other_principal.service_id,
            "Other Pro",
            None,
            999,
            "usd",
            "[]",
            None,
            false,
            now_str,
        )
        .await
        .expect("create foreign plan");

        // A plan belonging to another service is refused.
        match create_subscription(
            State(f.state.clone()),
            f.principal.clone(),
            Json(CreateSubscriptionRequest {
                user_id: user.id.clone(),
                plan_id: foreign_plan_id,
                status: None,
                current_period_end: None,
            }),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden for foreign plan, got {other:?}"),
        }

        let Json(created) = create_subscription(
            State(f.state.clone()),
            f.principal.clone(),
            Json(CreateSubscriptionRequest {
                user_id: user.id.clone(),
                plan_id: plan_id.clone(),
                status: Some("active".to_string()),
                current_period_end: Some("2030-01-01T00:00:00Z".to_string()),
            }),
        )
        .await
        .expect("create subscription");
        assert_eq!(created.plan_name, "Pro");

        let Json(list) = list_service_subscriptions(
            State(f.state.clone()),
            f.principal.clone(),
            Query(ListSubscriptionsQuery {
                status: None,
                limit: None,
                offset: None,
            }),
        )
        .await
        .expect("list subscriptions");
        assert_eq!(list.subscriptions.len(), 1);

        let Json(got) = get_user_subscription(
            State(f.state.clone()),
            f.principal.clone(),
            Path(user.id.clone()),
        )
        .await
        .expect("get subscription");
        assert_eq!(got.status, "active");

        let updated = update_subscription(
            State(f.state.clone()),
            f.principal.clone(),
            Path(user.id.clone()),
            Json(UpdateSubscriptionRequest {
                status: Some("cancelled".to_string()),
                current_period_end: Some("bad-date".to_string()),
            }),
        )
        .await;
        match updated {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("Invalid current_period_end"))
            }
            other => panic!("expected BadRequest for bad date, got {other:?}"),
        }

        let status = delete_subscription(
            State(f.state.clone()),
            f.principal.clone(),
            Path(user.id.clone()),
        )
        .await
        .expect("delete subscription");
        assert_eq!(status, StatusCode::NO_CONTENT);

        match get_user_subscription(State(f.state.clone()), f.principal.clone(), Path(user.id))
            .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found after delete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn analytics_and_service_info_round_trip() {
        let f = fixture().await;
        let _user = create_linked_user(&f, "counted@example.test").await;

        let Json(analytics) = get_service_analytics(State(f.state.clone()), f.principal.clone())
            .await
            .expect("analytics");
        assert_eq!(analytics.total_users, 1);
        assert_eq!(analytics.total_subscriptions, 0);

        let Json(info) = get_service_info(State(f.state.clone()), f.principal.clone())
            .await
            .expect("service info");
        assert_eq!(info.slug, "portal");

        let Json(updated) = update_service_info(
            State(f.state.clone()),
            f.principal.clone(),
            Json(UpdateServiceInfoRequest {
                name: Some("Portal Renamed".to_string()),
            }),
        )
        .await
        .expect("update service info");
        assert_eq!(updated.name, "Portal Renamed");
    }
}
