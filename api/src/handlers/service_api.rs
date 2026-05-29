use crate::error::{AppError, Result};
use crate::middleware::ServicePrincipal;
use crate::state::AppState;
use crate::store::{
    DB, identities::IdentityStore, login_events::LoginEventStore,
    provider_token_requests::ProviderTokenRequestStore, services::ServiceStore,
    subscriptions::SubscriptionStore, users::UserStore,
};
use axum::{
    Json,
    extract::{Path, Query, State},
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
    let has_authenticated = IdentityStore::user_has_authenticated_with_service(
        DB::Conn(&state.db),
        user_id,
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

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    // Get total count of users who have authenticated with this service
    let total = IdentityStore::count_users_by_service(DB::Conn(&state.db), &principal.service_id)
        .await? as i64;

    // Get list of user IDs who have authenticated with this service
    let user_ids = IdentityStore::list_users_by_service(
        DB::Conn(&state.db),
        &principal.service_id,
        limit,
        offset,
    )
    .await?;

    // Fetch user details for these IDs
    let users = UserStore::find_by_ids(DB::Conn(&state.db), &user_ids).await?;

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

    // Verify the user has authenticated with this service
    let has_authenticated = IdentityStore::user_has_authenticated_with_service(
        DB::Conn(&state.db),
        &user_id,
        &principal.service_id,
    )
    .await?;

    if !has_authenticated {
        return Err(AppError::NotFound(
            "User not found or has not authenticated with this service".to_string(),
        ));
    }

    // Get the user
    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

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

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

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
    let total_users =
        IdentityStore::count_users_by_service(DB::Conn(&state.db), &principal.service_id).await?
            as i64;

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
        let has_identity = IdentityStore::user_has_authenticated_with_service(
            DB::Conn(&state.db),
            &user.id,
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
