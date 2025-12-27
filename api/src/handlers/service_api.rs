use crate::error::{AppError, Result};
use crate::middleware::ServicePrincipal;
use crate::state::AppState;
use crate::store::{
    identities::IdentityStore, login_events::LoginEventStore, services::ServiceStore,
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
pub async fn create_user(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Json(payload): Json<CreateUserRequest>,
) -> Result<Json<ServiceApiUser>> {
    check_permission(&principal, "write:users")?;

    // Validate email format
    if !payload.email.contains('@') {
        return Err(AppError::BadRequest("Invalid email format".to_string()));
    }

    // Create the user (find_or_create will return existing user if email already exists)
    let (user, was_created) =
        UserStore::find_or_create(DB::Conn(&state.db), &payload.email).await?;

    // Link the user to this service via an identity record if one doesn't exist
    // This allows list_service_users and get_service_user to work
    let has_identity = IdentityStore::user_has_authenticated_with_service(
        DB::Conn(&state.db),
        &user.id,
        &principal.service_id,
    )
    .await?;

    if !has_identity {
        IdentityStore::create(
            DB::Conn(&state.db),
            &user.id,
            "service_api",                   // Provider name for service-created users
            &user.email,                     // Use email as provider_user_id
            None,                            // access_token
            None,                            // refresh_token
            None,                            // access_token_encrypted
            None,                            // refresh_token_encrypted
            None,                            // encryption_key_id
            None,                            // expires_at
            None,                            // scopes
            Some(&principal.service.org_id), // issuing_org_id
            Some(&principal.service_id),     // issuing_service_id
        )
        .await?;
    }

    // Publish signup event if user was just created (via Service API)
    if was_created {
        use crate::services::events::{Event, EventType};
        use serde_json::json;

        let event = Event::builder(EventType::UserSignupSuccess)
            .actor_user_id(&user.id)
            .actor_email(&payload.email)
            .org_id(&principal.service.org_id)
            .detail("service_id", json!(&principal.service_id))
            .detail("api_key_method", json!(true))
            .build();

        // Fire and forget
        let dispatcher = state.event_dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatcher.publish(event).await {
                tracing::error!("Failed to publish signup event: {}", e);
            }
        });
    }

    Ok(Json(ServiceApiUser {
        id: user.id,
        email: user.email,
        created_at: DateTime::from_naive_utc_and_offset(user.created_at, Utc),
    }))
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

    // Update email if provided
    let user = if let Some(email) = payload.email {
        // Validate email format
        if !email.contains('@') {
            return Err(AppError::BadRequest("Invalid email format".to_string()));
        }

        // Check if email is already taken by another user
        if UserStore::is_email_taken(DB::Conn(&state.db), &email, &user_id).await? {
            return Err(AppError::BadRequest(
                "Email already taken by another user".to_string(),
            ));
        }

        UserStore::update_email(DB::Conn(&state.db), &user_id, &email).await?
    } else {
        // If no fields to update, just return the existing user
        UserStore::find_by_id(DB::Conn(&state.db), &user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?
    };

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

    // Verify user exists
    let user = UserStore::find_by_id(DB::Conn(&state.db), &payload.user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Set defaults
    let status = payload.status.unwrap_or_else(|| "active".to_string());
    let current_period_end = payload
        .current_period_end
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .unwrap()
                .naive_utc()
        })
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

    // Update the subscription
    let current_period_end = payload
        .current_period_end
        .as_ref()
        .map(|s| chrono::DateTime::parse_from_rfc3339(s).unwrap().naive_utc());

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
pub async fn delete_user(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Path(user_id): Path<String>,
) -> Result<axum::http::StatusCode> {
    check_permission(&principal, "delete:users")?;

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

    // Delete the user (will cascade delete related data)
    UserStore::delete(DB::Conn(&state.db), &user_id).await?;

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

    // Delete the subscription for this user and service
    SubscriptionStore::delete(DB::Conn(&state.db), &user_id, &principal.service_id).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}
