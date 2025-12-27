use crate::entities::users;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    identities::IdentityStore, organizations::OrganizationStore, services::ServiceStore,
    sessions::SessionStore, subscriptions::SubscriptionStore, users::UserStore, DB,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct ListEndUsersQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub service_slug: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EndUserSubscription {
    pub service_id: String,
    pub service_slug: String,
    pub service_name: String,
    pub plan_id: String,
    pub plan_name: String,
    pub status: String,
    pub current_period_end: chrono::DateTime<Utc>,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct EndUserIdentity {
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct EndUser {
    pub user: users::Model,
    pub subscriptions: Vec<EndUserSubscription>,
    pub identities: Vec<EndUserIdentity>,
}

#[derive(Debug, Serialize)]
pub struct EndUserListResponse {
    pub users: Vec<EndUser>,
    pub total: i64,
    pub page: i64,
    pub limit: i64,
}

#[derive(Debug, Serialize)]
pub struct EndUserDetailResponse {
    pub user: users::Model,
    pub subscriptions: Vec<EndUserSubscription>,
    pub identities: Vec<EndUserIdentity>,
    pub session_count: i64,
}

/// List all end-users for an organization
/// End-users are those who have subscriptions to the organization's services
pub async fn list_end_users(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Query(query): Query<ListEndUsersQuery>,
) -> Result<Json<EndUserListResponse>> {
    let user = &auth_user.user;

    // Find organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member (any role can view end-users)
    crate::middleware::check_org_membership(&state.db, &user.id, &organization.id, &[]).await?;

    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = (page - 1) * limit;

    // Build query to get users who have identities or subscriptions for this organization
    // This includes users who logged in (have identities) even if they don't have subscriptions yet
    let (end_user_rows, service_id) = if let Some(ref service_slug) = query.service_slug {
        // Filter by specific service - first get the service
        let service =
            ServiceStore::find_by_slug_and_org(DB::Conn(&state.db), service_slug, &organization.id)
                .await?
                .ok_or_else(|| {
                    AppError::NotFound(format!("Service '{}' not found", service_slug))
                })?;

        let rows = SubscriptionStore::list_end_users_by_org(
            DB::Conn(&state.db),
            &organization.id,
            Some(&service.id),
            limit,
            offset,
        )
        .await?;
        (rows, Some(service.id))
    } else {
        // Show all users across all services in the organization
        let rows = SubscriptionStore::list_end_users_by_org(
            DB::Conn(&state.db),
            &organization.id,
            None,
            limit,
            offset,
        )
        .await?;
        (rows, None)
    };

    // Build user objects and collect their IDs
    let users: Vec<users::Model> = end_user_rows
        .into_iter()
        .map(|row| users::Model {
            id: row.id.clone(),
            email: row.email,
            is_platform_owner: row.is_platform_owner,
            password_hash: None,
            email_verified_at: None,
            created_at: DateTime::parse_from_rfc3339(&row.created_at)
                .ok()
                .map(|dt| dt.naive_utc())
                .unwrap_or_else(|| Utc::now().naive_utc()),
            updated_at: None,
            deleted_at: None,
        })
        .collect();

    let user_ids: Vec<String> = users.iter().map(|u| u.id.clone()).collect();

    // Early return if no users found
    if user_ids.is_empty() {
        return Ok(Json(EndUserListResponse {
            users: Vec::new(),
            total: 0,
            page,
            limit,
        }));
    }

    // Fetch subscriptions for these users (optionally filtered by service)
    let all_subscription_rows = SubscriptionStore::list_subscriptions_for_users_in_org(
        DB::Conn(&state.db),
        &user_ids,
        &organization.id,
        service_id.as_deref(),
    )
    .await?;

    // Group subscriptions by user_id
    let mut subscriptions_by_user: HashMap<String, Vec<EndUserSubscription>> = HashMap::new();
    for sub_row in all_subscription_rows {
        let subscription = EndUserSubscription {
            service_id: sub_row.service_id.clone(),
            service_slug: sub_row.service_slug,
            service_name: sub_row.service_name,
            plan_id: sub_row.plan_id,
            plan_name: sub_row.plan_name,
            status: sub_row.status,
            current_period_end: chrono::DateTime::parse_from_rfc3339(&sub_row.current_period_end)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            created_at: chrono::DateTime::parse_from_rfc3339(&sub_row.subscription_created_at)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
        };
        subscriptions_by_user
            .entry(sub_row.user_id)
            .or_default()
            .push(subscription);
    }

    // Fetch identities for these users (optionally filtered by service)
    let all_identity_rows = IdentityStore::list_identities_for_users_in_org(
        DB::Conn(&state.db),
        &user_ids,
        &organization.id,
        service_id.as_deref(),
    )
    .await?;

    // Group identities by user_id
    let mut identities_by_user: HashMap<String, Vec<EndUserIdentity>> = HashMap::new();
    for id_row in all_identity_rows {
        let identity = EndUserIdentity {
            provider: id_row.provider,
            provider_user_id: id_row.provider_user_id,
            created_at: chrono::DateTime::parse_from_rfc3339(&id_row.created_at)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
        };
        identities_by_user
            .entry(id_row.user_id)
            .or_default()
            .push(identity);
    }

    // Build end-user objects using the grouped data
    let end_users: Vec<EndUser> = users
        .into_iter()
        .map(|user| {
            let subscriptions = subscriptions_by_user.remove(&user.id).unwrap_or_default();
            let identities = identities_by_user.remove(&user.id).unwrap_or_default();

            EndUser {
                user,
                subscriptions,
                identities,
            }
        })
        .collect();

    // Get total count (matching the filter logic above)
    let total = SubscriptionStore::count_end_users_by_org(
        DB::Conn(&state.db),
        &organization.id,
        service_id.as_deref(),
    )
    .await?;

    Ok(Json(EndUserListResponse {
        users: end_users,
        total,
        page,
        limit,
    }))
}

/// Get detailed information about a specific end-user
pub async fn get_end_user(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, end_user_id)): Path<(String, String)>,
) -> Result<Json<EndUserDetailResponse>> {
    let user = &auth_user.user;

    // Find organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is member (any role can view end-users)
    crate::middleware::check_org_membership(&state.db, &user.id, &organization.id, &[]).await?;

    // Get end-user
    let end_user_obj = UserStore::find_by_id(DB::Conn(&state.db), &end_user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("End-user not found".to_string()))?;

    // Verify this user has subscriptions to this organization's services
    let subscription_count = SubscriptionStore::count_by_user_and_org(
        DB::Conn(&state.db),
        &end_user_id,
        &organization.id,
    )
    .await? as i64;

    if subscription_count == 0 {
        return Err(AppError::NotFound(
            "User is not an end-user of this organization".to_string(),
        ));
    }

    // Get subscriptions
    let subscription_rows = SubscriptionStore::list_with_details_by_user_and_org(
        DB::Conn(&state.db),
        &end_user_id,
        &organization.id,
    )
    .await?;

    let subscriptions: Vec<EndUserSubscription> = subscription_rows
        .into_iter()
        .map(|sub_row| EndUserSubscription {
            service_id: sub_row.service_id,
            service_slug: sub_row.service_slug,
            service_name: sub_row.service_name,
            plan_id: sub_row.plan_id,
            plan_name: sub_row.plan_name,
            status: sub_row.status,
            current_period_end: chrono::DateTime::parse_from_rfc3339(&sub_row.current_period_end)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
            created_at: chrono::DateTime::parse_from_rfc3339(&sub_row.created_at)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
        })
        .collect();

    // Get identities that were created via this organization's services
    // Only show identities where issuing_org_id matches this organization
    let identity_rows = IdentityStore::list_identities_for_user_in_org(
        DB::Conn(&state.db),
        &end_user_id,
        &organization.id,
    )
    .await?;

    let identities: Vec<EndUserIdentity> = identity_rows
        .into_iter()
        .map(|id_row| EndUserIdentity {
            provider: id_row.provider,
            provider_user_id: id_row.provider_user_id,
            created_at: chrono::DateTime::parse_from_rfc3339(&id_row.created_at)
                .ok()
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(Utc::now),
        })
        .collect();

    // Get active session count
    let session_count =
        SessionStore::count_active_by_user(DB::Conn(&state.db), &end_user_id).await? as i64;

    Ok(Json(EndUserDetailResponse {
        user: end_user_obj,
        subscriptions,
        identities,
        session_count,
    }))
}

/// Revoke all active sessions for an end-user (admin/owner only)
pub async fn revoke_end_user_sessions(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, end_user_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let user = &auth_user.user;

    // Find organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is admin or owner (required for session management)
    crate::middleware::check_org_admin(&state.db, &user.id, &organization.id).await?;

    // Verify this user has subscriptions to this organization's services
    let subscription_count = SubscriptionStore::count_by_user_and_org(
        DB::Conn(&state.db),
        &end_user_id,
        &organization.id,
    )
    .await? as i64;

    if subscription_count == 0 {
        return Err(AppError::NotFound(
            "User is not an end-user of this organization".to_string(),
        ));
    }

    // Delete all active sessions for this user
    let revoked_count =
        SessionStore::delete_all_for_user(DB::Conn(&state.db), &end_user_id).await?;

    Ok(Json(serde_json::json!({
        "message": "Sessions revoked successfully",
        "revoked_count": revoked_count
    })))
}
