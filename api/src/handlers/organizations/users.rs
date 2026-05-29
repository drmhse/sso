use crate::entities::users;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{
    PermissionService, CAP_END_USERS_MANAGE, CAP_END_USERS_VIEW,
};
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
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

async fn require_end_user_viewer(state: &AppState, org_id: &str, user_id: &str) -> Result<()> {
    if PermissionService::check_any(
        DB::Conn(&state.db),
        org_id,
        user_id,
        &[CAP_END_USERS_VIEW, CAP_END_USERS_MANAGE],
    )
    .await?
    {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to view end users".to_string(),
    ))
}

async fn require_end_user_manager(state: &AppState, org_id: &str, user_id: &str) -> Result<()> {
    if PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_END_USERS_MANAGE).await? {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to manage end users".to_string(),
    ))
}

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
    pub sessions: Vec<EndUserSession>,
    pub recent_logins: Vec<EndUserLoginEvent>,
}

#[derive(Debug, Serialize)]
pub struct EndUserSession {
    pub id: String,
    pub service_id: Option<String>,
    pub service_name: Option<String>,
    pub org_slug: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: chrono::DateTime<Utc>,
    pub refresh_token_expires_at: Option<chrono::DateTime<Utc>>,
    pub created_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct EndUserLoginEvent {
    pub id: String,
    pub service_id: Option<String>,
    pub service_name: Option<String>,
    pub provider: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub risk_score: Option<i32>,
    pub risk_factors: Vec<String>,
    pub geo_country: Option<String>,
    pub geo_city: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
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

    require_end_user_viewer(&state, &organization.id, &user.id).await?;

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
            org_id: None,
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

    require_end_user_viewer(&state, &organization.id, &user.id).await?;

    // Get end-user
    let end_user_obj = UserStore::find_by_id(DB::Conn(&state.db), &end_user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("End-user not found".to_string()))?;

    // Verify this user is an end-user of this organization
    // Uses the same query logic as list_end_users_by_org for consistency
    let is_end_user =
        SubscriptionStore::is_end_user_of_org(DB::Conn(&state.db), &end_user_id, &organization.id)
            .await?;

    if !is_end_user {
        tracing::warn!(
            user_id = %end_user_id,
            org_id = %organization.id,
            "End-user validation failed: user is not an end-user of this organization"
        );
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

    // Get scoped sessions and recent login events to support admin troubleshooting.
    let org_services = ServiceStore::list_by_org(DB::Conn(&state.db), &organization.id).await?;
    let service_ids: HashSet<String> = org_services
        .iter()
        .map(|service| service.id.clone())
        .collect();
    let service_names: HashMap<String, String> = org_services
        .into_iter()
        .map(|service| (service.id, service.name))
        .collect();

    let now = Utc::now().naive_utc();
    let sessions = SessionStore::list_by_user(DB::Conn(&state.db), &end_user_id)
        .await?
        .into_iter()
        .filter(|session| {
            session.org_slug.as_deref() == Some(&org_slug)
                || session
                    .service_id
                    .as_ref()
                    .map(|id| service_ids.contains(id))
                    .unwrap_or(false)
        })
        .map(|session| EndUserSession {
            id: session.id,
            service_name: session
                .service_id
                .as_ref()
                .and_then(|id| service_names.get(id).cloned()),
            service_id: session.service_id,
            org_slug: session.org_slug,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
            expires_at: chrono::DateTime::from_naive_utc_and_offset(session.expires_at, Utc),
            refresh_token_expires_at: session
                .refresh_token_expires_at
                .map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, Utc)),
            created_at: chrono::DateTime::from_naive_utc_and_offset(session.created_at, Utc),
        })
        .collect::<Vec<_>>();

    let session_count = sessions
        .iter()
        .filter(|session| session.expires_at.naive_utc() > now)
        .count() as i64;

    use crate::entities::login_events::{Column as LoginEventColumn, Entity as LoginEvents};
    let login_rows = LoginEvents::find()
        .filter(LoginEventColumn::UserId.eq(&end_user_id))
        .filter(LoginEventColumn::OrgId.eq(&organization.id))
        .order_by_desc(LoginEventColumn::CreatedAt)
        .limit(20)
        .all(&state.db)
        .await?;

    let recent_logins = login_rows
        .into_iter()
        .map(|event| EndUserLoginEvent {
            id: event.id,
            service_name: event
                .service_id
                .as_ref()
                .and_then(|id| service_names.get(id).cloned()),
            service_id: event.service_id,
            provider: event.provider,
            ip_address: event.ip_address,
            user_agent: event.user_agent,
            risk_score: event.risk_score,
            risk_factors: event
                .risk_factors
                .as_ref()
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or_default(),
            geo_country: event.geo_country,
            geo_city: event.geo_city,
            created_at: chrono::DateTime::from_naive_utc_and_offset(event.created_at, Utc),
        })
        .collect();

    Ok(Json(EndUserDetailResponse {
        user: end_user_obj,
        subscriptions,
        identities,
        session_count,
        sessions,
        recent_logins,
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

    require_end_user_manager(&state, &organization.id, &user.id).await?;

    // Verify this user is an end-user of this organization
    let is_end_user =
        SubscriptionStore::is_end_user_of_org(DB::Conn(&state.db), &end_user_id, &organization.id)
            .await?;

    if !is_end_user {
        return Err(AppError::NotFound(
            "User is not an end-user of this organization".to_string(),
        ));
    }

    let org_services = ServiceStore::list_by_org(DB::Conn(&state.db), &organization.id).await?;
    let service_ids: Vec<String> = org_services.into_iter().map(|service| service.id).collect();

    let revoked_count = SessionStore::delete_user_org_scoped_sessions(
        DB::Conn(&state.db),
        &end_user_id,
        &org_slug,
        &service_ids,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": "Sessions revoked successfully",
        "revoked_count": revoked_count
    })))
}
