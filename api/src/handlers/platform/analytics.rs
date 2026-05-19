use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    login_events::LoginEventStore, organizations::OrganizationStore, services::ServiceStore,
    users::UserStore, DB,
};
use axum::{
    extract::{Query, State},
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AnalyticsDateRangeQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PlatformOverviewMetrics {
    pub total_organizations: i64,
    pub total_users: i64,
    pub total_end_users: i64,
    pub total_services: i64,
    pub total_logins_24h: i64,
    pub total_logins_30d: i64,
}

#[derive(Debug, Serialize)]
pub struct OrganizationStatusBreakdown {
    pub pending: i64,
    pub active: i64,
    pub suspended: i64,
    pub rejected: i64,
}

#[derive(Debug, Serialize)]
pub struct GrowthTrendPoint {
    pub date: String,
    pub new_organizations: i64,
    pub new_users: i64,
}

#[derive(Debug, Serialize)]
pub struct LoginActivityPoint {
    pub date: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct TopOrganization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub user_count: i64,
    pub service_count: i64,
    pub login_count_30d: i64,
}

// ============================================================================
// Platform Analytics Endpoints
// ============================================================================

/// GET /api/platform/analytics/overview
/// Get high-level platform metrics
pub async fn get_platform_overview(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<PlatformOverviewMetrics>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Get total organizations using store
    let total_organizations = OrganizationStore::count_all(DB::Conn(&state.db)).await? as i64;

    // Get total platform admins (platform owners and org owners/admins) using store
    let total_users = UserStore::count_admin_users(DB::Conn(&state.db)).await?;

    // Get total end-users (regular users, non-admins) using store
    let total_end_users = UserStore::count_all(DB::Conn(&state.db), true).await? as i64;

    // Get total services using store
    let total_services = ServiceStore::count_all(DB::Conn(&state.db)).await? as i64;

    // Get logins in last 24 hours using store
    let since_24h = (Utc::now() - chrono::Duration::hours(24)).naive_utc();
    let total_logins_24h = LoginEventStore::count_since(DB::Conn(&state.db), since_24h).await?;

    // Get logins in last 30 days using store
    let since_30d = (Utc::now() - chrono::Duration::days(30)).naive_utc();
    let total_logins_30d = LoginEventStore::count_since(DB::Conn(&state.db), since_30d).await?;

    Ok(Json(PlatformOverviewMetrics {
        total_organizations,
        total_users,
        total_end_users,
        total_services,
        total_logins_24h,
        total_logins_30d,
    }))
}

/// GET /api/platform/analytics/organization-status
/// Get organization count breakdown by status
pub async fn get_organization_status_breakdown(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<OrganizationStatusBreakdown>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Use store methods to count by status
    let pending = OrganizationStore::count_by_status(DB::Conn(&state.db), "pending").await? as i64;
    let active = OrganizationStore::count_by_status(DB::Conn(&state.db), "active").await? as i64;
    let suspended =
        OrganizationStore::count_by_status(DB::Conn(&state.db), "suspended").await? as i64;
    let rejected =
        OrganizationStore::count_by_status(DB::Conn(&state.db), "rejected").await? as i64;

    Ok(Json(OrganizationStatusBreakdown {
        pending,
        active,
        suspended,
        rejected,
    }))
}

/// GET /api/platform/analytics/growth-trends
/// Get platform growth trends over time
pub async fn get_growth_trends(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<AnalyticsDateRangeQuery>,
) -> Result<Json<Vec<GrowthTrendPoint>>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive())
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let start_date = query
        .start_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| (Utc::now() - chrono::Duration::days(30)).date_naive())
        .and_hms_opt(0, 0, 0)
        .unwrap();

    // Get new organizations per day using store
    let org_trends =
        OrganizationStore::get_growth_trends(DB::Conn(&state.db), start_date, end_date).await?;

    // Get new users per day (non-platform-owners) using store
    let user_trends =
        UserStore::get_growth_trends(DB::Conn(&state.db), start_date, end_date, false).await?;

    // Merge the two trend lines
    let mut trends_map: std::collections::HashMap<String, GrowthTrendPoint> =
        std::collections::HashMap::new();

    for item in org_trends {
        trends_map
            .entry(item.date.to_string())
            .or_insert_with(|| GrowthTrendPoint {
                date: item.date.to_string(),
                new_organizations: 0,
                new_users: 0,
            })
            .new_organizations = item.count;
    }

    for item in user_trends {
        trends_map
            .entry(item.date.to_string())
            .or_insert_with(|| GrowthTrendPoint {
                date: item.date.to_string(),
                new_organizations: 0,
                new_users: 0,
            })
            .new_users = item.count;
    }

    let mut result: Vec<GrowthTrendPoint> = trends_map.into_values().collect();
    result.sort_by(|a, b| a.date.cmp(&b.date));

    Ok(Json(result))
}

/// GET /api/platform/analytics/login-activity
/// Get platform-wide login activity trends
pub async fn get_login_activity(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<AnalyticsDateRangeQuery>,
) -> Result<Json<Vec<LoginActivityPoint>>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| Utc::now().date_naive())
        .and_hms_opt(23, 59, 59)
        .unwrap();
    let start_date = query
        .start_date
        .and_then(|s| chrono::NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok())
        .unwrap_or_else(|| (Utc::now() - chrono::Duration::days(30)).date_naive())
        .and_hms_opt(0, 0, 0)
        .unwrap();

    // Get login activity per day using store
    let activity =
        LoginEventStore::get_platform_activity_trends(DB::Conn(&state.db), start_date, end_date)
            .await?;

    let result = activity
        .into_iter()
        .filter_map(|item| {
            // Skip entries with NULL dates
            item.date.map(|date| LoginActivityPoint {
                date,
                count: item.count,
            })
        })
        .collect();

    Ok(Json(result))
}

/// GET /api/platform/analytics/top-organizations
/// Get most active organizations by various metrics
pub async fn get_top_organizations(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<TopOrganization>>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Get top organizations using store
    let organizations = OrganizationStore::get_top_organizations(DB::Conn(&state.db), 10).await?;

    let result = organizations
        .into_iter()
        .map(|org| TopOrganization {
            id: org.id,
            name: org.name,
            slug: org.slug,
            user_count: org.user_count,
            service_count: org.service_count,
            login_count_30d: org.login_count_30d,
        })
        .collect();

    Ok(Json(result))
}
