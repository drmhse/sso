use crate::error::AppError;
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{
    login_events::{
        LoginEventStore, LoginTrendPoint, LoginsByProvider, LoginsByService, RecentLogin,
    },
    memberships::MembershipStore,
    organizations::OrganizationStore,
    DB,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::Utc;
use sea_orm::DatabaseConnection;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i64>,
}

/// GET /api/organizations/:org_slug/analytics/login-trends
pub async fn get_login_trends(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginTrendPoint>>, AppError> {
    // Verify user is a member of this organization
    verify_org_membership(&state.db, &auth_user.claims.sub, &org_slug).await?;

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

    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Query login trends using store
    let trends = LoginEventStore::get_login_trends(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(trends))
}

/// GET /api/organizations/:org_slug/analytics/logins-by-service
pub async fn get_logins_by_service(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginsByService>>, AppError> {
    // Verify user is a member of this organization
    verify_org_membership(&state.db, &auth_user.claims.sub, &org_slug).await?;

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

    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Query logins using store
    let logins = LoginEventStore::get_logins_by_service(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(logins))
}

/// GET /api/organizations/:org_slug/analytics/logins-by-provider
pub async fn get_logins_by_provider(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<LoginsByProvider>>, AppError> {
    // Verify user is a member of this organization
    verify_org_membership(&state.db, &auth_user.claims.sub, &org_slug).await?;

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

    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Query logins using store
    let logins = LoginEventStore::get_logins_by_provider(
        DB::Conn(&state.db),
        &organization.id,
        start_date,
        end_date,
    )
    .await?;

    Ok(Json(logins))
}

/// GET /api/organizations/:org_slug/analytics/recent-logins
pub async fn get_recent_logins(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    auth_user: AuthUser,
) -> std::result::Result<Json<Vec<RecentLogin>>, AppError> {
    // Verify user is a member of this organization
    verify_org_membership(&state.db, &auth_user.claims.sub, &org_slug).await?;

    let limit = query.limit.unwrap_or(10);

    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Query recent logins using store
    let logins =
        LoginEventStore::get_recent_logins(DB::Conn(&state.db), &organization.id, limit).await?;

    Ok(Json(logins))
}

// Helper function to verify organization membership
async fn verify_org_membership(
    pool: &DatabaseConnection,
    user_id: &str,
    org_slug: &str,
) -> std::result::Result<(), AppError> {
    let membership =
        MembershipStore::find_by_org_slug_and_user(DB::Conn(pool), org_slug, user_id).await?;

    if membership.is_none() {
        return Err(AppError::Forbidden(
            "You are not a member of this organization".to_string(),
        ));
    }

    Ok(())
}
