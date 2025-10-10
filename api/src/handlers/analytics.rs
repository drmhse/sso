use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Clone)]
pub struct AnalyticsState {
    pub pool: SqlitePool,
}

#[derive(Debug, Deserialize)]
pub struct AnalyticsQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct LoginTrendPoint {
    pub date: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct LoginsByService {
    pub service_id: String,
    pub service_name: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct LoginsByProvider {
    pub provider: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct RecentLogin {
    pub id: String,
    pub user_id: String,
    pub service_id: String,
    pub provider: String,
    pub created_at: DateTime<Utc>,
}

/// GET /api/organizations/:org_slug/analytics/login-trends
pub async fn get_login_trends(
    State(state): State<AnalyticsState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<LoginTrendPoint>>> {
    // Verify user is a member of this organization
    verify_org_membership(&state.pool, &auth_user.claims.sub, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    let start_date = query.start_date.unwrap_or_else(|| {
        (Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string()
    });

    // Get organization ID
    let org_id = sqlx::query_scalar::<_, String>("SELECT id FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_one(&state.pool)
        .await?;

    // Query login trends grouped by date
    let trends = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT
            DATE(le.created_at) as date,
            COUNT(*) as count
        FROM login_events le
        JOIN services s ON le.service_id = s.id
        WHERE s.org_id = ?
          AND DATE(le.created_at) >= DATE(?)
          AND DATE(le.created_at) <= DATE(?)
        GROUP BY DATE(le.created_at)
        ORDER BY date ASC
        "#,
    )
    .bind(&org_id)
    .bind(&start_date)
    .bind(&end_date)
    .fetch_all(&state.pool)
    .await?;

    let result = trends
        .into_iter()
        .map(|(date, count)| LoginTrendPoint { date, count })
        .collect();

    Ok(Json(result))
}

/// GET /api/organizations/:org_slug/analytics/logins-by-service
pub async fn get_logins_by_service(
    State(state): State<AnalyticsState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<LoginsByService>>> {
    // Verify user is a member of this organization
    verify_org_membership(&state.pool, &auth_user.claims.sub, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    let start_date = query.start_date.unwrap_or_else(|| {
        (Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string()
    });

    // Get organization ID
    let org_id = sqlx::query_scalar::<_, String>("SELECT id FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_one(&state.pool)
        .await?;

    // Query logins grouped by service
    let logins = sqlx::query_as::<_, (String, String, i64)>(
        r#"
        SELECT
            s.id as service_id,
            s.name as service_name,
            COUNT(*) as count
        FROM login_events le
        JOIN services s ON le.service_id = s.id
        WHERE s.org_id = ?
          AND DATE(le.created_at) >= DATE(?)
          AND DATE(le.created_at) <= DATE(?)
        GROUP BY s.id, s.name
        ORDER BY count DESC
        "#,
    )
    .bind(&org_id)
    .bind(&start_date)
    .bind(&end_date)
    .fetch_all(&state.pool)
    .await?;

    let result = logins
        .into_iter()
        .map(|(service_id, service_name, count)| LoginsByService {
            service_id,
            service_name,
            count,
        })
        .collect();

    Ok(Json(result))
}

/// GET /api/organizations/:org_slug/analytics/logins-by-provider
pub async fn get_logins_by_provider(
    State(state): State<AnalyticsState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<LoginsByProvider>>> {
    // Verify user is a member of this organization
    verify_org_membership(&state.pool, &auth_user.claims.sub, &org_slug).await?;

    // Parse date range or use defaults (last 30 days)
    let end_date = query
        .end_date
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    let start_date = query.start_date.unwrap_or_else(|| {
        (Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string()
    });

    // Get organization ID
    let org_id = sqlx::query_scalar::<_, String>("SELECT id FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_one(&state.pool)
        .await?;

    // Query logins grouped by provider
    let logins = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT
            le.provider,
            COUNT(*) as count
        FROM login_events le
        JOIN services s ON le.service_id = s.id
        WHERE s.org_id = ?
          AND DATE(le.created_at) >= DATE(?)
          AND DATE(le.created_at) <= DATE(?)
        GROUP BY le.provider
        ORDER BY count DESC
        "#,
    )
    .bind(&org_id)
    .bind(&start_date)
    .bind(&end_date)
    .fetch_all(&state.pool)
    .await?;

    let result = logins
        .into_iter()
        .map(|(provider, count)| LoginsByProvider { provider, count })
        .collect();

    Ok(Json(result))
}

/// GET /api/organizations/:org_slug/analytics/recent-logins
pub async fn get_recent_logins(
    State(state): State<AnalyticsState>,
    Path(org_slug): Path<String>,
    Query(query): Query<AnalyticsQuery>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<RecentLogin>>> {
    // Verify user is a member of this organization
    verify_org_membership(&state.pool, &auth_user.claims.sub, &org_slug).await?;

    let limit = query.limit.unwrap_or(10);

    // Get organization ID
    let org_id = sqlx::query_scalar::<_, String>("SELECT id FROM organizations WHERE slug = ?")
        .bind(&org_slug)
        .fetch_one(&state.pool)
        .await?;

    // Query recent logins
    let logins = sqlx::query_as::<_, (String, String, String, String, DateTime<Utc>)>(
        r#"
        SELECT
            le.id,
            le.user_id,
            le.service_id,
            le.provider,
            le.created_at
        FROM login_events le
        JOIN services s ON le.service_id = s.id
        WHERE s.org_id = ?
        ORDER BY le.created_at DESC
        LIMIT ?
        "#,
    )
    .bind(&org_id)
    .bind(limit)
    .fetch_all(&state.pool)
    .await?;

    let result = logins
        .into_iter()
        .map(
            |(id, user_id, service_id, provider, created_at)| RecentLogin {
                id,
                user_id,
                service_id,
                provider,
                created_at,
            },
        )
        .collect();

    Ok(Json(result))
}

// Helper function to verify organization membership
async fn verify_org_membership(pool: &SqlitePool, user_id: &str, org_slug: &str) -> Result<()> {
    let membership_exists = sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1
            FROM memberships m
            JOIN organizations o ON m.org_id = o.id
            WHERE o.slug = ? AND m.user_id = ?
        )
        "#,
    )
    .bind(org_slug)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    if !membership_exists {
        return Err(AppError::Forbidden(
            "You are not a member of this organization".to_string(),
        ));
    }

    Ok(())
}
