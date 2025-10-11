use crate::db::models::{Organization, OrganizationTier, PlatformAuditLog, User};
use crate::error::{AppError, Result};
use crate::handlers::auth::AppState;
use crate::middleware::AuthUser;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Row, Sqlite};
use uuid::Uuid;

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct ListOrganizationsQuery {
    pub status: Option<String>,
    pub tier_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct OrganizationWithDetails {
    #[serde(flatten)]
    pub organization: Organization,
    pub tier: Option<OrganizationTier>,
    pub owner: User,
}

#[derive(Debug, Serialize)]
pub struct ListOrganizationsResponse {
    pub organizations: Vec<OrganizationWithDetails>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct ApproveOrganizationRequest {
    pub tier_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RejectOrganizationRequest {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTierRequest {
    pub tier_id: String,
    pub max_services: Option<i64>,
    pub max_users: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PromoteOwnerRequest {
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub logs: Vec<PlatformAuditLog>,
    pub total: i64,
}

// ============================================================================
// Audit Log Helpers
// ============================================================================

/// Create an audit log entry
pub async fn create_audit_log<'a, E>(
    executor: E,
    platform_owner_id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    metadata: Option<serde_json::Value>,
) -> Result<PlatformAuditLog>
where
    E: sqlx::Executor<'a, Database = Sqlite>,
{
    let id = Uuid::new_v4().to_string();
    let metadata_str = metadata.map(|m| m.to_string());

    let log = sqlx::query_as::<_, PlatformAuditLog>(
        r#"
        INSERT INTO platform_audit_log (id, platform_owner_id, action, target_type, target_id, metadata)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING *
        "#,
    )
    .bind(&id)
    .bind(platform_owner_id)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(metadata_str)
    .fetch_one(executor)
    .await
    .map_err(AppError::Database)?;

    Ok(log)
}

// ============================================================================
// Platform Governance Endpoints
// ============================================================================

/// GET /api/platform/tiers
/// List all available organization tiers
pub async fn list_tiers(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<OrganizationTier>>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let tiers = sqlx::query_as::<_, OrganizationTier>(
        "SELECT * FROM organization_tiers ORDER BY price_cents ASC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(tiers))
}

/// GET /api/platform/organizations
/// List organizations with optional filters
pub async fn list_organizations(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<ListOrganizationsQuery>,
) -> Result<Json<ListOrganizationsResponse>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    // Build dynamic query based on filters
    let mut conditions = vec![];
    let mut bind_values: Vec<String> = vec![];

    if let Some(status) = &query.status {
        conditions.push("o.status = ?");
        bind_values.push(status.clone());
    }
    if let Some(tier_id) = &query.tier_id {
        conditions.push("o.tier_id = ?");
        bind_values.push(tier_id.clone());
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    // Get total count
    let count_query = format!(
        "SELECT COUNT(*) as count FROM organizations o {}",
        where_clause
    );
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_query);
    for value in &bind_values {
        count_q = count_q.bind(value);
    }
    let total = count_q
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Database)?;

    // Get organizations with owner info
    let list_query = format!(
        r#"
        SELECT
            o.id, o.slug, o.name, o.owner_user_id, o.status, o.tier_id,
            o.max_services, o.max_users, o.approved_by, o.approved_at,
            o.rejected_by, o.rejected_at, o.rejection_reason,
            o.created_at, o.updated_at,
            u.id as owner_id, u.email as owner_email,
            u.is_platform_owner as owner_is_platform_owner, u.created_at as owner_created_at
        FROM organizations o
        INNER JOIN users u ON o.owner_user_id = u.id
        {}
        ORDER BY o.created_at DESC
        LIMIT ? OFFSET ?
        "#,
        where_clause
    );

    let mut list_q = sqlx::query(&list_query);
    for value in &bind_values {
        list_q = list_q.bind(value);
    }
    list_q = list_q.bind(limit).bind(offset);

    let rows = list_q
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Database)?;

    let mut organizations = Vec::new();

    for row in rows {
        let org = Organization {
            id: row.get("id"),
            slug: row.get("slug"),
            name: row.get("name"),
            owner_user_id: row.get("owner_user_id"),
            status: row.get("status"),
            tier_id: row.get("tier_id"),
            max_services: row.get("max_services"),
            max_users: row.get("max_users"),
            approved_by: row.get("approved_by"),
            approved_at: row.get("approved_at"),
            rejected_by: row.get("rejected_by"),
            rejected_at: row.get("rejected_at"),
            rejection_reason: row.get("rejection_reason"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        };

        let owner = User {
            id: row.get("owner_id"),
            email: row.get("owner_email"),
            is_platform_owner: row.get("owner_is_platform_owner"),
            created_at: row.get("owner_created_at"),
        };

        // Fetch tier if present
        let tier = if let Some(tier_id) = &org.tier_id {
            sqlx::query_as::<_, OrganizationTier>("SELECT * FROM organization_tiers WHERE id = ?")
                .bind(tier_id)
                .fetch_optional(&state.pool)
                .await
                .map_err(AppError::Database)?
        } else {
            None
        };

        organizations.push(OrganizationWithDetails {
            organization: org,
            tier,
            owner,
        });
    }

    Ok(Json(ListOrganizationsResponse {
        organizations,
        total,
    }))
}

/// POST /api/platform/organizations/:id/approve
/// Approve a pending organization
pub async fn approve_organization(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
    Json(req): Json<ApproveOrganizationRequest>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Fetch current organization
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
        .bind(&org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if org.status != "pending" {
        return Err(AppError::BadRequest(
            "Organization is not in pending status".to_string(),
        ));
    }

    // Use provided tier_id or default to 'tier_free'
    let tier_id = req.tier_id.as_deref().unwrap_or("tier_free");

    // Verify tier exists
    sqlx::query("SELECT id FROM organization_tiers WHERE id = ?")
        .bind(tier_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization tier not found".to_string()))?;

    // Log organization approval
    tracing::info!(
        org_id = %org_id,
        platform_owner = %auth_user.user.id,
        tier_id = %tier_id,
        "Approving organization"
    );

    // Update organization
    let updated_org = sqlx::query_as::<_, Organization>(
        r#"
        UPDATE organizations
        SET status = 'active',
            tier_id = ?,
            approved_by = ?,
            approved_at = ?,
            updated_at = ?
        WHERE id = ?
        RETURNING *
        "#,
    )
    .bind(tier_id)
    .bind(&auth_user.user.id)
    .bind(Utc::now())
    .bind(Utc::now())
    .bind(&org_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Create audit log
    create_audit_log(
        &mut *tx,
        &auth_user.user.id,
        "approve_organization",
        "organization",
        &org_id,
        Some(json!({
            "old_status": org.status,
            "new_status": "active",
            "tier_id": tier_id,
        })),
    )
    .await?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(updated_org))
}

/// POST /api/platform/organizations/:id/reject
/// Reject a pending organization
pub async fn reject_organization(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
    Json(req): Json<RejectOrganizationRequest>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Fetch current organization
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
        .bind(&org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if org.status != "pending" {
        return Err(AppError::BadRequest(
            "Organization is not in pending status".to_string(),
        ));
    }

    // Update organization
    let updated_org = sqlx::query_as::<_, Organization>(
        r#"
        UPDATE organizations
        SET status = 'rejected',
            rejected_by = ?,
            rejected_at = ?,
            rejection_reason = ?,
            updated_at = ?
        WHERE id = ?
        RETURNING *
        "#,
    )
    .bind(&auth_user.user.id)
    .bind(Utc::now())
    .bind(&req.reason)
    .bind(Utc::now())
    .bind(&org_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Create audit log
    create_audit_log(
        &mut *tx,
        &auth_user.user.id,
        "reject_organization",
        "organization",
        &org_id,
        Some(json!({
            "old_status": org.status,
            "new_status": "rejected",
            "reason": req.reason,
        })),
    )
    .await?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(updated_org))
}

/// POST /api/platform/organizations/:id/suspend
/// Suspend an active organization
pub async fn suspend_organization(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Fetch current organization
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
        .bind(&org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if org.status == "suspended" {
        return Err(AppError::BadRequest(
            "Organization is already suspended".to_string(),
        ));
    }

    // Update organization
    let updated_org = sqlx::query_as::<_, Organization>(
        r#"
        UPDATE organizations
        SET status = 'suspended',
            updated_at = ?
        WHERE id = ?
        RETURNING *
        "#,
    )
    .bind(Utc::now())
    .bind(&org_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Create audit log
    create_audit_log(
        &mut *tx,
        &auth_user.user.id,
        "suspend_organization",
        "organization",
        &org_id,
        Some(json!({
            "old_status": org.status,
            "new_status": "suspended",
        })),
    )
    .await?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(updated_org))
}

/// POST /api/platform/organizations/:id/activate
/// Reactivate a suspended organization
pub async fn activate_organization(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Fetch current organization
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
        .bind(&org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if org.status != "suspended" {
        return Err(AppError::BadRequest(
            "Organization is not suspended".to_string(),
        ));
    }

    // Update organization
    let updated_org = sqlx::query_as::<_, Organization>(
        r#"
        UPDATE organizations
        SET status = 'active',
            updated_at = ?
        WHERE id = ?
        RETURNING *
        "#,
    )
    .bind(Utc::now())
    .bind(&org_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Create audit log
    create_audit_log(
        &mut *tx,
        &auth_user.user.id,
        "activate_organization",
        "organization",
        &org_id,
        Some(json!({
            "old_status": org.status,
            "new_status": "active",
        })),
    )
    .await?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(updated_org))
}

/// PATCH /api/platform/organizations/:id/tier
/// Update organization tier and limits
pub async fn update_organization_tier(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
    Json(req): Json<UpdateTierRequest>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Fetch current organization
    let org = sqlx::query_as::<_, Organization>("SELECT * FROM organizations WHERE id = ?")
        .bind(&org_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Verify tier exists
    sqlx::query("SELECT id FROM organization_tiers WHERE id = ?")
        .bind(&req.tier_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("Organization tier not found".to_string()))?;

    // Update organization
    let updated_org = sqlx::query_as::<_, Organization>(
        r#"
        UPDATE organizations
        SET tier_id = ?,
            max_services = ?,
            max_users = ?,
            updated_at = ?
        WHERE id = ?
        RETURNING *
        "#,
    )
    .bind(&req.tier_id)
    .bind(req.max_services)
    .bind(req.max_users)
    .bind(Utc::now())
    .bind(&org_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Create audit log
    create_audit_log(
        &mut *tx,
        &auth_user.user.id,
        "update_organization_tier",
        "organization",
        &org_id,
        Some(json!({
            "old_tier_id": org.tier_id,
            "new_tier_id": req.tier_id,
            "max_services": req.max_services,
            "max_users": req.max_users,
        })),
    )
    .await?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(updated_org))
}

/// POST /api/platform/owners
/// Promote a user to platform owner
pub async fn promote_platform_owner(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<PromoteOwnerRequest>,
) -> Result<Json<User>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Fetch user
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&req.user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if user.is_platform_owner {
        return Err(AppError::BadRequest(
            "User is already a platform owner".to_string(),
        ));
    }

    // Update user
    let updated_user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET is_platform_owner = 1
        WHERE id = ?
        RETURNING *
        "#,
    )
    .bind(&req.user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Create audit log
    create_audit_log(
        &mut *tx,
        &auth_user.user.id,
        "promote_platform_owner",
        "user",
        &req.user_id,
        Some(json!({
            "user_email": updated_user.email,
        })),
    )
    .await?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(updated_user))
}

/// DELETE /api/platform/owners/:user_id
/// Demote a platform owner to regular user
pub async fn demote_platform_owner(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<User>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Prevent self-demotion
    if auth_user.user.id == user_id {
        return Err(AppError::BadRequest(
            "Cannot demote yourself".to_string(),
        ));
    }

    let mut tx = state.pool.begin().await.map_err(AppError::Database)?;

    // Fetch user to demote
    let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?")
        .bind(&user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AppError::Database)?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    if !user.is_platform_owner {
        return Err(AppError::BadRequest(
            "User is not a platform owner".to_string(),
        ));
    }

    // Check if this is the last platform owner
    let owner_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE is_platform_owner = 1")
        .fetch_one(&mut *tx)
        .await
        .map_err(AppError::Database)?;

    if owner_count <= 1 {
        return Err(AppError::BadRequest(
            "Cannot demote the last platform owner".to_string(),
        ));
    }

    // Update user
    let updated_user = sqlx::query_as::<_, User>(
        r#"
        UPDATE users
        SET is_platform_owner = 0
        WHERE id = ?
        RETURNING *
        "#,
    )
    .bind(&user_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppError::Database)?;

    // Create audit log
    create_audit_log(
        &mut *tx,
        &auth_user.user.id,
        "demote_platform_owner",
        "user",
        &user_id,
        Some(json!({
            "user_email": updated_user.email,
        })),
    )
    .await?;

    tx.commit().await.map_err(AppError::Database)?;

    Ok(Json(updated_user))
}

/// GET /api/platform/audit-log
/// Get platform audit logs with optional filters
pub async fn get_audit_log(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    // Build dynamic query based on filters
    let mut conditions = vec![];
    let mut bind_values: Vec<String> = vec![];

    if let Some(action) = &query.action {
        conditions.push("action = ?");
        bind_values.push(action.clone());
    }
    if let Some(target_type) = &query.target_type {
        conditions.push("target_type = ?");
        bind_values.push(target_type.clone());
    }
    if let Some(target_id) = &query.target_id {
        conditions.push("target_id = ?");
        bind_values.push(target_id.clone());
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    // Get total count
    let count_query = format!(
        "SELECT COUNT(*) as count FROM platform_audit_log {}",
        where_clause
    );
    let mut count_q = sqlx::query_scalar::<_, i64>(&count_query);
    for value in &bind_values {
        count_q = count_q.bind(value);
    }
    let total = count_q
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Database)?;

    // Get logs
    let list_query = format!(
        "SELECT * FROM platform_audit_log {} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        where_clause
    );
    let mut list_q = sqlx::query_as::<_, PlatformAuditLog>(&list_query);
    for value in &bind_values {
        list_q = list_q.bind(value);
    }
    list_q = list_q.bind(limit).bind(offset);

    let logs = list_q
        .fetch_all(&state.pool)
        .await
        .map_err(AppError::Database)?;

    Ok(Json(AuditLogResponse { logs, total }))
}

// ============================================================================
// Platform Analytics Endpoints
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

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RecentOrganization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub status: String,
    pub created_at: chrono::DateTime<Utc>,
}

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

    // Get total organizations
    let total_organizations: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM organizations")
            .fetch_one(&state.pool)
            .await
            .map_err(AppError::Database)?;

    // Get total platform admins (platform owners and org owners/admins)
    let total_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT u.id) FROM users u
         LEFT JOIN memberships m ON u.id = m.user_id
         WHERE u.is_platform_owner = 1 OR m.role IN ('owner', 'admin')"
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    // Get total end-users (regular users, non-admins)
    let total_end_users: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM users WHERE is_platform_owner = 0"
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    // Get total services
    let total_services: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM services")
        .fetch_one(&state.pool)
        .await
        .map_err(AppError::Database)?;

    // Get logins in last 24 hours
    let total_logins_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM login_events WHERE created_at >= datetime('now', '-1 day')",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    // Get logins in last 30 days
    let total_logins_30d: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM login_events WHERE created_at >= datetime('now', '-30 days')",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

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

    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organizations WHERE status = 'pending'",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let active: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organizations WHERE status = 'active'",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let suspended: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organizations WHERE status = 'suspended'",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let rejected: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM organizations WHERE status = 'rejected'",
    )
    .fetch_one(&state.pool)
    .await
    .map_err(AppError::Database)?;

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
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    let start_date = query.start_date.unwrap_or_else(|| {
        (Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string()
    });

    // Get new organizations per day
    let org_trends = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT
            DATE(created_at) as date,
            COUNT(*) as count
        FROM organizations
        WHERE DATE(created_at) >= DATE(?)
          AND DATE(created_at) <= DATE(?)
        GROUP BY DATE(created_at)
        ORDER BY date ASC
        "#,
    )
    .bind(&start_date)
    .bind(&end_date)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    // Get new users per day (non-platform-owners)
    let user_trends = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT
            DATE(created_at) as date,
            COUNT(*) as count
        FROM users
        WHERE is_platform_owner = 0
          AND DATE(created_at) >= DATE(?)
          AND DATE(created_at) <= DATE(?)
        GROUP BY DATE(created_at)
        ORDER BY date ASC
        "#,
    )
    .bind(&start_date)
    .bind(&end_date)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    // Merge the two trend lines
    let mut trends_map: std::collections::HashMap<String, GrowthTrendPoint> =
        std::collections::HashMap::new();

    for (date, count) in org_trends {
        trends_map
            .entry(date.clone())
            .or_insert_with(|| GrowthTrendPoint {
                date,
                new_organizations: 0,
                new_users: 0,
            })
            .new_organizations = count;
    }

    for (date, count) in user_trends {
        trends_map
            .entry(date.clone())
            .or_insert_with(|| GrowthTrendPoint {
                date,
                new_organizations: 0,
                new_users: 0,
            })
            .new_users = count;
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
        .unwrap_or_else(|| Utc::now().format("%Y-%m-%d").to_string());
    let start_date = query.start_date.unwrap_or_else(|| {
        (Utc::now() - chrono::Duration::days(30))
            .format("%Y-%m-%d")
            .to_string()
    });

    // Get login activity per day
    let activity = sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT
            DATE(created_at) as date,
            COUNT(*) as count
        FROM login_events
        WHERE DATE(created_at) >= DATE(?)
          AND DATE(created_at) <= DATE(?)
        GROUP BY DATE(created_at)
        ORDER BY date ASC
        "#,
    )
    .bind(&start_date)
    .bind(&end_date)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let result = activity
        .into_iter()
        .map(|(date, count)| LoginActivityPoint { date, count })
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

    let organizations = sqlx::query_as::<_, (String, String, String, i64, i64, i64)>(
        r#"
        SELECT
            o.id,
            o.name,
            o.slug,
            COALESCE((
                SELECT COUNT(DISTINCT le.user_id)
                FROM login_events le
                JOIN services s ON le.service_id = s.id
                WHERE s.org_id = o.id
            ), 0) as user_count,
            COALESCE((SELECT COUNT(*) FROM services WHERE org_id = o.id), 0) as service_count,
            COALESCE((
                SELECT COUNT(*)
                FROM login_events le
                JOIN services s ON le.service_id = s.id
                WHERE s.org_id = o.id
                  AND le.created_at >= datetime('now', '-30 days')
            ), 0) as login_count_30d
        FROM organizations o
        WHERE o.status = 'active'
        ORDER BY login_count_30d DESC, user_count DESC
        LIMIT 10
        "#,
    )
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    let result = organizations
        .into_iter()
        .map(|(id, name, slug, user_count, service_count, login_count_30d)| TopOrganization {
            id,
            name,
            slug,
            user_count,
            service_count,
            login_count_30d,
        })
        .collect();

    Ok(Json(result))
}

/// GET /api/platform/analytics/recent-organizations
/// Get recently created organizations
pub async fn get_recent_organizations(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<Vec<RecentOrganization>>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let limit = query.limit.unwrap_or(10).min(50);

    let organizations = sqlx::query_as::<_, RecentOrganization>(
        r#"
        SELECT id, name, slug, status, created_at
        FROM organizations
        ORDER BY created_at DESC
        LIMIT ?
        "#,
    )
    .bind(limit)
    .fetch_all(&state.pool)
    .await
    .map_err(AppError::Database)?;

    Ok(Json(organizations))
}
