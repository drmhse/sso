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
