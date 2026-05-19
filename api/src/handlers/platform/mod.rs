#![allow(dead_code)]

// Platform module - handles all platform governance, analytics, and user management endpoints
// This module is organized into logical sub-modules:
// - governance: Organization approval, tier management, and lifecycle operations
// - analytics: Platform-wide metrics, growth trends, and reporting
// - users: User search, platform owner management, and MFA administration

pub mod analytics;
pub mod governance;
pub mod impersonation;
pub mod operations;
pub mod users;

use crate::db::models::{Organization, PlatformAuditLog, User};
use crate::entities::{organizations, platform_audit_log, users as users_entity};
use crate::error::{with_retrying_transaction, Result};
use crate::store::{
    organizations::OrganizationStore, platform_audit_log::PlatformAuditLogStore, DB,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ConnectionTrait, Set};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// Re-export all public handlers from sub-modules

// Governance handlers
pub use governance::{
    activate_organization, approve_organization, list_organizations, list_tiers,
    reject_organization, suspend_organization, update_organization_features,
    update_organization_tier,
};

// Analytics handlers
pub use analytics::{
    get_growth_trends, get_login_activity, get_organization_status_breakdown,
    get_platform_overview, get_top_organizations,
};

// User management handlers
pub use users::{
    demote_platform_owner, force_disable_user_mfa, get_platform_user, get_user_mfa_status,
    list_users, promote_platform_owner, search_users,
};

// Impersonation handlers
pub use impersonation::impersonate_user;
pub use operations::get_operations_status;

// Additional handlers that weren't in the split (kept in this module)
use crate::error::AppError;
use crate::middleware::AuthUser;
use crate::state::AppState;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};

// ============================================================================
// Model Conversion Helpers (Shared across sub-modules)
// ============================================================================

/// Convert organizations::Model to Organization
pub(crate) fn org_model_to_old(model: organizations::Model) -> Organization {
    Organization {
        id: model.id,
        slug: model.slug,
        name: model.name,
        owner_user_id: model.owner_user_id,
        status: model.status,
        tier_id: model.tier_id,
        max_services: model.max_services.map(|v| v as i64),
        max_users: model.max_users.map(|v| v as i64),
        approved_by: model.approved_by,
        approved_at: model
            .approved_at
            .map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, Utc)),
        rejected_by: model.rejected_by,
        rejected_at: model
            .rejected_at
            .map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, Utc)),
        rejection_reason: model.rejection_reason,
        custom_domain: model.custom_domain,
        domain_verified: model.domain_verified,
        domain_verification_token: model.domain_verification_token,
        brand_logo_url: model.brand_logo_url,
        brand_primary_color: model.brand_primary_color,
        feature_overrides: model.feature_overrides,
        created_at: chrono::DateTime::from_naive_utc_and_offset(model.created_at, Utc),
        updated_at: chrono::DateTime::from_naive_utc_and_offset(model.updated_at, Utc),
    }
}

/// Convert users::Model to User
pub(crate) fn user_model_to_old(model: users_entity::Model) -> User {
    User {
        id: model.id,
        email: model.email,
        is_platform_owner: model.is_platform_owner,
        password_hash: model.password_hash,
        email_verified_at: model
            .email_verified_at
            .map(|dt| chrono::DateTime::from_naive_utc_and_offset(dt, Utc)),
        created_at: chrono::DateTime::from_naive_utc_and_offset(model.created_at, Utc),
    }
}

// ============================================================================
// Audit Log Helpers (Shared across sub-modules)
// ============================================================================

/// Create an audit log entry
pub(crate) async fn create_audit_log<C>(
    db: &C,
    platform_owner_id: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    metadata: Option<serde_json::Value>,
) -> Result<PlatformAuditLog>
where
    C: ConnectionTrait,
{
    let id = Uuid::new_v4().to_string();
    let metadata_str = metadata.map(|m| m.to_string());
    let now = Utc::now().naive_utc();

    let new_log = platform_audit_log::ActiveModel {
        id: Set(id.clone()),
        platform_owner_id: Set(platform_owner_id.to_string()),
        action: Set(action.to_string()),
        target_type: Set(target_type.to_string()),
        target_id: Set(target_id.to_string()),
        metadata: Set(metadata_str.clone()),
        created_at: Set(now),
    };

    let log_model = new_log.insert(db).await?;

    // Convert to old model format
    Ok(PlatformAuditLog {
        id: log_model.id,
        platform_owner_id: log_model.platform_owner_id,
        action: log_model.action,
        target_type: log_model.target_type,
        target_id: log_model.target_id,
        metadata: log_model.metadata,
        created_at: chrono::DateTime::from_naive_utc_and_offset(log_model.created_at, Utc),
    })
}

// ============================================================================
// Additional Platform Endpoints (not in the split categories)
// ============================================================================

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

#[derive(Debug, Serialize)]
pub struct RecentOrganization {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub status: String,
    pub created_at: String,
}

/// DELETE /api/platform/organizations/:id
/// Delete an organization (Platform Owner only)
pub async fn delete_organization_platform(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    use serde_json::json;

    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_organization",
        |db| {
            let org_id = org_id.clone();
            let auth_user_id = auth_user.user.id.clone();

            Box::pin(async move {
                // Fetch organization
                let org_model = OrganizationStore::find_by_id(db.clone(), &org_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let org_slug = org_model.slug.clone();
                let org_name = org_model.name.clone();

                // Create audit log before deletion
                create_audit_log(
                    &db,
                    &auth_user_id,
                    "delete_organization",
                    "organization",
                    &org_id,
                    Some(json!({
                        "org_slug": org_slug,
                        "org_name": org_name,
                        "status": org_model.status,
                    })),
                )
                .await?;

                // Delete organization (database cascades will handle related data)
                OrganizationStore::delete(db.clone(), &org_id).await?;

                Ok(())
            })
        },
    )
    .await?;

    Ok(Json(json!({
        "success": true,
        "message": "Organization deleted successfully"
    })))
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

    // Get total count using store
    let total = PlatformAuditLogStore::count_with_filters(
        DB::Conn(&state.db),
        query.action.as_deref(),
        query.target_type.as_deref(),
        query.target_id.as_deref(),
    )
    .await? as i64;

    // Get logs using store
    let log_models = PlatformAuditLogStore::list_with_filters(
        DB::Conn(&state.db),
        query.action.as_deref(),
        query.target_type.as_deref(),
        query.target_id.as_deref(),
        limit as u64,
        offset as u64,
    )
    .await?;

    // Convert to old model format
    let logs = log_models
        .into_iter()
        .map(|l| PlatformAuditLog {
            id: l.id,
            platform_owner_id: l.platform_owner_id,
            action: l.action,
            target_type: l.target_type,
            target_id: l.target_id,
            metadata: l.metadata,
            created_at: chrono::DateTime::from_naive_utc_and_offset(l.created_at, Utc),
        })
        .collect();

    Ok(Json(AuditLogResponse { logs, total }))
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

    // Get recent organizations using store
    let orgs = OrganizationStore::list_recent(DB::Conn(&state.db), limit as u64).await?;

    let organizations = orgs
        .into_iter()
        .map(|o| RecentOrganization {
            id: o.id,
            name: o.name,
            slug: o.slug,
            status: o.status,
            created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(o.created_at, Utc)
                .to_rfc3339(),
        })
        .collect();

    Ok(Json(organizations))
}

// ============================================================================
// MFA Metrics and Analytics
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct MfaMetricsQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub days: Option<i64>,
}

/// GET /api/platform/mfa/metrics - Get MFA usage metrics
pub async fn get_mfa_metrics(
    State(_state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Query(query): Query<MfaMetricsQuery>,
) -> Result<Json<serde_json::Value>> {
    use serde_json::json;

    // Only platform owners can access metrics
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Platform owners need to specify an org_id to get detailed metrics
    // For now, return aggregate summary
    let days = query.days.unwrap_or(30);

    // Return empty metrics structure since platform-level metrics require org_id
    let metrics = json!({
        "message": "Platform MFA metrics",
        "note": "Use /api/platform/mfa/metrics?org_id=:id for organization-specific metrics",
        "period_days": days
    });

    Ok(Json(metrics))
}

/// GET /api/platform/mfa/suspicious-activity - Get suspicious MFA activity alerts
pub async fn get_suspicious_activity(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<Vec<crate::services::metrics::SuspiciousActivityAlert>>> {
    // Only platform owners can access security alerts
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // org_id is optional - if not provided, returns all suspicious activity
    let org_id = params.get("org_id").map(|s| s.as_str());

    let alerts = state
        .metrics_service
        .get_suspicious_activity(org_id, Some(100))
        .await?;

    Ok(Json(alerts))
}

/// GET /api/platform/mfa/metrics/generate - Generate daily metrics for a specific date
#[axum::debug_handler]
pub async fn generate_daily_metrics(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<Json<crate::entities::mfa_daily_metrics::Model>> {
    // Only platform owners can generate metrics
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // org_id is optional - if not provided, generates platform-wide metrics
    let org_id = params.get("org_id").map(|s| s.as_str());

    let date_str = params
        .get("date")
        .cloned()
        .unwrap_or_else(|| chrono::Utc::now().date_naive().to_string());

    let date = chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
        .map_err(|_| AppError::BadRequest("Invalid date format. Use YYYY-MM-DD".to_string()))?;

    let metrics = state
        .metrics_service
        .generate_daily_metrics(org_id, date)
        .await?;

    Ok(Json(metrics))
}
