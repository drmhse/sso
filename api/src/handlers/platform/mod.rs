pub mod analytics;
pub mod bootstrap;
pub mod governance;
pub mod impersonation;
pub mod operations;
pub mod users;

use crate::db::models::{Organization, PlatformAuditLog, User};
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::{organizations, platform_audit_log, users as users_entity};
use crate::error::Result;
use crate::store::{organizations::OrganizationStore, platform_audit_log::PlatformAuditLogStore};
use chrono::Utc;
use sea_orm::{ConnectionTrait, Set};
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
pub use bootstrap::{
    apply_managed_config, bootstrap_login, get_managed_config, update_managed_config,
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

// Model Conversion Helpers (Shared across sub-modules)

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

// Audit Log Helpers (Shared across sub-modules)

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

    crate::audit::actor::enqueue_platform_with_connection(db, new_log).await?;

    Ok(PlatformAuditLog {
        id,
        platform_owner_id: platform_owner_id.to_string(),
        action: action.to_string(),
        target_type: target_type.to_string(),
        target_id: target_id.to_string(),
        metadata: metadata_str,
        created_at: chrono::DateTime::from_naive_utc_and_offset(now, Utc),
    })
}

// Additional Platform Endpoints (not in the split categories)

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

fn redact_platform_audit_metadata(metadata: Option<String>) -> Option<String> {
    metadata.and_then(|metadata| {
        serde_json::from_str(&metadata)
            .ok()
            .map(crate::handlers::organization_audit::redact_audit_metadata)
            .map(|metadata| metadata.to_string())
    })
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

                // Delete organization (database cascades will handle related data)
                OrganizationStore::delete(db.clone(), &org_id).await?;

                // The platform event does not reference the deleted organization
                // through a foreign key, so enqueue it after the last fallible
                // domain operation while preserving the identity in its payload.
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

    let (limit, offset) =
        crate::utils::pagination::signed_limit_offset(query.limit, query.offset, 50, 100);

    let total = PlatformAuditLogStore::count_with_filters(
        DB::Conn(&state.db),
        query.action.as_deref(),
        query.target_type.as_deref(),
        query.target_id.as_deref(),
    )
    .await? as i64;

    // Get logs using store
    let (limit_u64, offset_u64) = crate::utils::pagination::store_u64(limit, offset, 100);
    let log_models = PlatformAuditLogStore::list_with_filters(
        DB::Conn(&state.db),
        query.action.as_deref(),
        query.target_type.as_deref(),
        query.target_id.as_deref(),
        limit_u64,
        offset_u64,
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
            metadata: redact_platform_audit_metadata(l.metadata),
            created_at: chrono::DateTime::from_naive_utc_and_offset(l.created_at, Utc),
        })
        .collect();

    Ok(Json(AuditLogResponse { logs, total }))
}

#[cfg(test)]
mod audit_redaction_tests {
    use super::redact_platform_audit_metadata;

    #[test]
    fn platform_audit_metadata_uses_recursive_credential_redaction() {
        let redacted = redact_platform_audit_metadata(Some(
            serde_json::json!({
                "target_id": "safe-id",
                "nested": [{"client_secret_value": "secret-canary"}]
            })
            .to_string(),
        ))
        .expect("valid metadata remains available");
        let parsed: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        assert_eq!(parsed["target_id"], "safe-id");
        assert_eq!(parsed["nested"][0]["client_secret_value"], "[REDACTED]");
        assert!(!redacted.contains("secret-canary"));
        assert!(redact_platform_audit_metadata(Some("not-json-secret".to_string())).is_none());
    }
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

    let (limit, _) = crate::utils::pagination::signed_limit_offset(query.limit, None, 10, 50);

    // Get recent organizations using store
    let (limit, _) = crate::utils::pagination::store_u64(limit, 0, 50);
    let orgs = OrganizationStore::list_recent(DB::Conn(&state.db), limit).await?;

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

// MFA Metrics and Analytics

#[derive(Debug, Deserialize)]
pub struct MfaMetricsQuery {
    /// Omit for the platform-wide rollup; supply an id for one organization.
    pub org_id: Option<String>,
    /// Inclusive `YYYY-MM-DD` range. Both bounds are required together and
    /// take precedence over `days`.
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub days: Option<i64>,
}

/// GET /api/platform/mfa/metrics - Get MFA usage metrics
pub async fn get_mfa_metrics(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Query(query): Query<MfaMetricsQuery>,
) -> Result<Json<Vec<crate::services::metrics::MfaMetricsSummary>>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let org_id = query.org_id.as_deref();

    let metrics = match (&query.start_date, &query.end_date) {
        (Some(start), Some(end)) => {
            let start = parse_metrics_date(start, "start_date")?;
            let end = parse_metrics_date(end, "end_date")?;
            if start > end {
                return Err(AppError::BadRequest(
                    "start_date must not be after end_date".to_string(),
                ));
            }
            state
                .metrics_service
                .get_mfa_metrics_in_range(org_id, start, end)
                .await?
        }
        (None, None) => {
            let days = query.days.unwrap_or(30);
            if !(1..=366).contains(&days) {
                return Err(AppError::BadRequest(
                    "days must be between 1 and 366".to_string(),
                ));
            }
            state
                .metrics_service
                .get_mfa_metrics(org_id, Some(days))
                .await?
        }
        _ => {
            return Err(AppError::BadRequest(
                "start_date and end_date must be supplied together".to_string(),
            ))
        }
    };

    Ok(Json(metrics))
}

fn parse_metrics_date(value: &str, field: &str) -> Result<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map_err(|_| AppError::BadRequest(format!("{field} must be YYYY-MM-DD")))
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
    let org_id = params.get("org_id").map(std::string::String::as_str);

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
    let org_id = params.get("org_id").map(std::string::String::as_str);

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
