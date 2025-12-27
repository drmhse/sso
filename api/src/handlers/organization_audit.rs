//! Audit log endpoints for organizations

use crate::db::models::OrganizationAuditLogWithUser;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit::OrganizationAuditService;
use crate::state::AppState;
use crate::store::{organizations::OrganizationStore, DB};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuditLogEntry {
    pub id: String,
    #[serde(rename = "organization_id")]
    pub org_id: String,
    #[serde(rename = "actor_id")]
    pub actor_user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorInfo>,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ActorInfo {
    pub id: String,
    pub email: String,
}

impl From<OrganizationAuditLogWithUser> for AuditLogEntry {
    fn from(log: OrganizationAuditLogWithUser) -> Self {
        let actor = log.actor_user_email.as_ref().map(|email| ActorInfo {
            id: log.actor_user_id.clone(),
            email: email.clone(),
        });

        let metadata = log
            .details
            .as_ref()
            .and_then(|d| serde_json::from_str(d).ok());

        Self {
            id: log.id,
            org_id: log.org_id,
            actor_user_id: log.actor_user_id,
            actor,
            action: log.action,
            target_type: log.target_type,
            target_id: log.target_id,
            ip_address: log.ip_address,
            user_agent: log.user_agent,
            success: log.success,
            metadata,
            created_at: log.created_at.to_rfc3339(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AuditLogResponse {
    pub logs: Vec<AuditLogEntry>,
    pub pagination: PaginationInfo,
}

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub page: i64,
    pub limit: i64,
    pub total: i64,
    pub total_pages: i64,
    pub has_next: bool,
    pub has_prev: bool,
}

/// Get audit logs for an organization (owner/admin only)
pub async fn get_organization_audit_logs(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogResponse>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Check if user is admin or owner
    crate::middleware::check_org_admin(&state.db, &auth_user.user.id, &organization.id).await?;

    // Set default pagination values
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).min(100); // Max 100 items per page
    let offset = (page - 1) * limit;

    let audit_service = OrganizationAuditService::new(state.db.clone());

    // Get audit logs with optional filtering
    let logs = if let Some(ref action) = query.action {
        audit_service
            .get_audit_logs_by_action(&organization.id, action, limit, offset)
            .await?
    } else if let (Some(target_type), Some(target_id)) =
        (query.target_type.as_ref(), query.target_id.as_ref())
    {
        audit_service
            .get_target_audit_logs(&organization.id, target_type, target_id, limit)
            .await?
    } else {
        audit_service
            .get_organization_audit_logs(&organization.id, limit, offset)
            .await?
    };

    // Get total count for pagination
    let total = audit_service.get_audit_log_count(&organization.id).await?;
    let total_pages = (total + limit - 1) / limit; // Ceiling division

    let pagination = PaginationInfo {
        page,
        limit,
        total,
        total_pages,
        has_next: page < total_pages,
        has_prev: page > 1,
    };

    let log_entries: Vec<AuditLogEntry> = logs.into_iter().map(|l| l.into()).collect();
    Ok(Json(AuditLogResponse {
        logs: log_entries,
        pagination,
    }))
}

/// Get available audit event types for filtering
pub async fn get_audit_event_types(
    State(_state): State<AppState>,
    _auth_user: AuthUser,
    Path(_org_slug): Path<String>,
) -> Result<Json<Vec<EventTypeInfo>>> {
    let event_types = vec![
        EventTypeInfo {
            value: "user.invited".to_string(),
            label: "User Invited".to_string(),
            category: "User Management".to_string(),
        },
        EventTypeInfo {
            value: "user.joined".to_string(),
            label: "User Joined".to_string(),
            category: "User Management".to_string(),
        },
        EventTypeInfo {
            value: "user.removed".to_string(),
            label: "User Removed".to_string(),
            category: "User Management".to_string(),
        },
        EventTypeInfo {
            value: "user.role_updated".to_string(),
            label: "User Role Updated".to_string(),
            category: "User Management".to_string(),
        },
        EventTypeInfo {
            value: "service.created".to_string(),
            label: "Service Created".to_string(),
            category: "Service Management".to_string(),
        },
        EventTypeInfo {
            value: "service.updated".to_string(),
            label: "Service Updated".to_string(),
            category: "Service Management".to_string(),
        },
        EventTypeInfo {
            value: "service.deleted".to_string(),
            label: "Service Deleted".to_string(),
            category: "Service Management".to_string(),
        },
        EventTypeInfo {
            value: "service.oauth_credentials.updated".to_string(),
            label: "Service OAuth Credentials Updated".to_string(),
            category: "Service Management".to_string(),
        },
        EventTypeInfo {
            value: "organization.updated".to_string(),
            label: "Organization Updated".to_string(),
            category: "Organization Management".to_string(),
        },
        EventTypeInfo {
            value: "organization.smtp.configured".to_string(),
            label: "Organization SMTP Configured".to_string(),
            category: "Organization Management".to_string(),
        },
        EventTypeInfo {
            value: "organization.smtp.removed".to_string(),
            label: "Organization SMTP Removed".to_string(),
            category: "Organization Management".to_string(),
        },
        EventTypeInfo {
            value: "plan.created".to_string(),
            label: "Plan Created".to_string(),
            category: "Plan Management".to_string(),
        },
        EventTypeInfo {
            value: "plan.updated".to_string(),
            label: "Plan Updated".to_string(),
            category: "Plan Management".to_string(),
        },
        EventTypeInfo {
            value: "plan.deleted".to_string(),
            label: "Plan Deleted".to_string(),
            category: "Plan Management".to_string(),
        },
        EventTypeInfo {
            value: "subscription.created".to_string(),
            label: "Subscription Created".to_string(),
            category: "Subscription Management".to_string(),
        },
        EventTypeInfo {
            value: "subscription.updated".to_string(),
            label: "Subscription Updated".to_string(),
            category: "Subscription Management".to_string(),
        },
        EventTypeInfo {
            value: "subscription.canceled".to_string(),
            label: "Subscription Canceled".to_string(),
            category: "Subscription Management".to_string(),
        },
        EventTypeInfo {
            value: "invitation.accepted".to_string(),
            label: "Invitation Accepted".to_string(),
            category: "Invitation Management".to_string(),
        },
        EventTypeInfo {
            value: "invitation.declined".to_string(),
            label: "Invitation Declined".to_string(),
            category: "Invitation Management".to_string(),
        },
        EventTypeInfo {
            value: "invitation.expired".to_string(),
            label: "Invitation Expired".to_string(),
            category: "Invitation Management".to_string(),
        },
        EventTypeInfo {
            value: "invitation.revoked".to_string(),
            label: "Invitation Revoked".to_string(),
            category: "Invitation Management".to_string(),
        },
        EventTypeInfo {
            value: "security.mfa.enabled".to_string(),
            label: "MFA Enabled".to_string(),
            category: "Security".to_string(),
        },
        EventTypeInfo {
            value: "security.mfa.disabled".to_string(),
            label: "MFA Disabled".to_string(),
            category: "Security".to_string(),
        },
        EventTypeInfo {
            value: "security.password.changed".to_string(),
            label: "Password Changed".to_string(),
            category: "Security".to_string(),
        },
    ];

    Ok(Json(event_types))
}

#[derive(Debug, Serialize)]
pub struct EventTypeInfo {
    pub value: String,
    pub label: String,
    pub category: String,
}
