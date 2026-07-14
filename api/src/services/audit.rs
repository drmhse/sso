//! Audit logging service for MFA and other security events

#![allow(dead_code)]

use crate::db::models::OrganizationAuditLogWithUser;
use crate::entities::users;
use crate::entities::{mfa_audit_log, organization_audit_log};
use crate::services::events::EventDispatcher;
use anyhow::Result;
use mfa_audit_log::ActiveModel as MfaAuditLogActiveModel;
use organization_audit_log::ActiveModel as OrgAuditLogActiveModel;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, FromQueryResult, QueryFilter, Set};
use serde_json::json;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

#[allow(dead_code)]
#[derive(Debug, serde::Deserialize)]
struct MfaAuditLogEntry {
    id: String,
    org_id: String,
    user_id: String,
    event_type: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    details: Option<String>,
    created_at: String,
}

#[allow(dead_code)]
#[derive(Debug, FromQueryResult)]
struct MfaAuditLogQuery {
    id: String,
    org_id: String,
    user_id: String,
    user_email: Option<String>,
    event_type: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    details: Option<String>,
    created_at: chrono::NaiveDateTime,
}

/// MFA audit event types
#[allow(dead_code)]
#[derive(Debug, Clone, strum::Display)]
pub enum MfaAuditEvent {
    #[strum(serialize = "mfa_setup_initiated")]
    SetupInitiated,
    #[strum(serialize = "mfa_setup_completed")]
    SetupCompleted,
    #[strum(serialize = "mfa_setup_failed")]
    SetupFailed,
    #[strum(serialize = "mfa_enabled")]
    Enabled,
    #[strum(serialize = "mfa_disabled")]
    Disabled,
    #[strum(serialize = "mfa_verify_attempt")]
    VerifyAttempt,
    #[strum(serialize = "mfa_verify_success")]
    VerifySuccess,
    #[strum(serialize = "mfa_verify_failed")]
    VerifyFailed,
    #[strum(serialize = "backup_codes_generated")]
    BackupCodesGenerated,
    #[strum(serialize = "backup_code_used")]
    BackupCodeUsed,
    #[strum(serialize = "mfa_force_disabled_by_admin")]
    ForceDisabledByAdmin,
}

// ...

/// Audit service for logging MFA events
pub struct MfaAuditService {
    db: DatabaseConnection,
}

impl MfaAuditService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Log an MFA audit event
    ///
    /// # Arguments
    /// * `org_id` - Optional Organization ID (None for platform-level MFA events)
    /// * `user_id` - User ID who triggered the event
    /// * `event` - Type of MFA event
    /// * `ip_address` - Optional client IP address
    /// * `user_agent` - Optional client user agent
    /// * `success` - Whether the operation succeeded
    /// * `details` - Optional details (e.g., failure reason, method used)
    #[allow(clippy::too_many_arguments)]
    pub async fn log_mfa_event(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        event: MfaAuditEvent,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        success: bool,
        details: Option<&str>,
    ) -> Result<()> {
        let audit_id = Uuid::new_v4().to_string();
        let event_type = event.to_string();
        let ip_str = ip_address.map(|ip| ip.to_string());

        let now = chrono::Utc::now().naive_utc();

        let audit_log = MfaAuditLogActiveModel {
            id: Set(audit_id),
            org_id: Set(org_id.map(|s| s.to_string())),
            user_id: Set(user_id.to_string()),
            event_type: Set(event_type.clone()),
            success: Set(success),
            details: Set(details.map(|s| s.to_string())),
            ip_address: Set(ip_str.clone()),
            user_agent: Set(user_agent.clone()),
            created_at: Set(now),
        };

        crate::services::audit_actor::enqueue_mfa_with_connection(&self.db, audit_log).await?;

        tracing::info!(
            "MFA audit log: org_id={}, user_id={}, event_type={}, success={}, ip={}",
            org_id.unwrap_or("[platform]"),
            user_id,
            event_type,
            success,
            ip_str.as_deref().unwrap_or("unknown")
        );

        Ok(())
    }

    /// Log MFA setup initiation
    pub async fn log_setup_initiated(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::SetupInitiated,
            ip_address,
            user_agent,
            true,
            None,
        )
        .await
    }

    /// Log MFA setup completion
    #[allow(dead_code)]
    pub async fn log_setup_completed(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        method: &str, // "totp", "passkey", etc.
    ) -> Result<()> {
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::SetupCompleted,
            ip_address,
            user_agent,
            true,
            Some(method),
        )
        .await
    }

    /// Log MFA setup failure
    #[allow(dead_code)]
    pub async fn log_setup_failed(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        reason: &str,
    ) -> Result<()> {
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::SetupFailed,
            ip_address,
            user_agent,
            false,
            Some(reason),
        )
        .await
    }

    /// Log MFA enablement
    pub async fn log_mfa_enabled(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        method: &str,
    ) -> Result<()> {
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::Enabled,
            ip_address,
            user_agent,
            true,
            Some(method),
        )
        .await
    }

    /// Log MFA disablement
    pub async fn log_mfa_disabled(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        disabled_by_admin: bool,
        admin_user_id: Option<String>,
    ) -> Result<()> {
        let event = if disabled_by_admin {
            MfaAuditEvent::ForceDisabledByAdmin
        } else {
            MfaAuditEvent::Disabled
        };

        let details = if disabled_by_admin {
            admin_user_id.map(|id| format!("disabled_by_admin:{}", id))
        } else {
            None
        };

        self.log_mfa_event(
            org_id,
            user_id,
            event,
            ip_address,
            user_agent,
            true,
            details.as_deref(),
        )
        .await
    }

    /// Log MFA verification attempt
    #[allow(dead_code)]
    pub async fn log_verify_attempt(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        verification_type: &str, // "totp" or "backup_code"
    ) -> Result<()> {
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::VerifyAttempt,
            ip_address,
            user_agent,
            true,
            Some(verification_type),
        )
        .await
    }

    /// Log MFA verification success
    pub async fn log_verify_success(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        verification_type: &str,
    ) -> Result<()> {
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::VerifySuccess,
            ip_address,
            user_agent,
            true,
            Some(verification_type),
        )
        .await
    }

    /// Log MFA verification failure
    pub async fn log_verify_failed(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        verification_type: &str,
        reason: &str,
    ) -> Result<()> {
        let details = format!("method:{},reason:{}", verification_type, reason);
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::VerifyFailed,
            ip_address,
            user_agent,
            false,
            Some(&details),
        )
        .await
    }

    /// Log backup codes generation
    pub async fn log_backup_codes_generated(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        code_count: usize,
    ) -> Result<()> {
        let details = format!("count:{}", code_count);
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::BackupCodesGenerated,
            ip_address,
            user_agent,
            true,
            Some(&details),
        )
        .await
    }

    /// Log backup code usage
    #[allow(dead_code)]
    pub async fn log_backup_code_used(
        &self,
        org_id: Option<&str>,
        user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        code_id: Option<&str>,
    ) -> Result<()> {
        let details = code_id.map(|id| format!("code_id:{}", id));
        self.log_mfa_event(
            org_id,
            user_id,
            MfaAuditEvent::BackupCodeUsed,
            ip_address,
            user_agent,
            true,
            details.as_deref(),
        )
        .await
    }

    /// Get recent MFA audit logs for a user
    #[allow(dead_code)]
    pub async fn get_user_mfa_logs(
        &self,
        user_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<serde_json::Value>> {
        use sea_orm::{QueryOrder, QuerySelect};

        let (limit_val, _) = crate::utils::pagination::signed_limit_offset(limit, None, 100, 1000);

        let (limit_val, _) = crate::utils::pagination::store_u64(limit_val, 0, 1000);
        let logs = mfa_audit_log::Entity::find()
            .filter(mfa_audit_log::Column::UserId.eq(user_id))
            .order_by_desc(mfa_audit_log::Column::CreatedAt)
            .limit(limit_val)
            .all(&self.db)
            .await?;

        let mut results = Vec::new();
        for log in logs {
            let log_json = json!({
                "id": log.id,
                "org_id": log.org_id,
                "user_id": log.user_id,
                "event_type": log.event_type,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "success": log.success,
                "details": log.details,
                "created_at": log.created_at.to_string()
            });
            results.push(log_json);
        }

        Ok(results)
    }

    /// Get MFA audit logs for an organization
    #[allow(dead_code)]
    pub async fn get_org_mfa_logs(
        &self,
        org_id: &str,
        limit: Option<i64>,
    ) -> Result<Vec<serde_json::Value>> {
        use sea_orm::{QueryOrder, QuerySelect};

        let (limit_val, _) = crate::utils::pagination::signed_limit_offset(limit, None, 100, 1000);

        let (limit_val, _) = crate::utils::pagination::store_u64(limit_val, 0, 1000);
        let logs = mfa_audit_log::Entity::find()
            .filter(mfa_audit_log::Column::OrgId.eq(org_id))
            .order_by_desc(mfa_audit_log::Column::CreatedAt)
            .limit(limit_val)
            .all(&self.db)
            .await?;

        let mut results = Vec::new();
        for log in logs {
            let log_json = json!({
                "id": log.id,
                "org_id": log.org_id,
                "user_id": log.user_id,
                "event_type": log.event_type,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "success": log.success,
                "details": log.details,
                "created_at": log.created_at.to_string()
            });
            results.push(log_json);
        }

        Ok(results)
    }

    /// Get all MFA audit logs (platform-wide)
    #[allow(dead_code)]
    pub async fn get_all_mfa_logs(&self, limit: Option<i64>) -> Result<Vec<serde_json::Value>> {
        use sea_orm::{QueryOrder, QuerySelect};

        let (limit_val, _) = crate::utils::pagination::signed_limit_offset(limit, None, 100, 1000);

        let (limit_val, _) = crate::utils::pagination::store_u64(limit_val, 0, 1000);
        let logs = mfa_audit_log::Entity::find()
            .order_by_desc(mfa_audit_log::Column::CreatedAt)
            .limit(limit_val)
            .all(&self.db)
            .await?;

        let mut results = Vec::new();
        for log in logs {
            let log_json = json!({
                "id": log.id,
                "org_id": log.org_id,
                "user_id": log.user_id,
                "event_type": log.event_type,
                "ip_address": log.ip_address,
                "user_agent": log.user_agent,
                "success": log.success,
                "details": log.details,
                "created_at": log.created_at.to_string()
            });
            results.push(log_json);
        }

        Ok(results)
    }
}

// ===============================================
// Organization Audit Log Service
// ===============================================

/// Audit event types for organization-level actions
#[allow(dead_code)]
#[derive(Debug, Clone, strum::Display)]
pub enum OrgAuditEvent {
    #[strum(serialize = "org.created")]
    OrgCreated,
    #[strum(serialize = "org.updated")]
    OrgUpdated,
    #[strum(serialize = "org.deleted")]
    OrgDeleted,
    #[strum(serialize = "member.added")]
    MemberAdded,
    #[strum(serialize = "member.removed")]
    MemberRemoved,
    #[strum(serialize = "member.role_changed")]
    MemberRoleChanged,
    #[strum(serialize = "settings.updated")]
    SettingsUpdated,
    #[strum(serialize = "domain.verified")]
    DomainVerified,
    #[strum(serialize = "domain.removed")]
    DomainRemoved,
    #[strum(serialize = "domain.set")]
    DomainSet,
    #[strum(serialize = "domain.deleted")]
    DomainDeleted,
    #[strum(serialize = "sso.configured")]
    SsoConfigured,
    #[strum(serialize = "sso.removed")]
    SsoRemoved,
    #[strum(serialize = "api_key.created")]
    ApiKeyCreated,
    #[strum(serialize = "api_key.revoked")]
    ApiKeyRevoked,
    #[strum(serialize = "api_key.deleted")]
    ApiKeyDeleted,
    #[strum(serialize = "webhook.created")]
    WebhookCreated,
    #[strum(serialize = "webhook.updated")]
    WebhookUpdated,
    #[strum(serialize = "webhook.deleted")]
    WebhookDeleted,
    #[strum(serialize = "service.created")]
    ServiceCreated,
    #[strum(serialize = "service.updated")]
    ServiceUpdated,
    #[strum(serialize = "service.deleted")]
    ServiceDeleted,
    #[strum(serialize = "branding.updated")]
    BrandingUpdated,
    #[strum(serialize = "siem_config.created")]
    SiemConfigCreated,
    #[strum(serialize = "siem_config.updated")]
    SiemConfigUpdated,
    #[strum(serialize = "siem_config.deleted")]
    SiemConfigDeleted,
    #[strum(serialize = "user.invited")]
    UserInvited,
    #[strum(serialize = "user.removed")]
    UserRemoved,
    #[strum(serialize = "user.role_updated")]
    UserRoleUpdated,
    #[strum(serialize = "user.anonymized")]
    UserAnonymized,
}

/// Audit service for logging organization events
#[derive(Clone)]
pub struct OrgAuditService {
    db: DatabaseConnection,
    event_dispatcher: Option<Arc<EventDispatcher>>,
}

impl OrgAuditService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self {
            db,
            event_dispatcher: None,
        }
    }

    pub fn with_event_dispatcher(db: DatabaseConnection, dispatcher: Arc<EventDispatcher>) -> Self {
        Self {
            db,
            event_dispatcher: Some(dispatcher),
        }
    }

    /// Log an organization audit event
    #[allow(clippy::too_many_arguments)]
    pub async fn log_org_event(
        &self,
        org_id: &str,
        actor_user_id: Option<&str>,
        event: OrgAuditEvent,
        target_type: Option<&str>,
        target_id: Option<&str>,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        success: bool,
        details: Option<serde_json::Value>,
    ) -> Result<()> {
        let audit_id = Uuid::new_v4().to_string();
        let action = event.to_string();
        let ip_str = ip_address.map(|ip| ip.to_string());
        let user_agent_str = user_agent.clone();

        let now = chrono::Utc::now().naive_utc();

        let audit_log = OrgAuditLogActiveModel {
            id: Set(audit_id.clone()),
            org_id: Set(org_id.to_string()),
            actor_user_id: Set(actor_user_id
                .map(|s| s.to_string())
                .unwrap_or_else(|| "system".to_string())),
            action: Set(action.clone()),
            target_type: Set(target_type
                .map(|s| s.to_string())
                .unwrap_or_else(|| "unknown".to_string())),
            target_id: Set(target_id.map(|s| s.to_string()).unwrap_or_default()),
            ip_address: Set(ip_str.clone()),
            user_agent: Set(user_agent_str.clone()),
            success: Set(success),
            details: Set(details.clone().map(|d| d.to_string())),
            created_at: Set(now),
        };

        crate::services::audit_actor::enqueue_org_with_connection(&self.db, audit_log).await?;

        // Emit event for real-time notifications (if dispatcher is configured)
        // Note: We don't publish audit log events to webhooks by default,
        // but this could be extended if needed in the future.
        let _ = &self.event_dispatcher; // Acknowledge dispatcher exists but don't use it for audit logs

        tracing::info!(
            "Org audit log: org_id={}, actor={}, action={}, target_type={}, success={}, ip={}",
            org_id,
            actor_user_id.unwrap_or("system"),
            action,
            target_type.unwrap_or("none"),
            success,
            ip_str.as_deref().unwrap_or("unknown")
        );

        Ok(())
    }

    /// Alias for log_org_event for backward compatibility
    #[allow(clippy::too_many_arguments)]
    pub async fn log_organization_event(
        &self,
        org_id: &str,
        actor_user_id: Option<&str>,
        event: OrgAuditEvent,
        target_type: Option<&str>,
        target_id: Option<&str>,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
        success: bool,
        details: Option<serde_json::Value>,
    ) -> Result<()> {
        self.log_org_event(
            org_id,
            actor_user_id,
            event,
            target_type,
            target_id,
            ip_address,
            user_agent,
            success,
            details,
        )
        .await
    }

    /// Helper function to convert entity logs to API model
    fn convert_logs_to_model(
        logs: Vec<organization_audit_log::Model>,
        users_map: &HashMap<String, String>,
    ) -> Vec<OrganizationAuditLogWithUser> {
        use chrono::{DateTime, Utc};

        logs.into_iter()
            .map(|log| {
                // actor_user_id is String, look it up in users_map
                let actor_user_email =
                    if log.actor_user_id.is_empty() || log.actor_user_id == "system" {
                        None
                    } else {
                        users_map.get(&log.actor_user_id).cloned()
                    };

                OrganizationAuditLogWithUser {
                    id: log.id,
                    org_id: log.org_id,
                    actor_user_id: log.actor_user_id,
                    actor_user_email,
                    action: log.action,
                    target_type: log.target_type,
                    target_id: log.target_id,
                    ip_address: log.ip_address,
                    user_agent: log.user_agent,
                    success: log.success,
                    details: log.details,
                    created_at: DateTime::<Utc>::from_naive_utc_and_offset(log.created_at, Utc),
                }
            })
            .collect()
    }

    /// Helper to fetch users map for actor IDs
    async fn fetch_users_map(&self, user_ids: Vec<String>) -> Result<HashMap<String, String>> {
        if user_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let users = users::Entity::find()
            .filter(users::Column::Id.is_in(user_ids))
            .all(&self.db)
            .await?;

        Ok(users.into_iter().map(|u| (u.id, u.email)).collect())
    }

    /// Get audit logs for an organization with pagination
    pub async fn get_organization_audit_logs(
        &self,
        org_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrganizationAuditLogWithUser>> {
        use sea_orm::{QueryOrder, QuerySelect};

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 100);
        let logs = organization_audit_log::Entity::find()
            .filter(organization_audit_log::Column::OrgId.eq(org_id))
            .order_by_desc(organization_audit_log::Column::CreatedAt)
            .order_by_desc(organization_audit_log::Column::Id)
            .limit(limit)
            .offset(offset)
            .all(&self.db)
            .await?;

        let user_ids: Vec<String> = logs.iter().map(|log| log.actor_user_id.clone()).collect();

        let users_map = self.fetch_users_map(user_ids).await?;
        Ok(Self::convert_logs_to_model(logs, &users_map))
    }

    /// Get audit logs filtered by action with pagination
    pub async fn get_audit_logs_by_action(
        &self,
        org_id: &str,
        action: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrganizationAuditLogWithUser>> {
        use sea_orm::{QueryOrder, QuerySelect};

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 100);
        let logs = organization_audit_log::Entity::find()
            .filter(organization_audit_log::Column::OrgId.eq(org_id))
            .filter(organization_audit_log::Column::Action.eq(action))
            .order_by_desc(organization_audit_log::Column::CreatedAt)
            .order_by_desc(organization_audit_log::Column::Id)
            .limit(limit)
            .offset(offset)
            .all(&self.db)
            .await?;

        let user_ids: Vec<String> = logs.iter().map(|log| log.actor_user_id.clone()).collect();

        let users_map = self.fetch_users_map(user_ids).await?;
        Ok(Self::convert_logs_to_model(logs, &users_map))
    }

    /// Get audit logs for a specific target
    pub async fn get_target_audit_logs(
        &self,
        org_id: &str,
        target_type: &str,
        target_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<OrganizationAuditLogWithUser>> {
        use sea_orm::{QueryOrder, QuerySelect};

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 100);
        let logs = organization_audit_log::Entity::find()
            .filter(organization_audit_log::Column::OrgId.eq(org_id))
            .filter(organization_audit_log::Column::TargetType.eq(target_type))
            .filter(organization_audit_log::Column::TargetId.eq(target_id))
            .order_by_desc(organization_audit_log::Column::CreatedAt)
            .order_by_desc(organization_audit_log::Column::Id)
            .limit(limit)
            .offset(offset)
            .all(&self.db)
            .await?;

        let user_ids: Vec<String> = logs.iter().map(|log| log.actor_user_id.clone()).collect();

        let users_map = self.fetch_users_map(user_ids).await?;
        Ok(Self::convert_logs_to_model(logs, &users_map))
    }

    /// Get total count of audit logs for an organization
    pub async fn get_audit_log_count(&self, org_id: &str) -> Result<i64> {
        use sea_orm::PaginatorTrait;

        let count = organization_audit_log::Entity::find()
            .filter(organization_audit_log::Column::OrgId.eq(org_id))
            .count(&self.db)
            .await?;

        Ok(count as i64)
    }

    /// Count audit logs using the same organization-first filter shape as list routes.
    pub async fn get_audit_log_count_filtered(
        &self,
        org_id: &str,
        action: Option<&str>,
        target_type: Option<&str>,
        target_id: Option<&str>,
    ) -> Result<i64> {
        use sea_orm::PaginatorTrait;

        let mut query = organization_audit_log::Entity::find()
            .filter(organization_audit_log::Column::OrgId.eq(org_id));
        if let Some(action) = action {
            query = query.filter(organization_audit_log::Column::Action.eq(action));
        } else if let (Some(target_type), Some(target_id)) = (target_type, target_id) {
            query = query
                .filter(organization_audit_log::Column::TargetType.eq(target_type))
                .filter(organization_audit_log::Column::TargetId.eq(target_id));
        }

        Ok(query.count(&self.db).await? as i64)
    }

    // Convenience methods for common org events

    /// Log member added event
    #[allow(dead_code)]
    pub async fn log_member_added(
        &self,
        org_id: &str,
        actor_user_id: &str,
        target_user_id: &str,
        role: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log_org_event(
            org_id,
            Some(actor_user_id),
            OrgAuditEvent::MemberAdded,
            Some("user"),
            Some(target_user_id),
            ip_address,
            user_agent,
            true,
            Some(json!({ "role": role })),
        )
        .await
    }

    /// Log member removed event
    #[allow(dead_code)]
    pub async fn log_member_removed(
        &self,
        org_id: &str,
        actor_user_id: &str,
        target_user_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log_org_event(
            org_id,
            Some(actor_user_id),
            OrgAuditEvent::MemberRemoved,
            Some("user"),
            Some(target_user_id),
            ip_address,
            user_agent,
            true,
            None,
        )
        .await
    }

    /// Log settings updated event
    #[allow(dead_code)]
    pub async fn log_settings_updated(
        &self,
        org_id: &str,
        actor_user_id: &str,
        changed_fields: Vec<&str>,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log_org_event(
            org_id,
            Some(actor_user_id),
            OrgAuditEvent::SettingsUpdated,
            Some("organization"),
            Some(org_id),
            ip_address,
            user_agent,
            true,
            Some(json!({ "changed_fields": changed_fields })),
        )
        .await
    }

    /// Log domain verification event
    #[allow(dead_code)]
    pub async fn log_domain_verified(
        &self,
        org_id: &str,
        actor_user_id: &str,
        domain: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log_org_event(
            org_id,
            Some(actor_user_id),
            OrgAuditEvent::DomainVerified,
            Some("domain"),
            Some(domain),
            ip_address,
            user_agent,
            true,
            None,
        )
        .await
    }

    /// Log webhook created event
    #[allow(dead_code)]
    pub async fn log_webhook_created(
        &self,
        org_id: &str,
        actor_user_id: &str,
        webhook_id: &str,
        webhook_name: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log_org_event(
            org_id,
            Some(actor_user_id),
            OrgAuditEvent::WebhookCreated,
            Some("webhook"),
            Some(webhook_id),
            ip_address,
            user_agent,
            true,
            Some(json!({ "name": webhook_name })),
        )
        .await
    }

    /// Log API key created event
    #[allow(dead_code)]
    pub async fn log_api_key_created(
        &self,
        org_id: &str,
        actor_user_id: &str,
        api_key_id: &str,
        key_name: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log_org_event(
            org_id,
            Some(actor_user_id),
            OrgAuditEvent::ApiKeyCreated,
            Some("api_key"),
            Some(api_key_id),
            ip_address,
            user_agent,
            true,
            Some(json!({ "name": key_name })),
        )
        .await
    }

    /// Log API key revoked event
    #[allow(dead_code)]
    pub async fn log_api_key_revoked(
        &self,
        org_id: &str,
        actor_user_id: &str,
        api_key_id: &str,
        ip_address: Option<IpAddr>,
        user_agent: Option<String>,
    ) -> Result<()> {
        self.log_org_event(
            org_id,
            Some(actor_user_id),
            OrgAuditEvent::ApiKeyRevoked,
            Some("api_key"),
            Some(api_key_id),
            ip_address,
            user_agent,
            true,
            None,
        )
        .await
    }
}

// Type aliases for backward compatibility
pub type OrganizationAuditService = OrgAuditService;
pub type OrganizationAuditEvent = OrgAuditEvent;
