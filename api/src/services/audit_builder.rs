//! Builder helpers for creating audit log ActiveModels
//!
//! These helpers provide an ergonomic API for creating audit events
//! that can be sent to the AuditActor for non-blocking persistence.

#![allow(dead_code)]

use crate::entities::{mfa_audit_log, organization_audit_log};
use sea_orm::Set;
use uuid::Uuid;

/// Builder for MFA audit events
pub struct MfaAuditBuilder {
    org_id: Option<String>,
    user_id: String,
    event_type: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    details: Option<String>,
}

impl MfaAuditBuilder {
    pub fn new(user_id: &str, event_type: &str) -> Self {
        Self {
            org_id: None,
            user_id: user_id.to_string(),
            event_type: event_type.to_string(),
            ip_address: None,
            user_agent: None,
            success: true,
            details: None,
        }
    }

    pub fn org_id(mut self, org_id: Option<&str>) -> Self {
        self.org_id = org_id.map(String::from);
        self
    }

    pub fn ip_address(mut self, ip: Option<&str>) -> Self {
        self.ip_address = ip.map(String::from);
        self
    }

    pub fn user_agent(mut self, ua: Option<String>) -> Self {
        self.user_agent = ua;
        self
    }

    pub fn success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn details(mut self, details: Option<&str>) -> Self {
        self.details = details.map(String::from);
        self
    }

    pub fn build(self) -> mfa_audit_log::ActiveModel {
        mfa_audit_log::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(self.org_id),
            user_id: Set(self.user_id),
            event_type: Set(self.event_type),
            ip_address: Set(self.ip_address),
            user_agent: Set(self.user_agent),
            success: Set(self.success),
            details: Set(self.details),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
    }
}

/// Builder for Organization audit events
pub struct OrgAuditBuilder {
    org_id: String,
    actor_user_id: String,
    action: String,
    target_type: String,
    target_id: String,
    ip_address: Option<String>,
    user_agent: Option<String>,
    success: bool,
    details: Option<String>,
}

impl OrgAuditBuilder {
    pub fn new(org_id: &str, actor_user_id: Option<&str>, action: &str) -> Self {
        Self {
            org_id: org_id.to_string(),
            actor_user_id: actor_user_id.unwrap_or("system").to_string(),
            action: action.to_string(),
            target_type: "unknown".to_string(),
            target_id: String::new(),
            ip_address: None,
            user_agent: None,
            success: true,
            details: None,
        }
    }

    pub fn target(mut self, target_type: &str, target_id: &str) -> Self {
        self.target_type = target_type.to_string();
        self.target_id = target_id.to_string();
        self
    }

    pub fn ip_address(mut self, ip: Option<&str>) -> Self {
        self.ip_address = ip.map(String::from);
        self
    }

    pub fn user_agent(mut self, ua: Option<String>) -> Self {
        self.user_agent = ua;
        self
    }

    pub fn success(mut self, success: bool) -> Self {
        self.success = success;
        self
    }

    pub fn details_json(mut self, details: Option<serde_json::Value>) -> Self {
        self.details = details.map(|d| d.to_string());
        self
    }

    pub fn details(mut self, details: Option<&str>) -> Self {
        self.details = details.map(String::from);
        self
    }

    pub fn build(self) -> organization_audit_log::ActiveModel {
        organization_audit_log::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(self.org_id),
            actor_user_id: Set(self.actor_user_id),
            action: Set(self.action),
            target_type: Set(self.target_type),
            target_id: Set(self.target_id),
            ip_address: Set(self.ip_address),
            user_agent: Set(self.user_agent),
            success: Set(self.success),
            details: Set(self.details),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
    }
}
