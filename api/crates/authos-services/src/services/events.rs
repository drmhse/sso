//! Centralized event dispatching system for webhooks
//!
//! This module provides a unified event system that decouples event publishing
//! from webhook delivery, supporting both organizational audit events and
//! end-user events (logins, signups, MFA changes, etc.)

use anyhow::Result;
use chrono::Utc;
use sea_orm::DatabaseConnection;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

/// All supported event types in the SSO platform
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EventType {
    // User lifecycle events
    UserSignupSuccess,
    UserLoginSuccess,
    UserLoginFailed,
    UserLogout,

    // MFA events
    UserMfaEnabled,
    UserMfaDisabled,
    UserMfaVerifySuccess,
    UserMfaVerifyFailed,

    // Organization audit events (from OrganizationAuditEvent)
    UserInvited,
    UserJoined,
    UserRemoved,
    UserRoleUpdated,
    UserAnonymized,

    ServiceCreated,
    ServiceUpdated,
    ServiceDeleted,
    ServiceOAuthCredentialsUpdated,

    OrganizationUpdated,
    OrganizationSmtpConfigured,
    OrganizationSmtpRemoved,

    PlanCreated,
    PlanUpdated,
    PlanDeleted,

    SubscriptionCreated,
    SubscriptionUpdated,
    SubscriptionCanceled,

    InvitationAccepted,
    InvitationDeclined,
    InvitationExpired,
    InvitationRevoked,

    SecurityMfaEnabled,
    SecurityMfaDisabled,
    SecurityPasswordChanged,

    ApiKeyCreated,
    ApiKeyDeleted,

    DomainSet,
    DomainVerified,
    DomainDeleted,
    BrandingUpdated,

    SiemConfigCreated,
    SiemConfigUpdated,
    SiemConfigDeleted,

    // Custom event type for extensibility
    Custom(String),
}

impl EventType {
    /// Convert event type to its string representation for webhook delivery
    pub fn as_str(&self) -> String {
        match self {
            // User lifecycle events
            EventType::UserSignupSuccess => "user.signup.success".to_string(),
            EventType::UserLoginSuccess => "user.login.success".to_string(),
            EventType::UserLoginFailed => "user.login.failed".to_string(),
            EventType::UserLogout => "user.logout".to_string(),

            // MFA events
            EventType::UserMfaEnabled => "user.mfa.enabled".to_string(),
            EventType::UserMfaDisabled => "user.mfa.disabled".to_string(),
            EventType::UserMfaVerifySuccess => "user.mfa.verify.success".to_string(),
            EventType::UserMfaVerifyFailed => "user.mfa.verify.failed".to_string(),

            // Organization audit events (matching OrganizationAuditEvent format)
            EventType::UserInvited => "user.invited".to_string(),
            EventType::UserJoined => "user.joined".to_string(),
            EventType::UserRemoved => "user.removed".to_string(),
            EventType::UserRoleUpdated => "user.role_updated".to_string(),
            EventType::UserAnonymized => "user.anonymized".to_string(),

            EventType::ServiceCreated => "service.created".to_string(),
            EventType::ServiceUpdated => "service.updated".to_string(),
            EventType::ServiceDeleted => "service.deleted".to_string(),
            EventType::ServiceOAuthCredentialsUpdated => {
                "service.oauth_credentials.updated".to_string()
            }

            EventType::OrganizationUpdated => "organization.updated".to_string(),
            EventType::OrganizationSmtpConfigured => "organization.smtp.configured".to_string(),
            EventType::OrganizationSmtpRemoved => "organization.smtp.removed".to_string(),

            EventType::PlanCreated => "plan.created".to_string(),
            EventType::PlanUpdated => "plan.updated".to_string(),
            EventType::PlanDeleted => "plan.deleted".to_string(),

            EventType::SubscriptionCreated => "subscription.created".to_string(),
            EventType::SubscriptionUpdated => "subscription.updated".to_string(),
            EventType::SubscriptionCanceled => "subscription.canceled".to_string(),

            EventType::InvitationAccepted => "invitation.accepted".to_string(),
            EventType::InvitationDeclined => "invitation.declined".to_string(),
            EventType::InvitationExpired => "invitation.expired".to_string(),
            EventType::InvitationRevoked => "invitation.revoked".to_string(),

            EventType::SecurityMfaEnabled => "security.mfa.enabled".to_string(),
            EventType::SecurityMfaDisabled => "security.mfa.disabled".to_string(),
            EventType::SecurityPasswordChanged => "security.password.changed".to_string(),

            EventType::ApiKeyCreated => "api_key.created".to_string(),
            EventType::ApiKeyDeleted => "api_key.deleted".to_string(),

            EventType::DomainSet => "domain.set".to_string(),
            EventType::DomainVerified => "domain.verified".to_string(),
            EventType::DomainDeleted => "domain.deleted".to_string(),
            EventType::BrandingUpdated => "branding.updated".to_string(),

            EventType::SiemConfigCreated => "siem_config.created".to_string(),
            EventType::SiemConfigUpdated => "siem_config.updated".to_string(),
            EventType::SiemConfigDeleted => "siem_config.deleted".to_string(),

            EventType::Custom(s) => s.clone(),
        }
    }

    /// Parse event type from string
    /// Infallible: unknown names become `Custom`, so this is not a parse.
    pub fn from_wire(s: &str) -> Self {
        match s {
            // User lifecycle events
            "user.signup.success" => EventType::UserSignupSuccess,
            "user.login.success" => EventType::UserLoginSuccess,
            "user.login.failed" => EventType::UserLoginFailed,
            "user.logout" => EventType::UserLogout,

            // MFA events
            "user.mfa.enabled" => EventType::UserMfaEnabled,
            "user.mfa.disabled" => EventType::UserMfaDisabled,
            "user.mfa.verify.success" => EventType::UserMfaVerifySuccess,
            "user.mfa.verify.failed" => EventType::UserMfaVerifyFailed,

            // Organization audit events
            "user.invited" => EventType::UserInvited,
            "user.joined" => EventType::UserJoined,
            "user.removed" => EventType::UserRemoved,
            "user.role_updated" => EventType::UserRoleUpdated,

            "service.created" => EventType::ServiceCreated,
            "service.updated" => EventType::ServiceUpdated,
            "service.deleted" => EventType::ServiceDeleted,
            "service.oauth_credentials.updated" => EventType::ServiceOAuthCredentialsUpdated,

            "organization.updated" => EventType::OrganizationUpdated,
            "organization.smtp.configured" => EventType::OrganizationSmtpConfigured,
            "organization.smtp.removed" => EventType::OrganizationSmtpRemoved,

            "plan.created" => EventType::PlanCreated,
            "plan.updated" => EventType::PlanUpdated,
            "plan.deleted" => EventType::PlanDeleted,

            "subscription.created" => EventType::SubscriptionCreated,
            "subscription.updated" => EventType::SubscriptionUpdated,
            "subscription.canceled" => EventType::SubscriptionCanceled,

            "invitation.accepted" => EventType::InvitationAccepted,
            "invitation.declined" => EventType::InvitationDeclined,
            "invitation.expired" => EventType::InvitationExpired,
            "invitation.revoked" => EventType::InvitationRevoked,

            "security.mfa.enabled" => EventType::SecurityMfaEnabled,
            "security.mfa.disabled" => EventType::SecurityMfaDisabled,
            "security.password.changed" => EventType::SecurityPasswordChanged,

            "api_key.created" => EventType::ApiKeyCreated,
            "api_key.deleted" => EventType::ApiKeyDeleted,

            "domain.set" => EventType::DomainSet,
            "domain.verified" => EventType::DomainVerified,
            "domain.deleted" => EventType::DomainDeleted,
            "branding.updated" => EventType::BrandingUpdated,

            "siem_config.created" => EventType::SiemConfigCreated,
            "siem_config.updated" => EventType::SiemConfigUpdated,
            "siem_config.deleted" => EventType::SiemConfigDeleted,

            custom => EventType::Custom(custom.to_string()),
        }
    }

    /// Get all valid event type strings for documentation/validation
    pub fn all_event_types() -> Vec<String> {
        vec![
            // User lifecycle events
            "user.signup.success".to_string(),
            "user.login.success".to_string(),
            "user.login.failed".to_string(),
            "user.logout".to_string(),
            // MFA events
            "user.mfa.enabled".to_string(),
            "user.mfa.disabled".to_string(),
            "user.mfa.verify.success".to_string(),
            "user.mfa.verify.failed".to_string(),
            // Organization audit events
            "user.invited".to_string(),
            "user.joined".to_string(),
            "user.removed".to_string(),
            "user.role_updated".to_string(),
            "service.created".to_string(),
            "service.updated".to_string(),
            "service.deleted".to_string(),
            "service.oauth_credentials.updated".to_string(),
            "organization.updated".to_string(),
            "organization.smtp.configured".to_string(),
            "organization.smtp.removed".to_string(),
            "plan.created".to_string(),
            "plan.updated".to_string(),
            "plan.deleted".to_string(),
            "subscription.created".to_string(),
            "subscription.updated".to_string(),
            "subscription.canceled".to_string(),
            "invitation.accepted".to_string(),
            "invitation.declined".to_string(),
            "invitation.expired".to_string(),
            "invitation.revoked".to_string(),
            "security.mfa.enabled".to_string(),
            "security.mfa.disabled".to_string(),
            "security.password.changed".to_string(),
            "api_key.created".to_string(),
            "api_key.deleted".to_string(),
            "domain.set".to_string(),
            "domain.verified".to_string(),
            "domain.deleted".to_string(),
            "branding.updated".to_string(),
            "siem_config.created".to_string(),
            "siem_config.updated".to_string(),
            "siem_config.deleted".to_string(),
        ]
    }
}

/// Event payload data structure
#[derive(Debug, Clone)]
pub struct Event {
    /// Organization ID (may be None for platform-level events)
    pub org_id: Option<String>,

    /// Event type
    pub event_type: EventType,

    /// User ID who triggered the event (actor)
    pub actor_user_id: Option<String>,

    /// User email for the actor
    pub actor_email: Option<String>,

    /// Target resource type (e.g., "user", "service", "organization")
    pub target_type: Option<String>,

    /// Target resource ID
    pub target_id: Option<String>,

    /// Additional event data/details
    pub details: HashMap<String, serde_json::Value>,

    /// Timestamp of the event
    pub timestamp: chrono::DateTime<Utc>,
}

impl Event {
    /// Create a new event builder
    pub fn builder(event_type: EventType) -> EventBuilder {
        EventBuilder {
            event_type,
            org_id: None,
            actor_user_id: None,
            actor_email: None,
            target_type: None,
            target_id: None,
            details: HashMap::new(),
        }
    }

    /// Convert event to JSON payload for webhook delivery
    pub fn to_webhook_payload(&self) -> serde_json::Value {
        let mut payload = json!({
            "event": self.event_type.as_str(),
            "timestamp": self.timestamp.to_rfc3339(),
        });

        if let Some(org_id) = &self.org_id {
            payload["organization_id"] = json!(org_id);
        }

        if let Some(actor_id) = &self.actor_user_id {
            payload["actor_user_id"] = json!(actor_id);
        }

        if let Some(actor_email) = &self.actor_email {
            payload["actor_email"] = json!(actor_email);
        }

        if let Some(target_type) = &self.target_type {
            payload["target_type"] = json!(target_type);
        }

        if let Some(target_id) = &self.target_id {
            payload["target_id"] = json!(target_id);
        }

        if !self.details.is_empty() {
            payload["data"] = json!(self.details);
        }

        payload
    }
}

/// Builder for creating events
pub struct EventBuilder {
    event_type: EventType,
    org_id: Option<String>,
    actor_user_id: Option<String>,
    actor_email: Option<String>,
    target_type: Option<String>,
    target_id: Option<String>,
    details: HashMap<String, serde_json::Value>,
}

impl EventBuilder {
    pub fn org_id(mut self, org_id: impl Into<String>) -> Self {
        self.org_id = Some(org_id.into());
        self
    }

    pub fn actor_user_id(mut self, user_id: impl Into<String>) -> Self {
        self.actor_user_id = Some(user_id.into());
        self
    }

    pub fn actor_email(mut self, email: impl Into<String>) -> Self {
        self.actor_email = Some(email.into());
        self
    }

    pub fn target(mut self, target_type: impl Into<String>, target_id: impl Into<String>) -> Self {
        self.target_type = Some(target_type.into());
        self.target_id = Some(target_id.into());
        self
    }

    pub fn detail(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.details.insert(key.into(), value);
        self
    }

    pub fn details(mut self, details: HashMap<String, serde_json::Value>) -> Self {
        self.details = details;
        self
    }

    pub fn build(self) -> Event {
        Event {
            org_id: self.org_id,
            event_type: self.event_type,
            actor_user_id: self.actor_user_id,
            actor_email: self.actor_email,
            target_type: self.target_type,
            target_id: self.target_id,
            details: self.details,
            timestamp: Utc::now(),
        }
    }
}

/// Centralized event dispatcher service
pub struct EventDispatcher {
    db: DatabaseConnection,
}

impl EventDispatcher {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    async fn enqueue_webhook_deliveries(
        &self,
        webhooks: &[crate::entities::webhooks::Model],
        event_type: &str,
        webhook_payload: &serde_json::Value,
    ) {
        use crate::db::DB as DbEnum;
        use crate::services::job_queue::JobQueueService;

        for webhook in webhooks {
            if let Err(e) = JobQueueService::enqueue_webhook(
                DbEnum::Conn(&self.db),
                &webhook.id,
                event_type,
                webhook_payload,
            )
            .await
            {
                tracing::error!("Failed to enqueue webhook delivery job: {}", e);
            }
        }
    }

    /// Publish an event and trigger webhook deliveries
    pub async fn publish(&self, event: Event) -> Result<()> {
        use crate::db::DB as DbEnum;
        use crate::store::webhooks::WebhookStore;

        let event_type_str = event.event_type.as_str();
        let webhook_payload = event.to_webhook_payload();

        tracing::debug!(
            "Publishing event: type={}, org_id={:?}",
            event_type_str,
            event.org_id
        );

        // If this event is associated with an organization, enqueue webhook deliveries
        if let Some(org_id) = &event.org_id {
            // Get all active webhooks for this organization that subscribe to this event
            let webhooks = WebhookStore::find_active_webhooks_for_event(
                DbEnum::Conn(&self.db),
                org_id,
                &event_type_str,
            )
            .await?;

            self.enqueue_webhook_deliveries(&webhooks, &event_type_str, &webhook_payload)
                .await;
        }

        Ok(())
    }

    /// Publish multiple events in batch
    pub async fn publish_batch(&self, events: Vec<Event>) -> Result<()> {
        use crate::db::DB as DbEnum;
        use crate::store::webhooks::WebhookStore;

        let mut webhook_cache: HashMap<(String, String), Vec<crate::entities::webhooks::Model>> =
            HashMap::new();

        for event in events {
            let event_type_str = event.event_type.as_str();
            let webhook_payload = event.to_webhook_payload();

            tracing::debug!(
                "Publishing event: type={}, org_id={:?}",
                event_type_str,
                event.org_id
            );

            if let Some(org_id) = &event.org_id {
                let cache_key = (org_id.clone(), event_type_str.clone());
                let webhooks = if let Some(cached) = webhook_cache.get(&cache_key) {
                    cached.clone()
                } else {
                    let loaded = WebhookStore::find_active_webhooks_for_event(
                        DbEnum::Conn(&self.db),
                        org_id,
                        &event_type_str,
                    )
                    .await?;
                    webhook_cache.insert(cache_key, loaded.clone());
                    loaded
                };

                self.enqueue_webhook_deliveries(&webhooks, &event_type_str, &webhook_payload)
                    .await;
            }
        }
        Ok(())
    }
}

/// Shared event dispatcher instance builder
pub fn create_dispatcher(db: DatabaseConnection) -> Arc<EventDispatcher> {
    Arc::new(EventDispatcher::new(db))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_type_conversion() {
        let event_type = EventType::UserLoginSuccess;
        assert_eq!(event_type.as_str(), "user.login.success");

        let parsed = EventType::from_wire("user.login.success");
        assert_eq!(parsed, EventType::UserLoginSuccess);
    }

    #[test]
    fn test_event_builder() {
        let event = Event::builder(EventType::UserSignupSuccess)
            .org_id("org123")
            .actor_user_id("user456")
            .actor_email("user@example.com")
            .target("user", "user456")
            .detail("provider", json!("github"))
            .build();

        assert_eq!(event.org_id, Some("org123".to_string()));
        assert_eq!(event.actor_user_id, Some("user456".to_string()));
        assert_eq!(event.event_type, EventType::UserSignupSuccess);
    }

    #[test]
    fn test_event_payload() {
        let event = Event::builder(EventType::UserLoginSuccess)
            .org_id("org123")
            .actor_user_id("user456")
            .actor_email("user@example.com")
            .detail("provider", json!("google"))
            .build();

        let payload = event.to_webhook_payload();

        assert_eq!(payload["event"], "user.login.success");
        assert_eq!(payload["organization_id"], "org123");
        assert_eq!(payload["actor_user_id"], "user456");
        assert_eq!(payload["data"]["provider"], "google");
    }
}
