use crate::db::DB;
use crate::error::Result;
use crate::store::memberships::MembershipStore;
use crate::store::organization_roles::OrganizationRoleStore;
use std::collections::HashSet;

/// Permission capabilities
pub const CAP_ORG_SETTINGS_MANAGE: &str = "org.settings.manage";
pub const CAP_ORG_MEMBERS_VIEW: &str = "org.members.view";
pub const CAP_ORG_MEMBERS_MANAGE: &str = "org.members.manage";
pub const CAP_ORG_ROLES_MANAGE: &str = "org.roles.manage";
pub const CAP_BILLING_MANAGE: &str = "billing.manage";
pub const CAP_SERVICES_VIEW: &str = "services.view";
pub const CAP_SERVICES_CREATE: &str = "services.create";
pub const CAP_SERVICES_MANAGE: &str = "services.manage";
pub const CAP_END_USERS_VIEW: &str = "end_users.view";
pub const CAP_END_USERS_MANAGE: &str = "end_users.manage";
pub const CAP_WEBHOOKS_MANAGE: &str = "webhooks.manage";
pub const CAP_INTEGRATIONS_MANAGE: &str = "integrations.manage";
pub const CAP_AUDIT_LOGS_VIEW: &str = "audit_logs.view";
pub const CAP_RISK_EVENTS_VIEW: &str = "risk_events.view";
pub const CAP_RISK_POLICIES_MANAGE: &str = "risk_policies.manage";

pub struct PermissionService;

impl PermissionService {
    /// Check if a user has a specific capability in an organization
    pub async fn check(db: DB<'_>, org_id: &str, user_id: &str, capability: &str) -> Result<bool> {
        let membership =
            match MembershipStore::find_by_org_and_user(db.clone(), org_id, user_id).await? {
                Some(m) => m,
                None => return Ok(false),
            };

        match membership.role.as_str() {
            "owner" => return Ok(true), // Owner has all permissions
            // Admin clears every capability by design; ownership transfer is
            // guarded separately rather than through this table.
            "admin" => return Ok(true),
            // Every capability is administrative, so the built-in member role
            // holds none of them.
            "member" => return Ok(false),
            // Anything else is a custom role, resolved from the database below.
            _ => {}
        }

        let role =
            OrganizationRoleStore::find_by_org_and_slug(db, org_id, &membership.role).await?;

        if let Some(role) = role {
            if let Some(permissions) = role.permissions.as_array() {
                for p in permissions {
                    if let Some(p_str) = p.as_str() {
                        if p_str == capability {
                            return Ok(true);
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check if a user has ONE OF the provided capabilities
    pub async fn check_any(
        db: DB<'_>,
        org_id: &str,
        user_id: &str,
        capabilities: &[&str],
    ) -> Result<bool> {
        if capabilities.is_empty() {
            return Ok(false);
        }

        let membership =
            match MembershipStore::find_by_org_and_user(db.clone(), org_id, user_id).await? {
                Some(m) => m,
                None => return Ok(false),
            };

        match membership.role.as_str() {
            "owner" | "admin" => return Ok(true),
            "member" => return Ok(false),
            _ => {}
        }

        let role =
            OrganizationRoleStore::find_by_org_and_slug(db, org_id, &membership.role).await?;

        let Some(role) = role else {
            return Ok(false);
        };

        let requested: HashSet<&str> = capabilities.iter().copied().collect();
        Ok(role.permissions.as_array().is_some_and(|permissions| {
            permissions
                .iter()
                .filter_map(|permission| permission.as_str())
                .any(|permission| requested.contains(permission))
        }))
    }

    /// Retrieve all capabilities for a user in an organization
    pub async fn get_user_capabilities(
        db: DB<'_>,
        org_id: &str,
        user_id: &str,
    ) -> Result<Vec<String>> {
        let membership =
            match MembershipStore::find_by_org_and_user(db.clone(), org_id, user_id).await? {
                Some(m) => m,
                None => return Ok(vec![]),
            };

        match membership.role.as_str() {
            "owner" | "admin" => {
                // Return all system capabilities
                Ok(vec![
                    CAP_ORG_SETTINGS_MANAGE.to_string(),
                    CAP_ORG_MEMBERS_VIEW.to_string(),
                    CAP_ORG_MEMBERS_MANAGE.to_string(),
                    CAP_ORG_ROLES_MANAGE.to_string(),
                    CAP_BILLING_MANAGE.to_string(),
                    CAP_SERVICES_VIEW.to_string(),
                    CAP_SERVICES_CREATE.to_string(),
                    CAP_SERVICES_MANAGE.to_string(),
                    CAP_END_USERS_VIEW.to_string(),
                    CAP_END_USERS_MANAGE.to_string(),
                    CAP_WEBHOOKS_MANAGE.to_string(),
                    CAP_INTEGRATIONS_MANAGE.to_string(),
                    CAP_AUDIT_LOGS_VIEW.to_string(),
                    CAP_RISK_EVENTS_VIEW.to_string(),
                    CAP_RISK_POLICIES_MANAGE.to_string(),
                ])
            }
            "member" => Ok(vec![]),
            _ => {
                // Custom role
                let role =
                    OrganizationRoleStore::find_by_org_and_slug(db, org_id, &membership.role)
                        .await?;
                if let Some(role) = role {
                    if let Some(permissions) = role.permissions.as_array() {
                        let caps: Vec<String> = permissions
                            .iter()
                            .filter_map(|p| p.as_str().map(std::string::ToString::to_string))
                            .collect();
                        return Ok(caps);
                    }
                }
                Ok(vec![])
            }
        }
    }
}
