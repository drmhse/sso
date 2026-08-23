#![allow(dead_code)]

use crate::entities::permissions::RelationTuple;
use crate::error::{AppError, Result};
use crate::store::permissions::PermissionsStore;
use crate::store::DB;
use sea_orm::DatabaseConnection;

/// Authorization service that provides high-level permission checking
/// Implements Zanzibar-style ReBAC (Relationship-Based Access Control)
pub struct AuthorizationService {
    db: DatabaseConnection,
}

impl AuthorizationService {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Check if a user has permission to perform an action on a resource
    pub async fn check_permission(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
        user_id: &str,
    ) -> Result<bool> {
        PermissionsStore::check(DB::Conn(&self.db), namespace, object_id, relation, user_id).await
    }

    /// Require a user to have permission (returns error if not authorized)
    pub async fn require_permission(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
        user_id: &str,
    ) -> Result<()> {
        let authorized = self
            .check_permission(namespace, object_id, relation, user_id)
            .await?;

        if !authorized {
            return Err(AppError::Forbidden(format!(
                "User {} does not have {} permission on {}:{}",
                user_id, relation, namespace, object_id
            )));
        }

        Ok(())
    }

    /// Grant a permission to a user
    pub async fn grant_user_permission(
        &self,
        namespace: impl Into<String>,
        object_id: impl Into<String>,
        relation: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Result<()> {
        let tuple = RelationTuple::user(namespace, object_id, relation, user_id);
        PermissionsStore::grant(DB::Conn(&self.db), tuple).await?;
        Ok(())
    }

    /// Revoke a permission from a user
    pub async fn revoke_user_permission(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
        user_id: &str,
    ) -> Result<()> {
        PermissionsStore::revoke(
            DB::Conn(&self.db),
            namespace,
            object_id,
            relation,
            "user",
            user_id,
            None,
        )
        .await
    }

    /// Grant a permission to all members of a group (userset)
    pub async fn grant_group_permission(
        &self,
        namespace: impl Into<String>,
        object_id: impl Into<String>,
        relation: impl Into<String>,
        group_namespace: impl Into<String>,
        group_id: impl Into<String>,
        group_relation: impl Into<String>,
    ) -> Result<()> {
        let tuple = RelationTuple::userset(
            namespace,
            object_id,
            relation,
            group_namespace,
            group_id,
            group_relation,
        );
        PermissionsStore::grant(DB::Conn(&self.db), tuple).await?;
        Ok(())
    }

    /// Get all users who have a specific permission (with expansion)
    pub async fn expand_permission(
        &self,
        namespace: &str,
        object_id: &str,
        relation: &str,
    ) -> Result<Vec<String>> {
        PermissionsStore::expand(DB::Conn(&self.db), namespace, object_id, relation).await
    }

    /// Organization-specific helpers
    ///
    /// Check if user is organization owner
    pub async fn is_org_owner(&self, org_id: &str, user_id: &str) -> Result<bool> {
        PermissionsStore::is_org_owner(DB::Conn(&self.db), org_id, user_id).await
    }

    /// Check if user is organization admin
    pub async fn is_org_admin(&self, org_id: &str, user_id: &str) -> Result<bool> {
        PermissionsStore::is_org_admin(DB::Conn(&self.db), org_id, user_id).await
    }

    /// Check if user is organization member
    pub async fn is_org_member(&self, org_id: &str, user_id: &str) -> Result<bool> {
        PermissionsStore::is_org_member(DB::Conn(&self.db), org_id, user_id).await
    }

    /// Check if user is organization owner or admin
    pub async fn is_org_owner_or_admin(&self, org_id: &str, user_id: &str) -> Result<bool> {
        PermissionsStore::is_org_owner_or_admin(DB::Conn(&self.db), org_id, user_id).await
    }

    /// Require user to be organization owner
    pub async fn require_org_owner(&self, org_id: &str, user_id: &str) -> Result<()> {
        if !self.is_org_owner(org_id, user_id).await? {
            return Err(AppError::Forbidden(format!(
                "User {} is not owner of organization {}",
                user_id, org_id
            )));
        }
        Ok(())
    }

    /// Require user to be organization admin
    pub async fn require_org_admin(&self, org_id: &str, user_id: &str) -> Result<()> {
        if !self.is_org_admin(org_id, user_id).await? {
            return Err(AppError::Forbidden(format!(
                "User {} is not admin of organization {}",
                user_id, org_id
            )));
        }
        Ok(())
    }

    /// Require user to be organization owner or admin
    pub async fn require_org_owner_or_admin(&self, org_id: &str, user_id: &str) -> Result<()> {
        if !self.is_org_owner_or_admin(org_id, user_id).await? {
            return Err(AppError::Forbidden(format!(
                "User {} is not owner or admin of organization {}",
                user_id, org_id
            )));
        }
        Ok(())
    }

    /// Require user to be organization member
    pub async fn require_org_member(&self, org_id: &str, user_id: &str) -> Result<()> {
        if !self.is_org_member(org_id, user_id).await? {
            return Err(AppError::Forbidden(format!(
                "User {} is not member of organization {}",
                user_id, org_id
            )));
        }
        Ok(())
    }

    /// Grant organization membership to a user
    pub async fn grant_org_membership(
        &self,
        org_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<()> {
        PermissionsStore::grant_org_membership(DB::Conn(&self.db), org_id, user_id, role).await?;
        Ok(())
    }

    /// Revoke organization membership from a user
    pub async fn revoke_org_membership(
        &self,
        org_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<()> {
        PermissionsStore::revoke_org_membership(DB::Conn(&self.db), org_id, user_id, role).await
    }

    /// Update organization membership role (revoke old, grant new)
    pub async fn update_org_membership_role(
        &self,
        org_id: &str,
        user_id: &str,
        old_role: &str,
        new_role: &str,
    ) -> Result<()> {
        // Revoke old role
        self.revoke_org_membership(org_id, user_id, old_role)
            .await?;

        // Grant new role
        self.grant_org_membership(org_id, user_id, new_role).await?;

        Ok(())
    }

    /// Grant service access to all members of an organization
    pub async fn grant_service_access_to_org(
        &self,
        service_id: &str,
        org_id: &str,
        relation: &str,
    ) -> Result<()> {
        PermissionsStore::grant_service_access_to_org(
            DB::Conn(&self.db),
            service_id,
            org_id,
            relation,
        )
        .await?;
        Ok(())
    }

    /// Clean up all permissions for a resource (when deleting)
    pub async fn delete_resource_permissions(
        &self,
        namespace: &str,
        object_id: &str,
    ) -> Result<()> {
        PermissionsStore::delete_object_permissions(DB::Conn(&self.db), namespace, object_id).await
    }

    /// List all permissions for a user
    pub async fn list_user_permissions(&self, user_id: &str) -> Result<Vec<PermissionSummary>> {
        let permissions =
            PermissionsStore::list_user_permissions(DB::Conn(&self.db), user_id).await?;

        Ok(permissions
            .into_iter()
            .map(|p| PermissionSummary {
                namespace: p.namespace,
                object_id: p.object_id,
                relation: p.relation,
            })
            .collect())
    }
}

/// Simplified permission summary for API responses
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PermissionSummary {
    pub namespace: String,
    pub object_id: String,
    pub relation: String,
}

impl PermissionSummary {
    /// Format as a permission string: namespace:object_id#relation
    pub fn to_string_format(&self) -> String {
        format!("{}:{}#{}", self.namespace, self.object_id, self.relation)
    }
}

/// Helper macros for common authorization patterns
#[macro_export]
macro_rules! require_org_owner {
    ($authz:expr, $org_id:expr, $user_id:expr) => {
        $authz.require_org_owner($org_id, $user_id).await?
    };
}

#[macro_export]
macro_rules! require_org_admin {
    ($authz:expr, $org_id:expr, $user_id:expr) => {
        $authz.require_org_admin($org_id, $user_id).await?
    };
}

#[macro_export]
macro_rules! require_org_owner_or_admin {
    ($authz:expr, $org_id:expr, $user_id:expr) => {
        $authz.require_org_owner_or_admin($org_id, $user_id).await?
    };
}

#[macro_export]
macro_rules! require_org_member {
    ($authz:expr, $org_id:expr, $user_id:expr) => {
        $authz.require_org_member($org_id, $user_id).await?
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::permissions::RelationTuple;
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore,
        permissions::PermissionsStore, users::UserStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    async fn db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    #[tokio::test]
    async fn grants_are_visible_to_checks_and_revocations_remove_them() {
        let db = db().await;
        let service = AuthorizationService::new(db.clone());

        assert!(
            !service
                .check_permission("organization", "org-1", "viewer", "user-1")
                .await
                .unwrap(),
            "nothing granted yet"
        );

        service
            .grant_user_permission("organization", "org-1", "viewer", "user-1")
            .await
            .expect("grant");

        assert!(service
            .check_permission("organization", "org-1", "viewer", "user-1")
            .await
            .unwrap());

        service
            .revoke_user_permission("organization", "org-1", "viewer", "user-1")
            .await
            .expect("revoke");

        assert!(
            !service
                .check_permission("organization", "org-1", "viewer", "user-1")
                .await
                .unwrap(),
            "revocation removes access"
        );
    }

    #[tokio::test]
    async fn require_permission_turns_missing_grants_into_forbidden() {
        let db = db().await;
        let service = AuthorizationService::new(db.clone());

        match service
            .require_permission("organization", "org-2", "manager", "user-2")
            .await
        {
            Err(AppError::Forbidden(message)) => {
                assert!(message.contains("does not have"), "{message}")
            }
            other => panic!("expected forbidden, got {other:?}"),
        }

        service
            .grant_user_permission("organization", "org-2", "manager", "user-2")
            .await
            .expect("grant");
        service
            .require_permission("organization", "org-2", "manager", "user-2")
            .await
            .expect("now authorised");
    }

    #[tokio::test]
    async fn org_role_helpers_reflect_real_memberships() {
        let db = db().await;
        let service = AuthorizationService::new(db.clone());

        let owner = UserStore::create(DB::Conn(&db), "authz-owner@example.test", None, false)
            .await
            .expect("create owner");
        let member = UserStore::create(DB::Conn(&db), "authz-member@example.test", None, false)
            .await
            .expect("create member");
        let outsider = UserStore::create(DB::Conn(&db), "authz-outsider@example.test", None, false)
            .await
            .expect("create outsider");

        let (org, _) =
            OrganizationStore::create_with_owner(DB::Conn(&db), "acme", "Acme", &owner.id, None)
                .await
                .expect("create org");
        MembershipStore::create(DB::Conn(&db), &org.id, &member.id, "member")
            .await
            .expect("create membership");

        // Role helpers read the Zanzibar tuples, so seed them the way the
        // permission layer expects.
        let tuple = |relation: &str, subject_id: &str| RelationTuple {
            namespace: "organization".to_string(),
            object_id: org.id.clone(),
            relation: relation.to_string(),
            subject_type: "user".to_string(),
            subject_id: subject_id.to_string(),
            subject_relation: None,
        };
        PermissionsStore::grant(DB::Conn(&db), tuple("owner", &owner.id))
            .await
            .expect("grant owner");
        PermissionsStore::grant(DB::Conn(&db), tuple("member", &member.id))
            .await
            .expect("grant member");

        assert!(service.is_org_owner(&org.id, &owner.id).await.unwrap());
        // The owner tuple does not imply the member relation in this model;
        // owners hold it separately.
        assert!(!service.is_org_member(&org.id, &owner.id).await.unwrap());
        PermissionsStore::grant(DB::Conn(&db), tuple("member", &owner.id))
            .await
            .expect("grant owner membership");
        assert!(service.is_org_member(&org.id, &owner.id).await.unwrap());
        assert!(!service.is_org_owner(&org.id, &member.id).await.unwrap());
        assert!(service.is_org_member(&org.id, &member.id).await.unwrap());
        assert!(!service.is_org_member(&org.id, &outsider.id).await.unwrap());
        assert!(!service.is_org_admin(&org.id, &member.id).await.unwrap());

        // The owner-or-admin helper accepts owners.
        assert!(service
            .is_org_owner_or_admin(&org.id, &owner.id)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn group_permissions_expand_to_members_through_usersets() {
        let db = db().await;
        let service = AuthorizationService::new(db.clone());

        // A userset grant: everyone holding `member` on `group:g1` gets
        // `viewer` on `doc:1`.
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple {
                namespace: "document".to_string(),
                object_id: "1".to_string(),
                relation: "viewer".to_string(),
                subject_type: "group".to_string(),
                subject_id: "g1".to_string(),
                subject_relation: Some("member".to_string()),
            },
        )
        .await
        .expect("grant userset");

        // No direct membership in the group yet.
        assert!(!service
            .check_permission("document", "1", "viewer", "user-9")
            .await
            .unwrap());

        // Membership in the group expands through the userset.
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple {
                namespace: "group".to_string(),
                object_id: "g1".to_string(),
                relation: "member".to_string(),
                subject_type: "user".to_string(),
                subject_id: "user-9".to_string(),
                subject_relation: None,
            },
        )
        .await
        .expect("grant group membership");

        assert!(
            service
                .check_permission("document", "1", "viewer", "user-9")
                .await
                .unwrap(),
            "userset expansion must reach the indirect member"
        );

        // Expansion reports the reachable permission.
        let expanded = service
            .expand_permission("document", "1", "viewer")
            .await
            .unwrap();
        assert!(!expanded.is_empty());
    }
}
