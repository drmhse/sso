//! `SeaORM` Entity for ReBAC permissions table

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "permissions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, column_type = "Text")]
    pub id: String,
    /// Resource type: organization, service, plan, webhook, api_key, etc.
    #[sea_orm(column_type = "Text")]
    pub namespace: String,
    /// ID of the specific resource instance
    #[sea_orm(column_type = "Text")]
    pub object_id: String,
    /// Permission type: owner, admin, member, viewer, editor, etc.
    #[sea_orm(column_type = "Text")]
    pub relation: String,
    /// Type of subject: 'user' for direct grants, or namespace for usersets
    #[sea_orm(column_type = "Text")]
    pub subject_type: String,
    /// User ID or object ID for userset relations
    #[sea_orm(column_type = "Text")]
    pub subject_id: String,
    /// Relation for usersets (e.g., 'member', 'admin'), null for direct user grants
    #[sea_orm(column_type = "Text", nullable)]
    pub subject_relation: Option<String>,
    pub created_at: DateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Resource namespace types for ReBAC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    Organization,
    Service,
    Plan,
    Webhook,
    ApiKey,
    User,
}

impl Namespace {
    pub fn as_str(&self) -> &'static str {
        match self {
            Namespace::Organization => "organization",
            Namespace::Service => "service",
            Namespace::Plan => "plan",
            Namespace::Webhook => "webhook",
            Namespace::ApiKey => "api_key",
            Namespace::User => "user",
        }
    }
}

impl From<Namespace> for String {
    fn from(ns: Namespace) -> Self {
        ns.as_str().to_string()
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Permission relation types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionRelation {
    Owner,
    Admin,
    Member,
    Viewer,
    Editor,
    Manager,
}

impl PermissionRelation {
    pub fn as_str(&self) -> &'static str {
        match self {
            PermissionRelation::Owner => "owner",
            PermissionRelation::Admin => "admin",
            PermissionRelation::Member => "member",
            PermissionRelation::Viewer => "viewer",
            PermissionRelation::Editor => "editor",
            PermissionRelation::Manager => "manager",
        }
    }
}

impl From<PermissionRelation> for String {
    fn from(rel: PermissionRelation) -> Self {
        rel.as_str().to_string()
    }
}

impl std::fmt::Display for PermissionRelation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Subject types for relation tuples
pub const SUBJECT_TYPE_USER: &str = "user";

/// Helper struct to represent a relation tuple in a type-safe way
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelationTuple {
    pub namespace: String,
    pub object_id: String,
    pub relation: String,
    pub subject_type: String,
    pub subject_id: String,
    pub subject_relation: Option<String>,
}

impl RelationTuple {
    /// Create a direct user permission: object#relation@user:user_id
    pub fn user(
        namespace: impl Into<String>,
        object_id: impl Into<String>,
        relation: impl Into<String>,
        user_id: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            object_id: object_id.into(),
            relation: relation.into(),
            subject_type: SUBJECT_TYPE_USER.to_string(),
            subject_id: user_id.into(),
            subject_relation: None,
        }
    }

    /// Create a userset permission: object#relation@subject_namespace:subject_id#subject_relation
    /// Example: service:abc#viewer@organization:123#member
    #[allow(dead_code)]
    pub fn userset(
        namespace: impl Into<String>,
        object_id: impl Into<String>,
        relation: impl Into<String>,
        subject_namespace: impl Into<String>,
        subject_id: impl Into<String>,
        subject_relation: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            object_id: object_id.into(),
            relation: relation.into(),
            subject_type: subject_namespace.into(),
            subject_id: subject_id.into(),
            subject_relation: Some(subject_relation.into()),
        }
    }

    /// Format as a Zanzibar-style tuple string: object#relation@subject
    #[allow(dead_code)]
    pub fn to_string_format(&self) -> String {
        let object = format!("{}:{}", self.namespace, self.object_id);
        let subject = if let Some(ref rel) = self.subject_relation {
            format!("{}:{}#{}", self.subject_type, self.subject_id, rel)
        } else {
            format!("{}:{}", self.subject_type, self.subject_id)
        };
        format!("{}#{}@{}", object, self.relation, subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_relation_tuple() {
        let tuple = RelationTuple::user("organization", "123", "admin", "user-456");
        assert_eq!(tuple.namespace, "organization");
        assert_eq!(tuple.object_id, "123");
        assert_eq!(tuple.relation, "admin");
        assert_eq!(tuple.subject_type, "user");
        assert_eq!(tuple.subject_id, "user-456");
        assert_eq!(tuple.subject_relation, None);
        assert_eq!(
            tuple.to_string_format(),
            "organization:123#admin@user:user-456"
        );
    }

    #[test]
    fn test_userset_relation_tuple() {
        let tuple =
            RelationTuple::userset("service", "abc", "viewer", "organization", "123", "member");
        assert_eq!(tuple.namespace, "service");
        assert_eq!(tuple.object_id, "abc");
        assert_eq!(tuple.relation, "viewer");
        assert_eq!(tuple.subject_type, "organization");
        assert_eq!(tuple.subject_id, "123");
        assert_eq!(tuple.subject_relation, Some("member".to_string()));
        assert_eq!(
            tuple.to_string_format(),
            "service:abc#viewer@organization:123#member"
        );
    }

    #[test]
    fn test_namespace_enum() {
        assert_eq!(Namespace::Organization.as_str(), "organization");
        assert_eq!(Namespace::Service.as_str(), "service");
        assert_eq!(Namespace::Plan.as_str(), "plan");
    }

    #[test]
    fn test_permission_relation_enum() {
        assert_eq!(PermissionRelation::Owner.as_str(), "owner");
        assert_eq!(PermissionRelation::Admin.as_str(), "admin");
        assert_eq!(PermissionRelation::Member.as_str(), "member");
    }
}
