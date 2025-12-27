use crate::entities::permissions::{
    self, Namespace, PermissionRelation, RelationTuple, SUBJECT_TYPE_USER,
};
use crate::entities::prelude::Permissions;
use crate::error::{AppError, Result};
use crate::store::DB;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use std::collections::HashSet;
use uuid::Uuid;

pub struct PermissionsStore;

impl PermissionsStore {
    /// Grant a permission (create a relation tuple)
    /// If the permission already exists, returns the existing permission
    pub async fn grant(db: DB<'_>, tuple: RelationTuple) -> Result<permissions::Model> {
        // Check if permission already exists
        let mut query = Permissions::find()
            .filter(permissions::Column::Namespace.eq(&tuple.namespace))
            .filter(permissions::Column::ObjectId.eq(&tuple.object_id))
            .filter(permissions::Column::Relation.eq(&tuple.relation))
            .filter(permissions::Column::SubjectType.eq(&tuple.subject_type))
            .filter(permissions::Column::SubjectId.eq(&tuple.subject_id));

        if let Some(ref sr) = tuple.subject_relation {
            query = query.filter(permissions::Column::SubjectRelation.eq(sr));
        } else {
            query = query.filter(permissions::Column::SubjectRelation.is_null());
        }

        if let Some(existing) = query.one(&db).await? {
            return Ok(existing);
        }

        // Permission doesn't exist, create it
        let permission = permissions::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            namespace: Set(tuple.namespace),
            object_id: Set(tuple.object_id),
            relation: Set(tuple.relation),
            subject_type: Set(tuple.subject_type),
            subject_id: Set(tuple.subject_id),
            subject_relation: Set(tuple.subject_relation),
            created_at: Set(Utc::now().naive_utc()),
        };

        let result = permission.insert(&db).await?;
        Ok(result)
    }

    /// Revoke a permission (delete a relation tuple)
    pub async fn revoke(
        db: DB<'_>,
        namespace: &str,
        object_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
        subject_relation: Option<&str>,
    ) -> Result<()> {
        let mut query = Permissions::find()
            .filter(permissions::Column::Namespace.eq(namespace))
            .filter(permissions::Column::ObjectId.eq(object_id))
            .filter(permissions::Column::Relation.eq(relation))
            .filter(permissions::Column::SubjectType.eq(subject_type))
            .filter(permissions::Column::SubjectId.eq(subject_id));

        if let Some(sr) = subject_relation {
            query = query.filter(permissions::Column::SubjectRelation.eq(sr));
        } else {
            query = query.filter(permissions::Column::SubjectRelation.is_null());
        }

        if let Some(permission) = query.one(&db).await? {
            let active: permissions::ActiveModel = permission.into();
            active.delete(&db).await?;
        }

        Ok(())
    }

    /// Check if a user has a specific permission on an object (with expansion)
    /// This is the core authorization check that implements Zanzibar's Check algorithm
    pub fn check<'a>(
        db: DB<'a>,
        namespace: &'a str,
        object_id: &'a str,
        relation: &'a str,
        user_id: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            // Initialize visited set and max depth for circular dependency prevention
            let mut visited = HashSet::new();
            Self::check_with_depth(
                db,
                namespace,
                object_id,
                relation,
                user_id,
                0,
                10,
                &mut visited,
            )
            .await
        })
    }

    /// Internal check function with depth limiting to prevent infinite recursion
    fn check_with_depth<'a>(
        db: DB<'a>,
        namespace: &'a str,
        object_id: &'a str,
        relation: &'a str,
        user_id: &'a str,
        current_depth: usize,
        max_depth: usize,
        visited: &'a mut HashSet<String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<bool>> + Send + 'a>> {
        Box::pin(async move {
            // Check depth limit
            if current_depth >= max_depth {
                tracing::warn!(
                    namespace = namespace,
                    object_id = object_id,
                    relation = relation,
                    max_depth = max_depth,
                    "Permission check exceeded max depth limit"
                );
                return Ok(false);
            }

            // Create a unique key for this check to detect cycles
            let check_key = format!("{}:{}:{}:{}", namespace, object_id, relation, user_id);

            // Prevent circular dependencies
            if visited.contains(&check_key) {
                tracing::debug!(
                    check_key = check_key.as_str(),
                    "Circular dependency detected in permission expansion"
                );
                return Ok(false);
            }
            visited.insert(check_key);

            // First, check for direct user grant
            let direct_grant = Permissions::find()
                .filter(permissions::Column::Namespace.eq(namespace))
                .filter(permissions::Column::ObjectId.eq(object_id))
                .filter(permissions::Column::Relation.eq(relation))
                .filter(permissions::Column::SubjectType.eq(SUBJECT_TYPE_USER))
                .filter(permissions::Column::SubjectId.eq(user_id))
                .one(&db)
                .await?;

            if direct_grant.is_some() {
                return Ok(true);
            }

            // Second, check for userset grants (indirect permissions)
            // Find all usersets that grant this permission
            let userset_grants = Permissions::find()
                .filter(permissions::Column::Namespace.eq(namespace))
                .filter(permissions::Column::ObjectId.eq(object_id))
                .filter(permissions::Column::Relation.eq(relation))
                .filter(permissions::Column::SubjectType.ne(SUBJECT_TYPE_USER))
                .all(&db)
                .await?;

            // For each userset, check if the user has the required relation
            for userset in userset_grants {
                let subject_relation = userset.subject_relation.as_ref().ok_or_else(|| {
                    AppError::InternalServerError(
                        "Userset grant missing subject_relation".to_string(),
                    )
                })?;

                // Recursively check with incremented depth
                let has_relation = Self::check_with_depth(
                    db.clone(),
                    &userset.subject_type,
                    &userset.subject_id,
                    subject_relation,
                    user_id,
                    current_depth + 1,
                    max_depth,
                    visited,
                )
                .await?;

                if has_relation {
                    return Ok(true);
                }
            }

            Ok(false)
        })
    }

    /// List all direct permissions for a user
    pub async fn list_user_permissions(
        db: DB<'_>,
        user_id: &str,
    ) -> Result<Vec<permissions::Model>> {
        let permissions = Permissions::find()
            .filter(permissions::Column::SubjectType.eq(SUBJECT_TYPE_USER))
            .filter(permissions::Column::SubjectId.eq(user_id))
            .all(&db)
            .await?;

        Ok(permissions)
    }

    /// List all permissions for an object
    pub async fn list_object_permissions(
        db: DB<'_>,
        namespace: &str,
        object_id: &str,
    ) -> Result<Vec<permissions::Model>> {
        let permissions = Permissions::find()
            .filter(permissions::Column::Namespace.eq(namespace))
            .filter(permissions::Column::ObjectId.eq(object_id))
            .all(&db)
            .await?;

        Ok(permissions)
    }

    /// Delete all permissions for an object (cleanup when deleting resources)
    pub async fn delete_object_permissions(
        db: DB<'_>,
        namespace: &str,
        object_id: &str,
    ) -> Result<()> {
        let permissions = Self::list_object_permissions(db.clone(), namespace, object_id).await?;

        for permission in permissions {
            let active: permissions::ActiveModel = permission.into();
            active.delete(&db).await?;
        }

        Ok(())
    }

    /// Expand a permission to get all users who have it (with userset resolution)
    /// This implements Zanzibar's Expand algorithm
    pub fn expand<'a>(
        db: DB<'a>,
        namespace: &'a str,
        object_id: &'a str,
        relation: &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<String>>> + Send + 'a>> {
        Box::pin(async move {
            let mut user_ids = HashSet::new();

            // Get all direct user grants
            let direct_grants = Permissions::find()
                .filter(permissions::Column::Namespace.eq(namespace))
                .filter(permissions::Column::ObjectId.eq(object_id))
                .filter(permissions::Column::Relation.eq(relation))
                .filter(permissions::Column::SubjectType.eq(SUBJECT_TYPE_USER))
                .all(&db)
                .await?;

            for grant in direct_grants {
                user_ids.insert(grant.subject_id);
            }

            // Get all userset grants and recursively expand them
            let userset_grants = Permissions::find()
                .filter(permissions::Column::Namespace.eq(namespace))
                .filter(permissions::Column::ObjectId.eq(object_id))
                .filter(permissions::Column::Relation.eq(relation))
                .filter(permissions::Column::SubjectType.ne(SUBJECT_TYPE_USER))
                .all(&db)
                .await?;

            for userset in userset_grants {
                let subject_relation = userset.subject_relation.as_ref().ok_or_else(|| {
                    AppError::InternalServerError(
                        "Userset grant missing subject_relation".to_string(),
                    )
                })?;

                // Recursively expand the userset
                let expanded_users = Self::expand(
                    db.clone(),
                    &userset.subject_type,
                    &userset.subject_id,
                    subject_relation,
                )
                .await?;

                user_ids.extend(expanded_users);
            }

            Ok(user_ids.into_iter().collect())
        })
    }

    /// Helper: Grant organization membership
    pub async fn grant_org_membership(
        db: DB<'_>,
        org_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<permissions::Model> {
        let tuple = RelationTuple::user(Namespace::Organization, org_id, role, user_id);
        Self::grant(db, tuple).await
    }

    /// Helper: Revoke organization membership
    pub async fn revoke_org_membership(
        db: DB<'_>,
        org_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<()> {
        Self::revoke(
            db,
            Namespace::Organization.as_str(),
            org_id,
            role,
            SUBJECT_TYPE_USER,
            user_id,
            None,
        )
        .await
    }

    /// Helper: Grant service access via organization membership
    /// Example: All members of org X can view service Y
    pub async fn grant_service_access_to_org(
        db: DB<'_>,
        service_id: &str,
        org_id: &str,
        relation: &str,
    ) -> Result<permissions::Model> {
        let tuple = RelationTuple::userset(
            Namespace::Service,
            service_id,
            relation,
            Namespace::Organization,
            org_id,
            PermissionRelation::Member,
        );
        Self::grant(db, tuple).await
    }

    /// Helper: Check if user is organization admin
    pub async fn is_org_admin(db: DB<'_>, org_id: &str, user_id: &str) -> Result<bool> {
        Self::check(
            db,
            Namespace::Organization.as_str(),
            org_id,
            PermissionRelation::Admin.as_str(),
            user_id,
        )
        .await
    }

    /// Helper: Check if user is organization owner
    pub async fn is_org_owner(db: DB<'_>, org_id: &str, user_id: &str) -> Result<bool> {
        Self::check(
            db,
            Namespace::Organization.as_str(),
            org_id,
            PermissionRelation::Owner.as_str(),
            user_id,
        )
        .await
    }

    /// Helper: Check if user is organization member
    pub async fn is_org_member(db: DB<'_>, org_id: &str, user_id: &str) -> Result<bool> {
        Self::check(
            db,
            Namespace::Organization.as_str(),
            org_id,
            PermissionRelation::Member.as_str(),
            user_id,
        )
        .await
    }

    /// Helper: Check if user has any admin role (owner or admin)
    pub async fn is_org_owner_or_admin(db: DB<'_>, org_id: &str, user_id: &str) -> Result<bool> {
        let is_owner = Self::is_org_owner(db.clone(), org_id, user_id).await?;
        if is_owner {
            return Ok(true);
        }

        let is_admin = Self::is_org_admin(db, org_id, user_id).await?;
        Ok(is_admin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relation_tuple_user() {
        let tuple = RelationTuple::user("organization", "org-123", "admin", "user-456");
        assert_eq!(tuple.namespace, "organization");
        assert_eq!(tuple.object_id, "org-123");
        assert_eq!(tuple.relation, "admin");
        assert_eq!(tuple.subject_type, SUBJECT_TYPE_USER);
        assert_eq!(tuple.subject_id, "user-456");
        assert_eq!(tuple.subject_relation, None);
    }

    #[test]
    fn test_relation_tuple_userset() {
        let tuple = RelationTuple::userset(
            "service",
            "svc-abc",
            "viewer",
            "organization",
            "org-123",
            "member",
        );
        assert_eq!(tuple.namespace, "service");
        assert_eq!(tuple.object_id, "svc-abc");
        assert_eq!(tuple.relation, "viewer");
        assert_eq!(tuple.subject_type, "organization");
        assert_eq!(tuple.subject_id, "org-123");
        assert_eq!(tuple.subject_relation, Some("member".to_string()));
    }
}
