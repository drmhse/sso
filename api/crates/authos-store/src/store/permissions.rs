use crate::db::DB;
use crate::entities::permissions::{
    self, Namespace, PermissionRelation, RelationTuple, SUBJECT_TYPE_USER,
};
use crate::entities::prelude::Permissions;
use crate::error::{AppError, Result};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, Condition, EntityTrait, QueryFilter, Set};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

pub struct PermissionsStore;

fn permission_key(
    tuple: &RelationTuple,
) -> (String, String, String, String, String, Option<String>) {
    (
        tuple.namespace.clone(),
        tuple.object_id.clone(),
        tuple.relation.clone(),
        tuple.subject_type.clone(),
        tuple.subject_id.clone(),
        tuple.subject_relation.clone(),
    )
}

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

    /// Grant multiple permissions with one existence query and one insert batch.
    /// Existing tuples are skipped, matching `grant` idempotency.
    pub async fn grant_many(db: DB<'_>, tuples: Vec<RelationTuple>) -> Result<()> {
        if tuples.is_empty() {
            return Ok(());
        }

        let mut unique_tuples = Vec::with_capacity(tuples.len());
        let mut requested_keys = HashSet::new();
        for tuple in tuples {
            let key = permission_key(&tuple);
            if requested_keys.insert(key) {
                unique_tuples.push(tuple);
            }
        }

        let mut existing_condition = Condition::any();
        for tuple in &unique_tuples {
            let mut tuple_condition = Condition::all()
                .add(permissions::Column::Namespace.eq(&tuple.namespace))
                .add(permissions::Column::ObjectId.eq(&tuple.object_id))
                .add(permissions::Column::Relation.eq(&tuple.relation))
                .add(permissions::Column::SubjectType.eq(&tuple.subject_type))
                .add(permissions::Column::SubjectId.eq(&tuple.subject_id));

            tuple_condition = if let Some(subject_relation) = &tuple.subject_relation {
                tuple_condition.add(permissions::Column::SubjectRelation.eq(subject_relation))
            } else {
                tuple_condition.add(permissions::Column::SubjectRelation.is_null())
            };

            existing_condition = existing_condition.add(tuple_condition);
        }

        let existing_keys = Permissions::find()
            .filter(existing_condition)
            .all(&db)
            .await?
            .into_iter()
            .map(|permission| {
                (
                    permission.namespace,
                    permission.object_id,
                    permission.relation,
                    permission.subject_type,
                    permission.subject_id,
                    permission.subject_relation,
                )
            })
            .collect::<HashSet<_>>();

        let now = Utc::now().naive_utc();
        let new_permissions = unique_tuples
            .into_iter()
            .filter(|tuple| !existing_keys.contains(&permission_key(tuple)))
            .map(|tuple| permissions::ActiveModel {
                id: Set(Uuid::new_v4().to_string()),
                namespace: Set(tuple.namespace),
                object_id: Set(tuple.object_id),
                relation: Set(tuple.relation),
                subject_type: Set(tuple.subject_type),
                subject_id: Set(tuple.subject_id),
                subject_relation: Set(tuple.subject_relation),
                created_at: Set(now),
            })
            .collect::<Vec<_>>();

        if !new_permissions.is_empty() {
            Permissions::insert_many(new_permissions).exec(&db).await?;
        }

        Ok(())
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
        let mut delete = Permissions::delete_many()
            .filter(permissions::Column::Namespace.eq(namespace))
            .filter(permissions::Column::ObjectId.eq(object_id))
            .filter(permissions::Column::Relation.eq(relation))
            .filter(permissions::Column::SubjectType.eq(subject_type))
            .filter(permissions::Column::SubjectId.eq(subject_id));

        if let Some(sr) = subject_relation {
            delete = delete.filter(permissions::Column::SubjectRelation.eq(sr));
        } else {
            delete = delete.filter(permissions::Column::SubjectRelation.is_null());
        }

        delete.exec(&db).await?;

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
    #[allow(clippy::too_many_arguments)]
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

    /// List direct service grants for a user across many service IDs.
    pub async fn list_direct_service_access_for_user(
        db: DB<'_>,
        service_ids: &[String],
        user_id: &str,
    ) -> Result<HashMap<String, String>> {
        if service_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let grants = Permissions::find()
            .filter(permissions::Column::Namespace.eq(Namespace::Service.as_str()))
            .filter(permissions::Column::ObjectId.is_in(service_ids.iter().cloned()))
            .filter(permissions::Column::Relation.is_in([
                PermissionRelation::Viewer.as_str(),
                PermissionRelation::Manager.as_str(),
            ]))
            .filter(permissions::Column::SubjectType.eq(SUBJECT_TYPE_USER))
            .filter(permissions::Column::SubjectId.eq(user_id))
            .filter(permissions::Column::SubjectRelation.is_null())
            .all(&db)
            .await?;

        let mut access_by_service = HashMap::new();
        for grant in grants {
            let existing = access_by_service.get(&grant.object_id);
            if existing.is_none() || grant.relation == PermissionRelation::Manager.as_str() {
                access_by_service.insert(grant.object_id, grant.relation);
            }
        }

        Ok(access_by_service)
    }

    /// List direct and userset-expanded service grants for a user across many service IDs.
    pub async fn list_service_access_for_user(
        db: DB<'_>,
        service_ids: &[String],
        user_id: &str,
    ) -> Result<HashMap<String, String>> {
        if service_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let grants = Permissions::find()
            .filter(permissions::Column::Namespace.eq(Namespace::Service.as_str()))
            .filter(permissions::Column::ObjectId.is_in(service_ids.iter().cloned()))
            .filter(permissions::Column::Relation.is_in([
                PermissionRelation::Viewer.as_str(),
                PermissionRelation::Manager.as_str(),
            ]))
            .filter(
                Condition::any()
                    .add(
                        Condition::all()
                            .add(permissions::Column::SubjectType.eq(SUBJECT_TYPE_USER))
                            .add(permissions::Column::SubjectId.eq(user_id))
                            .add(permissions::Column::SubjectRelation.is_null()),
                    )
                    .add(permissions::Column::SubjectType.ne(SUBJECT_TYPE_USER)),
            )
            .all(&db)
            .await?;

        let mut access_by_service = HashMap::new();
        let mut userset_checks = HashMap::new();

        for grant in &grants {
            if grant.subject_type == SUBJECT_TYPE_USER {
                Self::record_best_service_access(
                    &mut access_by_service,
                    &grant.object_id,
                    &grant.relation,
                );
                continue;
            }

            let subject_relation = grant.subject_relation.as_ref().ok_or_else(|| {
                AppError::InternalServerError("Userset grant missing subject_relation".to_string())
            })?;

            userset_checks
                .entry((
                    grant.subject_type.clone(),
                    grant.subject_id.clone(),
                    subject_relation.clone(),
                ))
                .or_insert(None);
        }

        for ((subject_type, subject_id, subject_relation), has_access) in &mut userset_checks {
            *has_access = Some(
                Self::check(
                    db.clone(),
                    subject_type,
                    subject_id,
                    subject_relation,
                    user_id,
                )
                .await?,
            );
        }

        for grant in grants {
            if grant.subject_type == SUBJECT_TYPE_USER {
                continue;
            }

            let Some(subject_relation) = grant.subject_relation.as_ref() else {
                continue;
            };
            let userset_key = (
                grant.subject_type.clone(),
                grant.subject_id.clone(),
                subject_relation.clone(),
            );

            if userset_checks
                .get(&userset_key)
                .copied()
                .flatten()
                .unwrap_or(false)
            {
                Self::record_best_service_access(
                    &mut access_by_service,
                    &grant.object_id,
                    &grant.relation,
                );
            }
        }

        Ok(access_by_service)
    }

    fn record_best_service_access(
        access_by_service: &mut HashMap<String, String>,
        service_id: &str,
        relation: &str,
    ) {
        let existing = access_by_service.get(service_id);
        if existing.is_none() || relation == PermissionRelation::Manager.as_str() {
            access_by_service.insert(service_id.to_string(), relation.to_string());
        }
    }

    /// Revoke direct viewer/manager service grants for a user across many service IDs.
    pub async fn revoke_direct_service_access_for_user(
        db: DB<'_>,
        service_ids: &[String],
        user_id: &str,
    ) -> Result<()> {
        if service_ids.is_empty() {
            return Ok(());
        }

        Permissions::delete_many()
            .filter(permissions::Column::Namespace.eq(Namespace::Service.as_str()))
            .filter(permissions::Column::ObjectId.is_in(service_ids.iter().cloned()))
            .filter(permissions::Column::Relation.is_in([
                PermissionRelation::Viewer.as_str(),
                PermissionRelation::Manager.as_str(),
            ]))
            .filter(permissions::Column::SubjectType.eq(SUBJECT_TYPE_USER))
            .filter(permissions::Column::SubjectId.eq(user_id))
            .filter(permissions::Column::SubjectRelation.is_null())
            .exec(&db)
            .await?;

        Ok(())
    }

    /// Revoke direct organization permissions for a bounded set of users and roles.
    pub async fn revoke_direct_org_memberships_for_users(
        db: DB<'_>,
        org_id: &str,
        user_ids: &[String],
        roles: &[String],
    ) -> Result<()> {
        if user_ids.is_empty() || roles.is_empty() {
            return Ok(());
        }

        Permissions::delete_many()
            .filter(permissions::Column::Namespace.eq(Namespace::Organization.as_str()))
            .filter(permissions::Column::ObjectId.eq(org_id))
            .filter(permissions::Column::Relation.is_in(roles.iter().cloned()))
            .filter(permissions::Column::SubjectType.eq(SUBJECT_TYPE_USER))
            .filter(permissions::Column::SubjectId.is_in(user_ids.iter().cloned()))
            .filter(permissions::Column::SubjectRelation.is_null())
            .exec(&db)
            .await?;

        Ok(())
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
        Permissions::delete_many()
            .filter(permissions::Column::Namespace.eq(namespace))
            .filter(permissions::Column::ObjectId.eq(object_id))
            .exec(&db)
            .await?;

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
    use crate::db::DB;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

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

    #[tokio::test]
    async fn grant_many_deduplicates_existing_direct_and_userset_tuples() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::user("organization", "org-1", "member", "user-1"),
        )
        .await
        .expect("grant existing direct tuple");

        PermissionsStore::grant_many(
            DB::Conn(&db),
            vec![
                RelationTuple::user("organization", "org-1", "member", "user-1"),
                RelationTuple::user("organization", "org-1", "member", "user-1"),
                RelationTuple::user("organization", "org-1", "admin", "user-1"),
                RelationTuple::userset(
                    "service",
                    "svc-1",
                    "viewer",
                    "organization",
                    "org-1",
                    "member",
                ),
                RelationTuple::userset(
                    "service",
                    "svc-1",
                    "viewer",
                    "organization",
                    "org-1",
                    "member",
                ),
            ],
        )
        .await
        .expect("grant many");

        let org_permissions =
            PermissionsStore::list_object_permissions(DB::Conn(&db), "organization", "org-1")
                .await
                .expect("list organization permissions");
        let service_permissions =
            PermissionsStore::list_object_permissions(DB::Conn(&db), "service", "svc-1")
                .await
                .expect("list service permissions");

        assert_eq!(org_permissions.len(), 2);
        assert_eq!(service_permissions.len(), 1);
        assert!(PermissionsStore::check(
            DB::Conn(&db),
            "organization",
            "org-1",
            "member",
            "user-1"
        )
        .await
        .expect("member permission exists"));
        assert!(
            PermissionsStore::check(DB::Conn(&db), "organization", "org-1", "admin", "user-1")
                .await
                .expect("admin permission exists")
        );
        assert!(
            PermissionsStore::check(DB::Conn(&db), "service", "svc-1", "viewer", "user-1")
                .await
                .expect("userset permission expands")
        );
    }

    #[tokio::test]
    async fn list_direct_service_access_batches_and_prefers_manager() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::user("service", "svc-1", "viewer", "user-1"),
        )
        .await
        .expect("grant viewer");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::user("service", "svc-2", "viewer", "user-1"),
        )
        .await
        .expect("grant viewer before manager");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::user("service", "svc-2", "manager", "user-1"),
        )
        .await
        .expect("grant manager");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::userset(
                "service",
                "svc-3",
                "viewer",
                "organization",
                "org-1",
                "member",
            ),
        )
        .await
        .expect("grant userset");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::user("service", "svc-4", "viewer", "user-2"),
        )
        .await
        .expect("grant other user");

        let service_ids = ["svc-1", "svc-2", "svc-3", "svc-4"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        let access = PermissionsStore::list_direct_service_access_for_user(
            DB::Conn(&db),
            &service_ids,
            "user-1",
        )
        .await
        .expect("list direct access");

        assert_eq!(access.len(), 2);
        assert_eq!(access.get("svc-1"), Some(&"viewer".to_string()));
        assert_eq!(access.get("svc-2"), Some(&"manager".to_string()));
        assert!(!access.contains_key("svc-3"));
        assert!(!access.contains_key("svc-4"));

        PermissionsStore::revoke_direct_service_access_for_user(
            DB::Conn(&db),
            &[
                "svc-1".to_string(),
                "svc-2".to_string(),
                "svc-3".to_string(),
            ],
            "user-1",
        )
        .await
        .expect("bulk revoke direct access");

        let access = PermissionsStore::list_direct_service_access_for_user(
            DB::Conn(&db),
            &service_ids,
            "user-1",
        )
        .await
        .expect("list after revoke");
        assert!(access.is_empty());

        let svc_3_permissions =
            PermissionsStore::list_object_permissions(DB::Conn(&db), "service", "svc-3")
                .await
                .expect("userset grant still exists");
        assert_eq!(svc_3_permissions.len(), 1);
        assert_eq!(svc_3_permissions[0].subject_type, "organization");
        assert!(
            PermissionsStore::check(DB::Conn(&db), "service", "svc-4", "viewer", "user-2")
                .await
                .expect("other user's direct grant still exists")
        );
    }

    #[tokio::test]
    async fn list_service_access_batches_direct_and_userset_grants() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::user("organization", "org-1", "member", "user-1"),
        )
        .await
        .expect("grant org membership");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::user("service", "svc-1", "viewer", "user-1"),
        )
        .await
        .expect("grant direct service viewer");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::userset(
                "service",
                "svc-2",
                "viewer",
                "organization",
                "org-1",
                "member",
            ),
        )
        .await
        .expect("grant userset service viewer");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::userset(
                "service",
                "svc-3",
                "manager",
                "organization",
                "org-2",
                "member",
            ),
        )
        .await
        .expect("grant inaccessible userset manager");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::userset(
                "service",
                "svc-4",
                "viewer",
                "organization",
                "org-1",
                "member",
            ),
        )
        .await
        .expect("grant viewer before manager userset");
        PermissionsStore::grant(
            DB::Conn(&db),
            RelationTuple::userset(
                "service",
                "svc-4",
                "manager",
                "organization",
                "org-1",
                "member",
            ),
        )
        .await
        .expect("grant manager userset");

        let service_ids = ["svc-1", "svc-2", "svc-3", "svc-4"]
            .into_iter()
            .map(String::from)
            .collect::<Vec<_>>();
        let access =
            PermissionsStore::list_service_access_for_user(DB::Conn(&db), &service_ids, "user-1")
                .await
                .expect("list expanded service access");

        assert_eq!(access.len(), 3);
        assert_eq!(access.get("svc-1"), Some(&"viewer".to_string()));
        assert_eq!(access.get("svc-2"), Some(&"viewer".to_string()));
        assert_eq!(access.get("svc-4"), Some(&"manager".to_string()));
        assert!(!access.contains_key("svc-3"));
    }
}
