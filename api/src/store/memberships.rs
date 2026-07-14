use crate::entities::prelude::Memberships;
use crate::entities::{memberships, users};
use crate::error::{is_deadlock_error, AppError, Result};
use crate::store::DB;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, PaginatorTrait, QueryFilter,
    QuerySelect, Set,
};
use std::collections::HashMap;
use uuid::Uuid;

/// Combined membership and user data for listing members
#[derive(Debug, FromQueryResult)]
pub struct MemberWithUser {
    // User fields
    pub user_id: String,
    pub user_email: String,
    pub user_is_platform_owner: bool,
    pub user_created_at: chrono::NaiveDateTime,
    // Membership fields
    pub membership_id: String,
    pub membership_role: String,
    pub membership_created_at: chrono::NaiveDateTime,
}

#[derive(Debug, FromQueryResult)]
struct CountByOrg {
    org_id: String,
    count: i64,
}

pub struct MembershipStore;

impl MembershipStore {
    /// Find a membership by ID
    pub async fn find_by_id(db: DB<'_>, membership_id: &str) -> Result<Option<memberships::Model>> {
        let result = Memberships::find()
            .filter(memberships::Column::Id.eq(membership_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a membership by organization and user
    pub async fn find_by_org_and_user(
        db: DB<'_>,
        org_id: &str,
        user_id: &str,
    ) -> Result<Option<memberships::Model>> {
        let result = Memberships::find()
            .filter(memberships::Column::OrgId.eq(org_id))
            .filter(memberships::Column::UserId.eq(user_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Resolve an email through membership in one exact organization.
    ///
    /// Email is tenant-scoped, so looking up a user globally and checking the
    /// membership afterwards can bind an arbitrary platform or other-tenant
    /// row. Joining from the selected organization's membership keeps the user
    /// and membership coupled. More than one matching member is rejected rather
    /// than selecting whichever row the database happens to return first.
    pub async fn find_unique_member_with_user_by_org_and_email(
        db: DB<'_>,
        org_id: &str,
        email: &str,
    ) -> Result<Option<(memberships::Model, users::Model)>> {
        let matches = Memberships::find()
            .filter(memberships::Column::OrgId.eq(org_id))
            .find_also_related(users::Entity)
            .filter(users::Column::Email.eq(email))
            .limit(2)
            .all(&db)
            .await?;

        match matches.as_slice() {
            [] => Ok(None),
            [(membership, Some(user))] => Ok(Some((membership.clone(), user.clone()))),
            [(_, None)] => Err(AppError::InternalServerError(
                "Organization membership references a missing user".to_string(),
            )),
            _ => Err(AppError::BadRequest(
                "More than one organization member has that email".to_string(),
            )),
        }
    }

    /// Create a new membership with retry logic for SQLite busy errors
    /// If membership already exists, returns the existing one (idempotent)
    pub async fn create(
        db: DB<'_>,
        org_id: &str,
        user_id: &str,
        role: &str,
    ) -> Result<memberships::Model> {
        // First check if membership already exists (idempotent)
        if let Some(existing) = Self::find_by_org_and_user(db.clone(), org_id, user_id).await? {
            return Ok(existing);
        }

        let new_membership = memberships::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(org_id.to_string()),
            user_id: Set(user_id.to_string()),
            role: Set(role.to_string()),
            ..Default::default()
        };

        // Retry loop for SQLite busy errors
        let max_retries = 10;
        let mut attempts = 0;
        loop {
            attempts += 1;
            match new_membership.clone().insert(&db).await {
                Ok(membership) => return Ok(membership),
                Err(e) => {
                    // Check if this is a UNIQUE constraint violation (race condition)
                    let err_str = e.to_string().to_lowercase();
                    if err_str.contains("unique") || err_str.contains("constraint") {
                        // Another transaction created the membership, return it
                        if let Some(existing) =
                            Self::find_by_org_and_user(db.clone(), org_id, user_id).await?
                        {
                            return Ok(existing);
                        }
                    }

                    // Check if this is a retryable deadlock/lock error
                    if is_deadlock_error(&e) && attempts <= max_retries {
                        let base_delay_ms = 10 * (1 << attempts.min(6));
                        let jitter_ms = rand::random::<u64>() % (base_delay_ms / 2);
                        let delay_ms = base_delay_ms + jitter_ms;

                        tracing::warn!(
                            operation = "create_membership",
                            attempt = attempts,
                            max_retries = max_retries,
                            delay_ms = delay_ms,
                            "Database lock detected, retrying membership creation"
                        );

                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }

                    return Err(e.into());
                }
            }
        }
    }

    /// Update membership role
    pub async fn update_role(
        db: DB<'_>,
        membership_id: &str,
        role: &str,
    ) -> Result<memberships::Model> {
        let membership = Self::find_by_id(db.clone(), membership_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Membership not found".to_string()))?;

        let mut membership_active: memberships::ActiveModel = membership.into();
        membership_active.role = Set(role.to_string());

        let updated_membership = membership_active.update(&db).await?;
        Ok(updated_membership)
    }

    /// Delete a membership
    pub async fn delete(db: DB<'_>, membership_id: &str) -> Result<()> {
        let result = Memberships::delete_many()
            .filter(memberships::Column::Id.eq(membership_id))
            .exec(&db)
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("Membership not found".to_string()));
        }

        Ok(())
    }

    /// Delete memberships by IDs.
    pub async fn delete_by_ids(db: DB<'_>, membership_ids: &[String]) -> Result<u64> {
        if membership_ids.is_empty() {
            return Ok(0);
        }

        let result = Memberships::delete_many()
            .filter(memberships::Column::Id.is_in(membership_ids.iter().cloned()))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Delete membership by org and user
    pub async fn delete_by_org_and_user(db: DB<'_>, org_id: &str, user_id: &str) -> Result<()> {
        Memberships::delete_many()
            .filter(memberships::Column::OrgId.eq(org_id))
            .filter(memberships::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;

        Ok(())
    }

    /// List all memberships for an organization
    pub async fn list_by_org(
        db: DB<'_>,
        org_id: &str,
        role_filter: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<memberships::Model>> {
        let mut query = Memberships::find().filter(memberships::Column::OrgId.eq(org_id));

        if let Some(role) = role_filter {
            query = query.filter(memberships::Column::Role.eq(role));
        }

        let memberships = query.limit(limit).offset(offset).all(&db).await?;

        Ok(memberships)
    }

    /// Count memberships for an organization
    pub async fn count_by_org(db: DB<'_>, org_id: &str, role_filter: Option<&str>) -> Result<u64> {
        let mut query = Memberships::find().filter(memberships::Column::OrgId.eq(org_id));

        if let Some(role) = role_filter {
            query = query.filter(memberships::Column::Role.eq(role));
        }

        let count = query.count(&db).await?;
        Ok(count)
    }

    /// List all memberships for a user
    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<memberships::Model>> {
        let memberships = Memberships::find()
            .filter(memberships::Column::UserId.eq(user_id))
            .all(&db)
            .await?;

        Ok(memberships)
    }

    /// List memberships for a user within a bounded set of organizations.
    pub async fn list_by_user_and_org_ids(
        db: DB<'_>,
        user_id: &str,
        org_ids: &[String],
    ) -> Result<Vec<memberships::Model>> {
        if org_ids.is_empty() {
            return Ok(Vec::new());
        }

        let memberships = Memberships::find()
            .filter(memberships::Column::UserId.eq(user_id))
            .filter(memberships::Column::OrgId.is_in(org_ids.iter().cloned()))
            .all(&db)
            .await?;

        Ok(memberships)
    }

    /// Count memberships grouped by organization ID.
    pub async fn count_by_orgs(db: DB<'_>, org_ids: &[String]) -> Result<HashMap<String, i64>> {
        if org_ids.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = Memberships::find()
            .filter(memberships::Column::OrgId.is_in(org_ids.iter().cloned()))
            .select_only()
            .column(memberships::Column::OrgId)
            .column_as(memberships::Column::Id.count(), "count")
            .group_by(memberships::Column::OrgId)
            .into_model::<CountByOrg>()
            .all(&db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| (row.org_id, row.count))
            .collect())
    }

    /// Check if user is a member of an organization
    pub async fn is_member(db: DB<'_>, org_id: &str, user_id: &str) -> Result<bool> {
        let membership = Self::find_by_org_and_user(db, org_id, user_id).await?;
        Ok(membership.is_some())
    }

    /// Check if user has a specific role in an organization
    pub async fn has_role(
        db: DB<'_>,
        org_id: &str,
        user_id: &str,
        required_role: &str,
    ) -> Result<bool> {
        if let Some(membership) = Self::find_by_org_and_user(db, org_id, user_id).await? {
            Ok(membership.role == required_role)
        } else {
            Ok(false)
        }
    }

    /// Check if user is owner or admin
    pub async fn is_owner_or_admin(db: DB<'_>, org_id: &str, user_id: &str) -> Result<bool> {
        if let Some(membership) = Self::find_by_org_and_user(db, org_id, user_id).await? {
            Ok(membership.role == "owner" || membership.role == "admin")
        } else {
            Ok(false)
        }
    }

    /// Find membership by organization slug and user ID
    pub async fn find_by_org_slug_and_user(
        db: DB<'_>,
        org_slug: &str,
        user_id: &str,
    ) -> Result<Option<memberships::Model>> {
        use crate::entities::{organizations, prelude::Organizations};

        // First get the organization by slug
        let org = Organizations::find()
            .filter(organizations::Column::Slug.eq(org_slug))
            .one(&db)
            .await?;

        // If org exists, check for membership
        if let Some(org) = org {
            let result = Memberships::find()
                .filter(memberships::Column::OrgId.eq(org.id))
                .filter(memberships::Column::UserId.eq(user_id))
                .one(&db)
                .await?;
            Ok(result)
        } else {
            Ok(None)
        }
    }

    /// Get user's first organization slug (oldest membership)
    pub async fn get_first_org_slug(db: DB<'_>, user_id: &str) -> Result<Option<String>> {
        use crate::entities::{organizations, prelude::Organizations};
        use sea_orm::QueryOrder;

        // Get the oldest membership for this user (no JOIN needed)
        let membership = Memberships::find()
            .filter(memberships::Column::UserId.eq(user_id))
            .order_by_asc(memberships::Column::CreatedAt)
            .one(&db)
            .await?;

        if let Some(m) = membership {
            // Now get the organization slug
            let org = Organizations::find()
                .filter(organizations::Column::Id.eq(m.org_id))
                .one(&db)
                .await?;
            Ok(org.map(|o| o.slug))
        } else {
            Ok(None)
        }
    }

    /// List members with user details using JOIN
    /// Returns membership and user data combined
    pub async fn list_with_users(
        db: DB<'_>,
        org_id: &str,
        role_filter: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<MemberWithUser>> {
        use sea_orm::{JoinType, QueryOrder, QuerySelect, RelationTrait};

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 1000);
        // Get memberships with user data using a simple JOIN
        let mut query = Memberships::find()
            .join(JoinType::InnerJoin, memberships::Relation::Users.def())
            .filter(memberships::Column::OrgId.eq(org_id))
            .order_by_asc(memberships::Column::CreatedAt)
            .limit(limit)
            .offset(offset);

        if let Some(role) = role_filter {
            query = query.filter(memberships::Column::Role.eq(role));
        }

        let results = query
            .select_only()
            .column_as(users::Column::Id, "user_id")
            .column_as(users::Column::Email, "user_email")
            .column_as(users::Column::IsPlatformOwner, "user_is_platform_owner")
            .column_as(users::Column::CreatedAt, "user_created_at")
            .column_as(memberships::Column::Id, "membership_id")
            .column_as(memberships::Column::Role, "membership_role")
            .column_as(memberships::Column::CreatedAt, "membership_created_at")
            .into_model::<MemberWithUser>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// Check if an email is already a member of an organization
    pub async fn is_email_member(db: DB<'_>, org_id: &str, email: &str) -> Result<bool> {
        use sea_orm::{JoinType, QuerySelect, RelationTrait};

        let count = Memberships::find()
            .join(JoinType::InnerJoin, memberships::Relation::Users.def())
            .filter(memberships::Column::OrgId.eq(org_id))
            .filter(users::Column::Email.eq(email))
            .count(&db)
            .await?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn direct_membership_deletes_preserve_missing_row_semantics() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        assert!(matches!(
            MembershipStore::delete(DB::Conn(&db), "missing").await,
            Err(AppError::NotFound(_))
        ));
        MembershipStore::delete_by_org_and_user(DB::Conn(&db), "missing-org", "missing-user")
            .await
            .expect("missing org/user delete is a noop");
    }
}
