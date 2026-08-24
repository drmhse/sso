use crate::entities::{platform_audit_log, prelude::PlatformAuditLog as PlatformAuditLogEntity};
use crate::error::Result;
use crate::store::DB;
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, QuerySelect};

pub struct PlatformAuditLogStore;

impl PlatformAuditLogStore {
    /// List audit logs with optional filters and pagination
    pub async fn list_with_filters(
        db: DB<'_>,
        action: Option<&str>,
        target_type: Option<&str>,
        target_id: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<platform_audit_log::Model>> {
        let mut query = PlatformAuditLogEntity::find();

        if let Some(action_filter) = action {
            query = query.filter(platform_audit_log::Column::Action.eq(action_filter));
        }
        if let Some(target_type_filter) = target_type {
            query = query.filter(platform_audit_log::Column::TargetType.eq(target_type_filter));
        }
        if let Some(target_id_filter) = target_id {
            query = query.filter(platform_audit_log::Column::TargetId.eq(target_id_filter));
        }

        let logs = query
            .order_by_desc(platform_audit_log::Column::CreatedAt)
            .limit(limit)
            .offset(offset)
            .all(&db)
            .await?;

        Ok(logs)
    }

    /// Count audit logs with optional filters
    pub async fn count_with_filters(
        db: DB<'_>,
        action: Option<&str>,
        target_type: Option<&str>,
        target_id: Option<&str>,
    ) -> Result<u64> {
        let mut query = PlatformAuditLogEntity::find();

        if let Some(action_filter) = action {
            query = query.filter(platform_audit_log::Column::Action.eq(action_filter));
        }
        if let Some(target_type_filter) = target_type {
            query = query.filter(platform_audit_log::Column::TargetType.eq(target_type_filter));
        }
        if let Some(target_id_filter) = target_id {
            query = query.filter(platform_audit_log::Column::TargetId.eq(target_id_filter));
        }

        let count = query.count(&db).await?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entities::platform_audit_log;
    use chrono::Utc;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::DatabaseConnection;
    use sea_orm::{ActiveModelTrait, Database, Set};
    use uuid::Uuid;

    async fn db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    async fn seed(db: &DatabaseConnection, action: &str, target_type: &str) {
        let owner = crate::store::users::UserStore::find_or_create_with_options(
            DB::Conn(db),
            "audit-owner@example.test",
            crate::store::users::UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create platform owner")
        .0;
        let entry = platform_audit_log::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            action: Set(action.to_string()),
            target_type: Set(target_type.to_string()),
            target_id: Set("t-1".to_string()),
            platform_owner_id: Set(owner.id),
            metadata: Set(None),
            created_at: Set(Utc::now().naive_utc()),
        };
        entry.insert(db).await.expect("seed audit log");
    }

    #[tokio::test]
    async fn filters_narrow_and_pagination_orders_newest_first() {
        let db = db().await;
        seed(&db, "user.promoted", "user").await;
        seed(&db, "org.suspended", "organization").await;

        let all = PlatformAuditLogStore::list_with_filters(DB::Conn(&db), None, None, None, 10, 0)
            .await
            .expect("list all");
        assert_eq!(all.len(), 2);

        let promoted = PlatformAuditLogStore::list_with_filters(
            DB::Conn(&db),
            Some("user.promoted"),
            None,
            None,
            10,
            0,
        )
        .await
        .expect("filter by action");
        assert_eq!(promoted.len(), 1);
        assert_eq!(promoted[0].action, "user.promoted");

        let by_target = PlatformAuditLogStore::list_with_filters(
            DB::Conn(&db),
            None,
            Some("organization"),
            None,
            10,
            0,
        )
        .await
        .expect("filter by target type");
        assert_eq!(by_target.len(), 1);

        // Newest first.
        assert_eq!(all[0].action, "org.suspended");

        let count = PlatformAuditLogStore::count_with_filters(DB::Conn(&db), None, None, None)
            .await
            .unwrap();
        assert_eq!(count, 2);
    }
}
