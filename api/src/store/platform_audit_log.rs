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
