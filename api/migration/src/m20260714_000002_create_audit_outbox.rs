use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager.create_table(create_audit_outbox_table()).await?;
        manager.create_index(create_pending_index()).await?;
        manager.create_index(create_event_index()).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditOutbox::Table).to_owned())
            .await
    }
}

fn create_audit_outbox_table() -> TableCreateStatement {
    Table::create()
        .table(AuditOutbox::Table)
        .if_not_exists()
        .col(
            ColumnDef::new(AuditOutbox::Id)
                .string_len(64)
                .not_null()
                .primary_key(),
        )
        .col(
            ColumnDef::new(AuditOutbox::EventId)
                .string_len(64)
                .not_null(),
        )
        .col(
            ColumnDef::new(AuditOutbox::EventKind)
                .string_len(32)
                .not_null(),
        )
        .col(ColumnDef::new(AuditOutbox::Payload).text().not_null())
        .col(
            ColumnDef::new(AuditOutbox::Status)
                .string_len(32)
                .not_null(),
        )
        .col(ColumnDef::new(AuditOutbox::Attempts).integer().not_null())
        .col(
            ColumnDef::new(AuditOutbox::AvailableAt)
                .date_time()
                .not_null(),
        )
        .col(ColumnDef::new(AuditOutbox::LastErrorCode).text().null())
        .col(
            ColumnDef::new(AuditOutbox::CreatedAt)
                .date_time()
                .not_null(),
        )
        .col(
            ColumnDef::new(AuditOutbox::UpdatedAt)
                .date_time()
                .not_null(),
        )
        .col(
            ColumnDef::new(AuditOutbox::DeadLetteredAt)
                .date_time()
                .null(),
        )
        .to_owned()
}

fn create_pending_index() -> IndexCreateStatement {
    Index::create()
        .name("idx_audit_outbox_pending")
        .table(AuditOutbox::Table)
        .col(AuditOutbox::Status)
        .col(AuditOutbox::AvailableAt)
        .col(AuditOutbox::CreatedAt)
        .to_owned()
}

fn create_event_index() -> IndexCreateStatement {
    Index::create()
        .name("idx_audit_outbox_event")
        .table(AuditOutbox::Table)
        .col(AuditOutbox::EventKind)
        .col(AuditOutbox::EventId)
        .unique()
        .to_owned()
}

#[derive(DeriveIden)]
enum AuditOutbox {
    Table,
    Id,
    EventId,
    EventKind,
    Payload,
    Status,
    Attempts,
    AvailableAt,
    LastErrorCode,
    CreatedAt,
    UpdatedAt,
    DeadLetteredAt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm_migration::sea_query::MysqlQueryBuilder;

    #[test]
    fn mysql_indexed_columns_are_bounded_varchars() {
        let sql = create_audit_outbox_table()
            .to_string(MysqlQueryBuilder)
            .to_ascii_lowercase();
        assert!(sql.contains("`id` varchar(64)"), "{sql}");
        assert!(sql.contains("`event_id` varchar(64)"), "{sql}");
        assert!(sql.contains("`event_kind` varchar(32)"), "{sql}");
        assert!(sql.contains("`status` varchar(32)"), "{sql}");
        assert!(sql.contains("`payload` text"), "{sql}");
        assert!(sql.contains("`last_error_code` text"), "{sql}");

        let pending = create_pending_index()
            .to_string(MysqlQueryBuilder)
            .to_ascii_lowercase();
        assert!(pending.contains("(`status`, `available_at`, `created_at`)"));
        let event = create_event_index()
            .to_string(MysqlQueryBuilder)
            .to_ascii_lowercase();
        assert!(event.starts_with("create unique index"), "{event}");
        assert!(event.contains("(`event_kind`, `event_id`)"), "{event}");
    }
}
