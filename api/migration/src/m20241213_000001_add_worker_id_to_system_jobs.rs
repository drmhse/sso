//! Migration to add worker_id column to system_jobs table
//! This enables atomic job claiming with worker identification for auditability

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add worker_id column to system_jobs table
        // This column tracks which worker claimed the job for debugging and auditing
        manager
            .alter_table(
                Table::alter()
                    .table(SystemJobs::Table)
                    .add_column(
                        ColumnDef::new(SystemJobs::WorkerId)
                            .string()
                            .null()
                            .to_owned(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add index on status and scheduled_for for efficient job claiming
        manager
            .create_index(
                Index::create()
                    .name("idx_system_jobs_claim")
                    .table(SystemJobs::Table)
                    .col(SystemJobs::Status)
                    .col(SystemJobs::ScheduledFor)
                    .col(SystemJobs::Priority)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Remove the index
        manager
            .drop_index(
                Index::drop()
                    .name("idx_system_jobs_claim")
                    .table(SystemJobs::Table)
                    .to_owned(),
            )
            .await?;

        // Remove the worker_id column
        manager
            .alter_table(
                Table::alter()
                    .table(SystemJobs::Table)
                    .drop_column(SystemJobs::WorkerId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum SystemJobs {
    Table,
    WorkerId,
    Status,
    ScheduledFor,
    Priority,
}
