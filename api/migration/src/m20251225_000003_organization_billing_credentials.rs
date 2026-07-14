//! Migration to add organization_billing_credentials table for BYOP (Bring Your Own Payment).
//!
//! This enables organizations to configure their own billing provider credentials
//! to charge their end-users directly.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OrganizationBillingCredentials::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::OrgId)
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::Provider)
                            .string_len(50)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::ApiKeyEncrypted)
                            .blob()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::WebhookSecretEncrypted)
                            .blob()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::EncryptionKeyId)
                            .string_len(100)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::Mode)
                            .string_len(10)
                            .not_null()
                            .default("test"),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::Enabled)
                            .boolean()
                            .not_null()
                            .default(true),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::CreatedAt)
                            .date_time()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .col(
                        ColumnDef::new(OrganizationBillingCredentials::UpdatedAt)
                            .date_time()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_org_billing_creds_org")
                            .from(
                                OrganizationBillingCredentials::Table,
                                OrganizationBillingCredentials::OrgId,
                            )
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create unique index on (org_id, provider, mode)
        // Allows one test and one live credential per provider per org
        manager
            .create_index(
                Index::create()
                    .name("idx_org_billing_creds_unique")
                    .table(OrganizationBillingCredentials::Table)
                    .col(OrganizationBillingCredentials::OrgId)
                    .col(OrganizationBillingCredentials::Provider)
                    .col(OrganizationBillingCredentials::Mode)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Create index on org_id for fast lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_org_billing_creds_org")
                    .table(OrganizationBillingCredentials::Table)
                    .col(OrganizationBillingCredentials::OrgId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The table drop removes both indexes and its foreign key atomically.
        // MySQL may otherwise reject an explicit index drop when it selected
        // that index to support the organization foreign key.
        manager
            .drop_table(
                Table::drop()
                    .table(OrganizationBillingCredentials::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum OrganizationBillingCredentials {
    Table,
    Id,
    OrgId,
    Provider,
    ApiKeyEncrypted,
    WebhookSecretEncrypted,
    EncryptionKeyId,
    Mode,
    Enabled,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
}
