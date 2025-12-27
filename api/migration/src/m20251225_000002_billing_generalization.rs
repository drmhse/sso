//! Migration to generalize billing from Stripe-specific to provider-agnostic.
//!
//! Changes:
//! - Renames `stripe_customers` table to `billing_customers`
//! - Renames `stripe_customer_id` column to `external_customer_id`
//! - Adds `provider` column to track which billing provider (stripe, polar, etc.)
//! - Adds `external_mapping` JSON column to `organization_tiers` for multi-provider pricing IDs

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Step 1: Create new billing_customers table with generalized schema
        manager
            .create_table(
                Table::create()
                    .table(BillingCustomers::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(BillingCustomers::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(BillingCustomers::OrgId)
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingCustomers::Provider)
                            .string_len(50)
                            .not_null()
                            .default("stripe"),
                    )
                    .col(
                        ColumnDef::new(BillingCustomers::ExternalCustomerId)
                            .string_len(191)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(BillingCustomers::CreatedAt)
                            .date_time()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_billing_customers_org")
                            .from(BillingCustomers::Table, BillingCustomers::OrgId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create unique index on org_id + provider (an org can have one customer per provider)
        manager
            .create_index(
                Index::create()
                    .name("idx_billing_customers_org_provider")
                    .table(BillingCustomers::Table)
                    .col(BillingCustomers::OrgId)
                    .col(BillingCustomers::Provider)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // Create index on external_customer_id for webhook lookups
        manager
            .create_index(
                Index::create()
                    .name("idx_billing_customers_external_id")
                    .table(BillingCustomers::Table)
                    .col(BillingCustomers::ExternalCustomerId)
                    .to_owned(),
            )
            .await?;

        // Step 2: Migrate data from stripe_customers to billing_customers
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            INSERT INTO billing_customers (id, org_id, provider, external_customer_id, created_at)
            SELECT id, org_id, 'stripe', stripe_customer_id, CURRENT_TIMESTAMP
            FROM stripe_customers
            "#,
        )
        .await?;

        // Step 3: Drop old stripe_customers table
        manager
            .drop_table(Table::drop().table(StripeCustomers::Table).to_owned())
            .await?;

        // Step 4: Add external_mapping to organization_tiers
        manager
            .alter_table(
                Table::alter()
                    .table(OrganizationTiers::Table)
                    .add_column(ColumnDef::new(OrganizationTiers::ExternalMapping).text().null())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Step 1: Remove external_mapping from organization_tiers
        manager
            .alter_table(
                Table::alter()
                    .table(OrganizationTiers::Table)
                    .drop_column(OrganizationTiers::ExternalMapping)
                    .to_owned(),
            )
            .await?;

        // Step 2: Recreate stripe_customers table
        manager
            .create_table(
                Table::create()
                    .table(StripeCustomers::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(StripeCustomers::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(StripeCustomers::OrgId)
                            .string_len(36)
                            .not_null()
                            .unique_key(),
                    )
                    .col(
                        ColumnDef::new(StripeCustomers::StripeCustomerId)
                            .string_len(191)
                            .not_null()
                            .unique_key(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_stripe_customers_org")
                            .from(StripeCustomers::Table, StripeCustomers::OrgId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Step 3: Migrate data back (only stripe provider)
        let db = manager.get_connection();
        db.execute_unprepared(
            r#"
            INSERT INTO stripe_customers (id, org_id, stripe_customer_id)
            SELECT id, org_id, external_customer_id
            FROM billing_customers
            WHERE provider = 'stripe'
            "#,
        )
        .await?;

        // Step 4: Drop billing_customers table and its indexes
        manager
            .drop_index(
                Index::drop()
                    .name("idx_billing_customers_external_id")
                    .table(BillingCustomers::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_billing_customers_org_provider")
                    .table(BillingCustomers::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_table(Table::drop().table(BillingCustomers::Table).to_owned())
            .await?;

        Ok(())
    }
}

#[derive(DeriveIden)]
enum BillingCustomers {
    Table,
    Id,
    OrgId,
    Provider,
    ExternalCustomerId,
    CreatedAt,
}

#[derive(DeriveIden)]
enum StripeCustomers {
    Table,
    Id,
    OrgId,
    StripeCustomerId,
}

#[derive(DeriveIden)]
enum OrganizationTiers {
    Table,
    ExternalMapping,
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
}
