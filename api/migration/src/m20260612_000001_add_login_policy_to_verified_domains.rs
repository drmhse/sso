use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager
            .has_column("verified_domains", "login_policy")
            .await?
        {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(VerifiedDomains::Table)
                    .add_column(
                        ColumnDef::new(VerifiedDomains::LoginPolicy)
                            .string()
                            .not_null()
                            .default("password_allowed"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager
            .has_column("verified_domains", "login_policy")
            .await?
        {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(VerifiedDomains::Table)
                    .drop_column(VerifiedDomains::LoginPolicy)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum VerifiedDomains {
    Table,
    LoginPolicy,
}
