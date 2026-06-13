use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_column("oauth_states", "resource").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(OauthStates::Table)
                        .add_column(ColumnDef::new(OauthStates::Resource).text().null())
                        .to_owned(),
                )
                .await?;
        }

        if !manager.has_column("sessions", "resource").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Sessions::Table)
                        .add_column(ColumnDef::new(Sessions::Resource).text().null())
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.has_column("sessions", "resource").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Sessions::Table)
                        .drop_column(Sessions::Resource)
                        .to_owned(),
                )
                .await?;
        }

        if manager.has_column("oauth_states", "resource").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(OauthStates::Table)
                        .drop_column(OauthStates::Resource)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}

#[derive(DeriveIden)]
enum OauthStates {
    Table,
    Resource,
}

#[derive(DeriveIden)]
enum Sessions {
    Table,
    Resource,
}
