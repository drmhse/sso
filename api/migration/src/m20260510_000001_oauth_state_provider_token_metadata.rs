use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(OauthStates::Table)
                    .add_column(ColumnDef::new(OauthStates::RequestedScopes).text().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(OauthStates::Table)
                    .add_column(
                        ColumnDef::new(OauthStates::ProviderTokenRequestState)
                            .string_len(36)
                            .null(),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(OauthStates::Table)
                    .drop_column(OauthStates::ProviderTokenRequestState)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(OauthStates::Table)
                    .drop_column(OauthStates::RequestedScopes)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum OauthStates {
    Table,
    RequestedScopes,
    ProviderTokenRequestState,
}
