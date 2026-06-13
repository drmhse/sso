use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.has_column("services", "resource_uris").await? {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Services::Table)
                    .add_column(ColumnDef::new(Services::ResourceUris).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager.has_column("services", "resource_uris").await? {
            return Ok(());
        }

        manager
            .alter_table(
                Table::alter()
                    .table(Services::Table)
                    .drop_column(Services::ResourceUris)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Services {
    Table,
    ResourceUris,
}
