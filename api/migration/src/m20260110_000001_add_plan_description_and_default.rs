use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Add description column (nullable text)
        manager
            .alter_table(
                Table::alter()
                    .table(Plans::Table)
                    .add_column(
                        ColumnDef::new(Plans::Description)
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;

        // Add is_default column (boolean, defaults to false)
        manager
            .alter_table(
                Table::alter()
                    .table(Plans::Table)
                    .add_column(
                        ColumnDef::new(Plans::IsDefault)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Plans::Table)
                    .drop_column(Plans::Description)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Plans::Table)
                    .drop_column(Plans::IsDefault)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Plans {
    Table,
    Description,
    IsDefault,
}
