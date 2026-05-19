use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OrganizationRoles::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OrganizationRoles::Id)
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(OrganizationRoles::OrgId).string().not_null())
                    .col(ColumnDef::new(OrganizationRoles::Slug).string().not_null())
                    .col(ColumnDef::new(OrganizationRoles::Name).string().not_null())
                    .col(ColumnDef::new(OrganizationRoles::Description).string())
                    .col(ColumnDef::new(OrganizationRoles::Permissions).json().not_null())
                    .col(
                        ColumnDef::new(OrganizationRoles::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OrganizationRoles::UpdatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-organization_roles-org_id")
                            .from(OrganizationRoles::Table, OrganizationRoles::OrgId)
                            .to(Organizations::Table, Organizations::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create composite index on org_id and slug to ensure uniqueness per org
        manager
            .create_index(
                Index::create()
                    .name("idx-organization_roles-org_id-slug")
                    .table(OrganizationRoles::Table)
                    .col(OrganizationRoles::OrgId)
                    .col(OrganizationRoles::Slug)
                    .unique()
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OrganizationRoles::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum OrganizationRoles {
    Table,
    Id,
    OrgId,
    Slug,
    Name,
    Description,
    Permissions,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
}
