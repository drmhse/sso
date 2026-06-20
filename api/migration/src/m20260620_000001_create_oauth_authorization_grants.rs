use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(OauthAuthorizationGrants::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(OauthAuthorizationGrants::Id)
                            .string_len(36)
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(OauthAuthorizationGrants::TokenHash)
                            .string_len(64)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OauthAuthorizationGrants::UserId)
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OauthAuthorizationGrants::ServiceId)
                            .string_len(36)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OauthAuthorizationGrants::ClientId)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OauthAuthorizationGrants::Resource)
                            .text()
                            .not_null(),
                    )
                    .col(ColumnDef::new(OauthAuthorizationGrants::Scope).text().null())
                    .col(
                        ColumnDef::new(OauthAuthorizationGrants::ExpiresAt)
                            .date_time()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(OauthAuthorizationGrants::CreatedAt)
                            .date_time()
                            .not_null()
                            .default(Expr::current_timestamp()),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_oauth_authorization_grants_user")
                            .from(
                                OauthAuthorizationGrants::Table,
                                OauthAuthorizationGrants::UserId,
                            )
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_oauth_authorization_grants_service")
                            .from(
                                OauthAuthorizationGrants::Table,
                                OauthAuthorizationGrants::ServiceId,
                            )
                            .to(Services::Table, Services::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_oauth_authorization_grants_token")
                    .table(OauthAuthorizationGrants::Table)
                    .col(OauthAuthorizationGrants::TokenHash)
                    .unique()
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_oauth_authorization_grants_expires")
                    .table(OauthAuthorizationGrants::Table)
                    .col(OauthAuthorizationGrants::ExpiresAt)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_oauth_authorization_grants_user_service")
                    .table(OauthAuthorizationGrants::Table)
                    .col(OauthAuthorizationGrants::UserId)
                    .col(OauthAuthorizationGrants::ServiceId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(
                Table::drop()
                    .table(OauthAuthorizationGrants::Table)
                    .if_exists()
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum OauthAuthorizationGrants {
    Table,
    Id,
    TokenHash,
    UserId,
    ServiceId,
    ClientId,
    Resource,
    Scope,
    ExpiresAt,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Users {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Services {
    Table,
    Id,
}
