use sea_orm_migration::prelude::*;

const LIFECYCLE_INDEX: &str = "idx_saml_keys_service_lifecycle";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if !manager
            .has_column("saml_signing_keys", "publish_until")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(SamlSigningKeys::Table)
                        .add_column(
                            ColumnDef::new(SamlSigningKeys::PublishUntil)
                                .date_time()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }
        if !manager
            .has_column("saml_signing_keys", "retired_at")
            .await?
        {
            manager
                .alter_table(
                    Table::alter()
                        .table(SamlSigningKeys::Table)
                        .add_column(
                            ColumnDef::new(SamlSigningKeys::RetiredAt)
                                .date_time()
                                .null(),
                        )
                        .to_owned(),
                )
                .await?;
        }

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(LIFECYCLE_INDEX)
                    .table(SamlSigningKeys::Table)
                    .col(SamlSigningKeys::ServiceId)
                    .col(SamlSigningKeys::IsActive)
                    .col(SamlSigningKeys::RetiredAt)
                    .col(SamlSigningKeys::PublishUntil)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name(LIFECYCLE_INDEX)
                    .table(SamlSigningKeys::Table)
                    .to_owned(),
            )
            .await?;

        for (name, column) in [
            ("retired_at", SamlSigningKeys::RetiredAt),
            ("publish_until", SamlSigningKeys::PublishUntil),
        ] {
            if manager.has_column("saml_signing_keys", name).await? {
                manager
                    .alter_table(
                        Table::alter()
                            .table(SamlSigningKeys::Table)
                            .drop_column(column)
                            .to_owned(),
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

#[derive(DeriveIden, Copy, Clone)]
enum SamlSigningKeys {
    Table,
    ServiceId,
    IsActive,
    PublishUntil,
    RetiredAt,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Migrator;
    use sea_orm_migration::sea_orm::Database;

    #[tokio::test]
    async fn sqlite_up_and_down_add_exactly_the_saml_lifecycle_columns() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let manager = SchemaManager::new(&db);
        assert!(manager
            .has_column("saml_signing_keys", "publish_until")
            .await
            .unwrap());
        assert!(manager
            .has_column("saml_signing_keys", "retired_at")
            .await
            .unwrap());

        Migration.down(&manager).await.unwrap();
        assert!(!manager
            .has_column("saml_signing_keys", "publish_until")
            .await
            .unwrap());
        assert!(!manager
            .has_column("saml_signing_keys", "retired_at")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn sqlite_up_resumes_after_only_the_first_column_exists() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let manager = SchemaManager::new(&db);
        Migration.down(&manager).await.unwrap();
        manager
            .alter_table(
                Table::alter()
                    .table(SamlSigningKeys::Table)
                    .add_column(
                        ColumnDef::new(SamlSigningKeys::PublishUntil)
                            .date_time()
                            .null(),
                    )
                    .to_owned(),
            )
            .await
            .unwrap();

        Migration.up(&manager).await.unwrap();
        assert!(manager
            .has_column("saml_signing_keys", "publish_until")
            .await
            .unwrap());
        assert!(manager
            .has_column("saml_signing_keys", "retired_at")
            .await
            .unwrap());
    }
}
