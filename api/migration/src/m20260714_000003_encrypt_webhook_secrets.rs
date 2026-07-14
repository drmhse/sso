use sea_orm_migration::{
    prelude::*,
    sea_orm::{ConnectionTrait, DbBackend, Statement},
};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        let binary_type = match backend {
            DbBackend::Postgres => "BYTEA",
            DbBackend::MySql | DbBackend::Sqlite => "BLOB",
        };
        for (column, sql) in [
            (
                "secret_encrypted",
                format!("ALTER TABLE webhooks ADD COLUMN secret_encrypted {binary_type} NULL"),
            ),
            (
                "encryption_key_id",
                "ALTER TABLE webhooks ADD COLUMN encryption_key_id VARCHAR(255) NULL".to_string(),
            ),
        ] {
            if manager.has_column("webhooks", column).await? {
                continue;
            }
            manager
                .get_connection()
                .execute(Statement::from_string(backend, sql))
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();
        for (column, sql) in [
            (
                "encryption_key_id",
                "ALTER TABLE webhooks DROP COLUMN encryption_key_id",
            ),
            (
                "secret_encrypted",
                "ALTER TABLE webhooks DROP COLUMN secret_encrypted",
            ),
        ] {
            if !manager.has_column("webhooks", column).await? {
                continue;
            }
            manager
                .get_connection()
                .execute(Statement::from_string(backend, sql.to_string()))
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Migrator;
    use sea_orm_migration::sea_orm::Database;

    #[tokio::test]
    async fn sqlite_up_and_down_add_exactly_the_webhook_secret_columns() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let manager = SchemaManager::new(&db);
        assert!(manager
            .has_column("webhooks", "secret_encrypted")
            .await
            .unwrap());
        assert!(manager
            .has_column("webhooks", "encryption_key_id")
            .await
            .unwrap());

        Migration.down(&manager).await.unwrap();
        assert!(!manager
            .has_column("webhooks", "secret_encrypted")
            .await
            .unwrap());
        assert!(!manager
            .has_column("webhooks", "encryption_key_id")
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn sqlite_up_resumes_after_only_the_first_column_exists() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        let manager = SchemaManager::new(&db);
        Migration.down(&manager).await.unwrap();
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "ALTER TABLE webhooks ADD COLUMN secret_encrypted BLOB NULL".to_string(),
        ))
        .await
        .unwrap();

        Migration.up(&manager).await.unwrap();
        assert!(manager
            .has_column("webhooks", "secret_encrypted")
            .await
            .unwrap());
        assert!(manager
            .has_column("webhooks", "encryption_key_id")
            .await
            .unwrap());
    }
}
