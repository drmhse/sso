use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        if manager.get_database_backend() != DbBackend::Sqlite {
            return Ok(());
        }

        #[cfg(not(feature = "db_sqlite"))]
        return Err(DbErr::Custom(
            "SQLite user-scope repair requires the db_sqlite migration feature".to_string(),
        ));

        #[cfg(feature = "db_sqlite")]
        {
            let SchemaManagerConnection::Connection(database) = manager.get_connection() else {
                return Err(DbErr::Custom(
                    "SQLite user-scope repair requires a direct migration connection".to_string(),
                ));
            };
            let mut connection = database
                .get_sqlite_connection_pool()
                .acquire()
                .await
                .map_err(|error| {
                    DbErr::Custom(format!("acquire SQLite migration connection: {error}"))
                })?;

            // The original schema declared `users.email` inline UNIQUE. SQLite
            // represents that as an auto-index which cannot be dropped. Rebuild on
            // one pinned connection so disabling foreign keys cannot accidentally
            // apply to a different pooled connection than the DDL.
            sqlite_execute(&mut connection, "PRAGMA foreign_keys = OFF").await?;
            let rebuild = async {
                sqlite_execute(&mut connection, "BEGIN IMMEDIATE").await?;
                sqlite_execute(
                    &mut connection,
                    "DROP TABLE IF EXISTS users_tenant_scope_new",
                )
                .await?;
                sqlite_execute(
                    &mut connection,
                    "CREATE TABLE users_tenant_scope_new (\
                    id varchar(36) NOT NULL PRIMARY KEY, \
                    email varchar(254) NOT NULL, \
                    is_platform_owner boolean NOT NULL DEFAULT 0, \
                    password_hash varchar(255) NULL, \
                    email_verified_at datetime NULL, \
                    created_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP, \
                    updated_at datetime NULL, \
                    deleted_at datetime NULL, \
                    org_id varchar(36) NULL REFERENCES organizations(id) ON DELETE SET NULL\
                )",
                )
                .await?;
                sqlite_execute(
                    &mut connection,
                    "INSERT INTO users_tenant_scope_new (\
                    id, email, is_platform_owner, password_hash, email_verified_at, \
                    created_at, updated_at, deleted_at, org_id\
                 ) SELECT \
                    id, email, is_platform_owner, password_hash, email_verified_at, \
                    created_at, updated_at, deleted_at, org_id \
                 FROM users",
                )
                .await?;
                sqlite_execute(&mut connection, "DROP TABLE users").await?;
                sqlite_execute(
                    &mut connection,
                    "ALTER TABLE users_tenant_scope_new RENAME TO users",
                )
                .await?;
                sqlite_execute(
                    &mut connection,
                    "CREATE UNIQUE INDEX idx_users_email_org \
                 ON users (email, org_id) WHERE org_id IS NOT NULL",
                )
                .await?;
                sqlite_execute(
                    &mut connection,
                    "CREATE UNIQUE INDEX idx_users_email_platform \
                 ON users (email) WHERE org_id IS NULL",
                )
                .await?;
                for statement in [
                    "CREATE INDEX idx_users_org_id ON users (org_id)",
                    "CREATE INDEX idx_users_deleted_at ON users (deleted_at)",
                    "CREATE INDEX idx_users_updated_at ON users (updated_at)",
                    "CREATE INDEX idx_users_created_at ON users (created_at)",
                ] {
                    sqlite_execute(&mut connection, statement).await?;
                }
                sqlite_execute(&mut connection, "COMMIT").await
            }
            .await;

            if let Err(error) = rebuild {
                let _ = sqlite_execute(&mut connection, "ROLLBACK").await;
                let _ = sqlite_execute(&mut connection, "PRAGMA foreign_keys = ON").await;
                return Err(error);
            }

            sqlite_execute(&mut connection, "PRAGMA foreign_keys = ON").await?;
            let violations = sea_orm_migration::sea_orm::sqlx::query("PRAGMA foreign_key_check")
                .fetch_all(&mut *connection)
                .await
                .map_err(|error| DbErr::Custom(format!("verify SQLite foreign keys: {error}")))?;
            if !violations.is_empty() {
                return Err(DbErr::Custom(format!(
                    "SQLite user-scope repair found {} foreign-key violation(s)",
                    violations.len()
                )));
            }
            Ok(())
        }
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        // Restoring global email uniqueness could be destructive once two
        // organizations legitimately contain the same email address.
        Ok(())
    }
}

#[cfg(feature = "db_sqlite")]
async fn sqlite_execute(
    connection: &mut sea_orm_migration::sea_orm::sqlx::SqliteConnection,
    statement: &str,
) -> Result<(), DbErr> {
    sea_orm_migration::sea_orm::sqlx::query(statement)
        .execute(connection)
        .await
        .map_err(|error| DbErr::Custom(format!("SQLite user-scope repair failed: {error}")))?;
    Ok(())
}

#[cfg(all(test, feature = "db_sqlite"))]
mod tests {
    use super::*;
    use crate::Migrator;
    use sea_orm_migration::sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Statement,
    };
    use std::path::PathBuf;
    use uuid::Uuid;

    struct TestDatabase {
        connection: DatabaseConnection,
        path: PathBuf,
    }

    impl TestDatabase {
        async fn before_repair() -> Self {
            let path = std::env::temp_dir().join(format!(
                "authos-users-tenant-scope-repair-{}.db",
                Uuid::new_v4()
            ));
            let mut options = ConnectOptions::new(format!("sqlite:{}?mode=rwc", path.display()));
            // The migration deliberately pins a connection while changing the
            // connection-local foreign_keys pragma. One connection lets the
            // test inspect that exact connection after the migration returns.
            options.min_connections(1).max_connections(1);
            let connection = Database::connect(options)
                .await
                .expect("connect SQLite migration test database");
            Migrator::up(&connection, Some(23))
                .await
                .expect("migrate to immediately before tenant-scope repair");
            Self { connection, path }
        }

        async fn execute(&self, sql: &str) {
            self.connection
                .execute_unprepared(sql)
                .await
                .unwrap_or_else(|error| panic!("execute test SQL `{sql}`: {error}"));
        }

        async fn foreign_keys_enabled(&self) -> bool {
            let row = self
                .connection
                .query_one(Statement::from_string(
                    DbBackend::Sqlite,
                    "PRAGMA foreign_keys".to_string(),
                ))
                .await
                .expect("read foreign_keys pragma")
                .expect("foreign_keys pragma row");
            row.try_get::<i64>("", "foreign_keys") == Ok(1)
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-shm", "-wal"] {
                let _ = std::fs::remove_file(format!("{}{}", self.path.display(), suffix));
            }
        }
    }

    async fn seed_representative_graph(database: &TestDatabase) {
        database
            .execute(
                "INSERT INTO users (
                    id, email, is_platform_owner, password_hash, email_verified_at,
                    created_at, updated_at, deleted_at, org_id
                 ) VALUES
                    ('owner', 'owner@example.test', 1, 'owner-hash',
                     '2024-01-02 03:04:05', '2024-01-01 00:00:00',
                     '2024-01-03 00:00:00', NULL, NULL),
                    ('preserved', 'preserved@example.test', 0, 'preserved-hash',
                     '2024-02-02 03:04:05', '2024-02-01 00:00:00',
                     '2024-02-03 00:00:00', '2024-02-04 00:00:00', NULL),
                    ('cascade-user', 'cascade@example.test', 0, NULL,
                     NULL, '2024-03-01 00:00:00', NULL, NULL, NULL)",
            )
            .await;
        database
            .execute(
                "INSERT INTO organizations (
                    id, slug, name, owner_user_id, status, domain_verified,
                    created_at, updated_at
                 ) VALUES
                    ('org-a', 'org-a', 'Org A', 'owner', 'active', 0,
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP),
                    ('org-b', 'org-b', 'Org B', 'owner', 'active', 0,
                     CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
            )
            .await;
        database
            .execute("UPDATE users SET org_id = 'org-a' WHERE id = 'preserved'")
            .await;
        database
            .execute(
                "INSERT INTO memberships (id, org_id, user_id, role, created_at)
                 VALUES ('membership-cascade', 'org-a', 'cascade-user', 'member', CURRENT_TIMESTAMP)",
            )
            .await;
        database
            .execute(
                "INSERT INTO sessions (
                    id, user_id, token_hash, expires_at, created_at
                 ) VALUES (
                    'session-cascade', 'cascade-user', 'session-token-hash',
                    '2099-01-01 00:00:00', CURRENT_TIMESTAMP
                 )",
            )
            .await;
    }

    #[tokio::test]
    async fn sqlite_rebuild_preserves_data_indexes_uniqueness_and_inbound_foreign_keys() {
        let database = TestDatabase::before_repair().await;
        assert!(database.foreign_keys_enabled().await);
        seed_representative_graph(&database).await;

        let manager = SchemaManager::new(&database.connection);
        Migration.up(&manager).await.expect("run repair migration");
        assert!(database.foreign_keys_enabled().await);

        let preserved = database
            .connection
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT email, org_id, is_platform_owner, password_hash,
                        email_verified_at, created_at, updated_at, deleted_at
                 FROM users WHERE id = 'preserved'"
                    .to_string(),
            ))
            .await
            .expect("read preserved user")
            .expect("preserved user exists");
        assert_eq!(
            preserved.try_get::<String>("", "email").as_deref(),
            Ok("preserved@example.test")
        );
        assert_eq!(
            preserved.try_get::<Option<String>>("", "org_id"),
            Ok(Some("org-a".to_string()))
        );
        assert_eq!(preserved.try_get::<i64>("", "is_platform_owner"), Ok(0));
        assert_eq!(
            preserved.try_get::<Option<String>>("", "password_hash"),
            Ok(Some("preserved-hash".to_string()))
        );
        for (column, expected) in [
            ("email_verified_at", "2024-02-02 03:04:05"),
            ("created_at", "2024-02-01 00:00:00"),
            ("updated_at", "2024-02-03 00:00:00"),
            ("deleted_at", "2024-02-04 00:00:00"),
        ] {
            assert_eq!(
                preserved.try_get::<Option<String>>("", column),
                Ok(Some(expected.to_string())),
                "column {column} was not preserved"
            );
        }

        let indexes = database
            .connection
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA index_list(users)".to_string(),
            ))
            .await
            .expect("read users indexes");
        for (name, unique, partial) in [
            ("idx_users_email_org", 1_i64, 1_i64),
            ("idx_users_email_platform", 1, 1),
            ("idx_users_org_id", 0, 0),
            ("idx_users_deleted_at", 0, 0),
            ("idx_users_updated_at", 0, 0),
            ("idx_users_created_at", 0, 0),
        ] {
            let row = indexes
                .iter()
                .find(|row| row.try_get::<String>("", "name").as_deref() == Ok(name))
                .unwrap_or_else(|| panic!("missing users index {name}"));
            assert_eq!(row.try_get::<i64>("", "unique"), Ok(unique), "{name}");
            assert_eq!(row.try_get::<i64>("", "partial"), Ok(partial), "{name}");
        }

        database
            .execute(
                "INSERT INTO users (id, email, org_id, is_platform_owner, created_at)
                 VALUES
                    ('same-platform', 'same@example.test', NULL, 0, CURRENT_TIMESTAMP),
                    ('same-org-a', 'same@example.test', 'org-a', 0, CURRENT_TIMESTAMP),
                    ('same-org-b', 'same@example.test', 'org-b', 0, CURRENT_TIMESTAMP)",
            )
            .await;
        assert!(database
            .connection
            .execute_unprepared(
                "INSERT INTO users (id, email, org_id, is_platform_owner, created_at)
                 VALUES ('duplicate-platform', 'same@example.test', NULL, 0, CURRENT_TIMESTAMP)",
            )
            .await
            .is_err());
        assert!(database
            .connection
            .execute_unprepared(
                "INSERT INTO users (id, email, org_id, is_platform_owner, created_at)
                 VALUES ('duplicate-org', 'same@example.test', 'org-a', 0, CURRENT_TIMESTAMP)",
            )
            .await
            .is_err());

        let violations = database
            .connection
            .query_all(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_key_check".to_string(),
            ))
            .await
            .expect("check inbound foreign keys after rebuild");
        assert!(violations.is_empty());
        database
            .execute("DELETE FROM users WHERE id = 'cascade-user'")
            .await;
        for (table, id) in [
            ("memberships", "membership-cascade"),
            ("sessions", "session-cascade"),
        ] {
            let count = database
                .connection
                .query_one(Statement::from_string(
                    DbBackend::Sqlite,
                    format!("SELECT COUNT(*) AS count FROM {table} WHERE id = '{id}'"),
                ))
                .await
                .expect("count cascade child")
                .expect("cascade count row")
                .try_get::<i64>("", "count");
            assert_eq!(count, Ok(0), "{table} row did not cascade");
        }

        // A rerun is safe when a migration runner retries before recording it.
        Migration
            .up(&manager)
            .await
            .expect("rerun repair migration");
        assert!(database.foreign_keys_enabled().await);
        assert!(database
            .connection
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM users WHERE id = 'preserved'".to_string(),
            ))
            .await
            .expect("read preserved user after rerun")
            .is_some());
    }

    #[tokio::test]
    async fn sqlite_rebuild_failure_rolls_back_and_restores_foreign_keys_before_retry() {
        let database = TestDatabase::before_repair().await;
        seed_representative_graph(&database).await;
        database.execute("DROP INDEX idx_users_email_org").await;
        database
            .execute("CREATE TABLE index_name_collision (value TEXT)")
            .await;
        database
            .execute("CREATE INDEX idx_users_email_org ON index_name_collision (value)")
            .await;

        let manager = SchemaManager::new(&database.connection);
        let error = Migration
            .up(&manager)
            .await
            .expect_err("colliding index name must fail rebuild");
        assert!(error.to_string().contains("idx_users_email_org"));
        assert!(database.foreign_keys_enabled().await);
        assert!(database
            .connection
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT id FROM users WHERE id = 'preserved'".to_string(),
            ))
            .await
            .expect("read original users after rollback")
            .is_some());
        assert!(!SchemaManager::new(&database.connection)
            .has_table("users_tenant_scope_new")
            .await
            .expect("check temporary table rollback"));

        database.execute("DROP TABLE index_name_collision").await;
        Migration
            .up(&manager)
            .await
            .expect("retry succeeds after failure cause is removed");
        assert!(database.foreign_keys_enabled().await);
    }
}
