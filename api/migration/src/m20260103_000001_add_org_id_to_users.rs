//! Security Audit Item 1: User Schema Isolation
//!
//! This migration adds org_id to the users table for multi-tenant user isolation.
//!
//! MIGRATION STRATEGY:
//! - Adds nullable org_id column to users table
//! - Creates backend-specific unique indexes to enforce uniqueness:
//!   - PostgreSQL/SQLite: Partial indexes with WHERE clause
//!   - MySQL 8.0+: Indexed generated scope column plus email
//! - Existing users remain with NULL org_id (platform-level users)
//! - New service-created users will have org_id set

use sea_orm_migration::prelude::*;
use sea_orm_migration::sea_orm::DbBackend;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        match backend {
            DbBackend::Sqlite => {
                // SQLite accepts a nullable REFERENCES column in place.
                self.up_sqlite(manager, db).await?;
            }
            DbBackend::Postgres => {
                // PostgreSQL supports partial indexes natively
                self.up_postgres(manager, db).await?;
            }
            DbBackend::MySql => {
                // MySQL 8.0+ uses functional indexes
                self.up_mysql(manager, db).await?;
            }
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = manager.get_database_backend();

        match backend {
            DbBackend::Sqlite => {
                self.down_sqlite(manager, db).await?;
            }
            DbBackend::Postgres => {
                self.down_postgres(manager, db).await?;
            }
            DbBackend::MySql => {
                self.down_mysql(manager, db).await?;
            }
        }

        Ok(())
    }
}

impl Migration {
    // ===== SQLITE =====
    // SQLite supports adding a nullable REFERENCES column in place. Avoid the
    // older table-copy/drop/rename strategy: when migrations run through a
    // multi-connection pool, its PRAGMA and DDL statements can execute on
    // different connections and leave the database at `users_new`.
    //
    // The recovery branch remains intentionally supported for databases left
    // by that older implementation.
    async fn up_sqlite<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        // Check current database state to determine the right recovery path.
        let users_exists = self.table_exists(db, "users").await?;
        let users_new_exists = self.table_exists(db, "users_new").await?;

        if !users_exists && users_new_exists {
            // Recovery path: the previous implementation copied all user rows,
            // dropped `users`, and failed before this rename. Rename first, then
            // use the same in-place column path as a normal upgrade if required.
            db.execute_unprepared("ALTER TABLE users_new RENAME TO users")
                .await?;
        } else if !users_exists {
            // CATASTROPHIC: Neither table exists - cannot proceed
            // This should not happen if initial_schema migration ran properly
            return Err(DbErr::Custom(
                "FATAL: Neither 'users' nor 'users_new' table exists. Database may be corrupted or initial schema was never applied.".to_string()
            ));
        }

        if !self.column_exists(db, "users", "org_id").await? {
            db.execute_unprepared(
                "ALTER TABLE users ADD COLUMN org_id TEXT NULL \
                 REFERENCES organizations(id) ON DELETE SET NULL",
            )
            .await?;
        }

        // The original global email index must not prevent the intended
        // platform-versus-tenant uniqueness rules below.
        let _ = manager
            .drop_index(
                Index::drop()
                    .name("idx_users_email")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await;

        // A stale temp table can exist only when the canonical users table also
        // survived an older interrupted attempt. It is safe to remove after the
        // canonical schema and data have been selected above.
        if self.table_exists(db, "users_new").await? {
            db.execute_unprepared("DROP TABLE users_new").await?;
        }

        // Verify foreign key integrity
        db.execute_unprepared("PRAGMA foreign_key_check").await?;

        // Create indexes
        self.ensure_indexes(manager, db).await?;

        Ok(())
    }

    /// Check if a table exists in SQLite
    async fn table_exists<'a>(
        &self,
        db: &SchemaManagerConnection<'a>,
        table_name: &str,
    ) -> Result<bool, DbErr> {
        let result = db
            .query_one(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                format!(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='{}'",
                    table_name
                ),
            ))
            .await?;
        Ok(result.is_some())
    }

    /// Check if a column exists in a SQLite table
    async fn column_exists<'a>(
        &self,
        db: &SchemaManagerConnection<'a>,
        table_name: &str,
        column_name: &str,
    ) -> Result<bool, DbErr> {
        let result = db
            .query_all(sea_orm::Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                format!("PRAGMA table_info({})", table_name),
            ))
            .await?;

        for row in result {
            if let Ok(name) = row.try_get::<String>("", "name") {
                if name == column_name {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Ensure all required indexes exist
    async fn ensure_indexes<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        // Create partial unique indexes (ignore errors if they already exist)
        let _ = db.execute_unprepared(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_org ON users (email, org_id) WHERE org_id IS NOT NULL"
        ).await;

        let _ = db.execute_unprepared(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_platform ON users (email) WHERE org_id IS NULL"
        ).await;

        // Create index on org_id for performance (ignore if exists)
        let _ = manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name("idx_users_org_id")
                    .table(Users::Table)
                    .col(Users::OrgId)
                    .to_owned(),
            )
            .await;

        Ok(())
    }

    // down_sqlite: Reverse the migration (remove org_id column)
    // Uses same pattern: create new table, copy data, drop old, rename new
    async fn down_sqlite<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        // 1. Disable foreign keys during table manipulation
        db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;

        // 2. Drop indexes that will be recreated
        let _ = manager
            .drop_index(
                Index::drop()
                    .name("idx_users_org_id")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await;
        let _ = db
            .execute_unprepared("DROP INDEX IF EXISTS idx_users_email_org")
            .await;
        let _ = db
            .execute_unprepared("DROP INDEX IF EXISTS idx_users_email_platform")
            .await;

        // 3. Create NEW table without org_id column
        db.execute_unprepared("DROP TABLE IF EXISTS users_new")
            .await?;
        db.execute_unprepared(
            "CREATE TABLE users_new (
                id TEXT NOT NULL PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                is_platform_owner BOOLEAN NOT NULL DEFAULT 0,
                password_hash TEXT NULL,
                email_verified_at TEXT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NULL,
                deleted_at TEXT NULL
            )",
        )
        .await?;

        // 4. Copy data (excluding org_id)
        db.execute_unprepared(
            "INSERT INTO users_new (id, email, is_platform_owner, password_hash, email_verified_at, created_at, updated_at, deleted_at)
             SELECT id, email, is_platform_owner, password_hash, email_verified_at, created_at, updated_at, deleted_at FROM users"
        ).await?;

        // 5. Drop the original users table
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await?;

        // 6. Rename users_new to users
        db.execute_unprepared("ALTER TABLE users_new RENAME TO users")
            .await?;

        // 7. Re-enable foreign keys
        db.execute_unprepared("PRAGMA foreign_keys = ON").await?;

        Ok(())
    }

    // ===== POSTGRESQL =====
    async fn up_postgres<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        // 1. Add nullable org_id column
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::OrgId).string_len(36).null())
                    .to_owned(),
            )
            .await?;

        // 1b. Drop legacy global unique constraint on email
        db.execute_unprepared("ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key")
            .await?;

        // 2. Add foreign key
        manager
            .create_foreign_key(
                ForeignKey::create()
                    .name("fk_users_org")
                    .from(Users::Table, Users::OrgId)
                    .to(Organizations::Table, Organizations::Id)
                    .on_delete(ForeignKeyAction::SetNull)
                    .to_owned(),
            )
            .await?;

        // 3. Create partial unique indexes (PostgreSQL supports WHERE clause)
        db.execute_unprepared(
            "CREATE UNIQUE INDEX idx_users_email_org ON users (email, org_id) WHERE org_id IS NOT NULL"
        ).await?;

        db.execute_unprepared(
            "CREATE UNIQUE INDEX idx_users_email_platform ON users (email) WHERE org_id IS NULL",
        )
        .await?;

        // 4. Create index on org_id for performance
        manager
            .create_index(
                Index::create()
                    .name("idx_users_org_id")
                    .table(Users::Table)
                    .col(Users::OrgId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down_postgres<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        db.execute_unprepared("DROP INDEX IF EXISTS idx_users_email_org")
            .await?;
        db.execute_unprepared("DROP INDEX IF EXISTS idx_users_email_platform")
            .await?;

        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_users_org")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_users_org_id")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::OrgId)
                    .to_owned(),
            )
            .await?;

        // Restore global unique constraint
        db.execute_unprepared("ALTER TABLE users ADD CONSTRAINT users_email_key UNIQUE (email)")
            .await?;

        Ok(())
    }

    // ===== MYSQL =====
    async fn up_mysql<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        // 1. Add nullable org_id column
        if !manager.has_column("users", "org_id").await? {
            manager
                .alter_table(
                    Table::alter()
                        .table(Users::Table)
                        .add_column(ColumnDef::new(Users::OrgId).string_len(36).null())
                        .to_owned(),
                )
                .await?;
        }

        // 1b. Drop legacy unique index on email
        let _ = db.execute_unprepared("DROP INDEX email ON users").await;
        let _ = db.execute_unprepared("DROP INDEX email_2 ON users").await; // Sometimes created as duplicate

        // 2. Add foreign key
        if !self.mysql_foreign_key_exists(db, "fk_users_org").await? {
            manager
                .create_foreign_key(
                    ForeignKey::create()
                        .name("fk_users_org")
                        .from(Users::Table, Users::OrgId)
                        .to(Organizations::Table, Organizations::Id)
                        .on_delete(ForeignKeyAction::SetNull)
                        .to_owned(),
                )
                .await?;
        }

        // 3. MySQL does not support partial indexes. Materialize the nullable
        // organization scope in a generated column, then index it with email.
        // This avoids the functional-key syntax and remains compatible with
        // MySQL 8.0/8.4 while preserving one platform user per email. It must
        // remain VIRTUAL because org_id has an ON DELETE SET NULL foreign key;
        // MySQL rejects that referential action for STORED generated bases.
        if !manager.has_column("users", "org_id_email_scope").await? {
            db.execute_unprepared(
                "ALTER TABLE users ADD COLUMN org_id_email_scope VARCHAR(36) \
                 GENERATED ALWAYS AS (COALESCE(org_id, '')) VIRTUAL",
            )
            .await?;
        }
        if !manager.has_index("users", "idx_users_email_org").await? {
            db.execute_unprepared(
                "CREATE UNIQUE INDEX idx_users_email_org ON users (org_id_email_scope, email)",
            )
            .await?;
        }

        // 4. Create index on org_id for performance
        if !manager.has_index("users", "idx_users_org_id").await? {
            manager
                .create_index(
                    Index::create()
                        .name("idx_users_org_id")
                        .table(Users::Table)
                        .col(Users::OrgId)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }

    async fn down_mysql<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        db.execute_unprepared("DROP INDEX idx_users_email_org ON users")
            .await?;

        // Older installations may have applied the previous functional index
        // form and therefore have no generated scope column.
        let _ = db
            .execute_unprepared("ALTER TABLE users DROP COLUMN org_id_email_scope")
            .await;

        manager
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_users_org")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                Index::drop()
                    .name("idx_users_org_id")
                    .table(Users::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .drop_column(Users::OrgId)
                    .to_owned(),
            )
            .await?;

        // Restore global unique index
        let _ = db
            .execute_unprepared("CREATE UNIQUE INDEX email ON users (email)")
            .await;

        Ok(())
    }

    async fn mysql_foreign_key_exists<'a>(
        &self,
        db: &SchemaManagerConnection<'a>,
        constraint_name: &str,
    ) -> Result<bool, DbErr> {
        let row = db
            .query_one(sea_orm::Statement::from_sql_and_values(
                sea_orm::DatabaseBackend::MySql,
                "SELECT COUNT(*) AS constraint_count \
                 FROM information_schema.TABLE_CONSTRAINTS \
                 WHERE CONSTRAINT_SCHEMA = DATABASE() \
                   AND TABLE_NAME = 'users' \
                   AND CONSTRAINT_NAME = ? \
                   AND CONSTRAINT_TYPE = 'FOREIGN KEY'",
                [constraint_name.into()],
            ))
            .await?;
        let count = row
            .ok_or_else(|| DbErr::Custom("failed to inspect MySQL foreign keys".to_owned()))?
            .try_get::<i64>("", "constraint_count")?;
        Ok(count > 0)
    }
}

#[derive(DeriveIden)]
#[allow(dead_code)]
enum Users {
    Table,
    Id,
    Email,
    OrgId,
    IsPlatformOwner,
    PasswordHash,
    EmailVerifiedAt,
    CreatedAt,
    UpdatedAt,
    DeletedAt,
}

#[derive(DeriveIden)]
enum Organizations {
    Table,
    Id,
}

#[cfg(test)]
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
        async fn connect() -> Self {
            let path = std::env::temp_dir()
                .join(format!("authos-users-org-migration-{}.db", Uuid::new_v4()));
            let mut options = ConnectOptions::new(format!("sqlite:{}?mode=rwc", path.display()));
            options.min_connections(1).max_connections(10);

            let connection = Database::connect(options)
                .await
                .expect("connect to pooled SQLite test database");

            Self { connection, path }
        }

        async fn assert_org_scope_schema(&self) {
            let columns = self
                .connection
                .query_all(Statement::from_string(
                    DbBackend::Sqlite,
                    "PRAGMA table_info(users)".to_owned(),
                ))
                .await
                .expect("read users columns");
            assert!(columns
                .iter()
                .any(|row| { row.try_get::<String>("", "name").as_deref() == Ok("org_id") }));

            let foreign_keys = self
                .connection
                .query_all(Statement::from_string(
                    DbBackend::Sqlite,
                    "PRAGMA foreign_key_list(users)".to_owned(),
                ))
                .await
                .expect("read users foreign keys");
            assert!(foreign_keys.iter().any(|row| {
                row.try_get::<String>("", "table").as_deref() == Ok("organizations")
                    && row.try_get::<String>("", "from").as_deref() == Ok("org_id")
                    && row.try_get::<String>("", "on_delete").as_deref() == Ok("SET NULL")
            }));

            for index_name in [
                "idx_users_email_org",
                "idx_users_email_platform",
                "idx_users_org_id",
            ] {
                let index = self
                    .connection
                    .query_one(Statement::from_sql_and_values(
                        DbBackend::Sqlite,
                        "SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?",
                        [index_name.into()],
                    ))
                    .await
                    .expect("query users index");
                assert!(index.is_some(), "missing users index {index_name}");
            }
        }
    }

    impl Drop for TestDatabase {
        fn drop(&mut self) {
            for suffix in ["", "-shm", "-wal"] {
                let _ = std::fs::remove_file(format!("{}{}", self.path.display(), suffix));
            }
        }
    }

    #[tokio::test]
    async fn fresh_sqlite_database_migrates_with_a_connection_pool() {
        let database = TestDatabase::connect().await;

        Migrator::up(&database.connection, Some(9))
            .await
            .expect("run migrations through add-org-id-to-users");

        database.assert_org_scope_schema().await;
    }

    #[tokio::test]
    async fn sqlite_upgrade_preserves_existing_users() {
        let database = TestDatabase::connect().await;
        Migrator::up(&database.connection, Some(8))
            .await
            .expect("prepare schema immediately before users org migration");

        database
            .connection
            .execute(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO users (id, email, is_platform_owner, password_hash, created_at) \
                 VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
                [
                    "existing-user".into(),
                    "existing@example.test".into(),
                    true.into(),
                    "existing-password-hash".into(),
                ],
            ))
            .await
            .expect("insert user using the pre-migration schema");

        Migrator::up(&database.connection, Some(1))
            .await
            .expect("upgrade existing users schema");

        let user = database
            .connection
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT email, password_hash, org_id FROM users WHERE id = 'existing-user'"
                    .to_owned(),
            ))
            .await
            .expect("query upgraded user")
            .expect("existing user remains after migration");
        assert_eq!(
            user.try_get::<String>("", "email").as_deref(),
            Ok("existing@example.test")
        );
        assert_eq!(
            user.try_get::<String>("", "password_hash").as_deref(),
            Ok("existing-password-hash")
        );
        assert_eq!(user.try_get::<Option<String>>("", "org_id"), Ok(None));

        database.assert_org_scope_schema().await;
    }

    #[tokio::test]
    async fn sqlite_upgrade_recovers_users_new_after_interrupted_rename() {
        let database = TestDatabase::connect().await;
        Migrator::up(&database.connection, Some(8))
            .await
            .expect("prepare schema immediately before users org migration");

        database
            .connection
            .execute_unprepared(
                "INSERT INTO users (id, email, is_platform_owner, password_hash, created_at) \
                 VALUES ('recovery-user', 'recovery@example.test', 0, \
                 'recovery-password-hash', CURRENT_TIMESTAMP)",
            )
            .await
            .expect("insert user before simulating interrupted migration");
        database
            .connection
            .execute_unprepared(
                "ALTER TABLE users ADD COLUMN org_id TEXT NULL \
                 REFERENCES organizations(id) ON DELETE SET NULL",
            )
            .await
            .expect("prepare copied schema with org_id");
        database
            .connection
            .execute_unprepared("ALTER TABLE users RENAME TO users_new")
            .await
            .expect("simulate interruption before users_new rename");

        Migrator::up(&database.connection, Some(1))
            .await
            .expect("recover interrupted users migration");

        let recovered_user = database
            .connection
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT email, password_hash, org_id FROM users WHERE id = 'recovery-user'"
                    .to_owned(),
            ))
            .await
            .expect("query recovered user")
            .expect("user data remains after recovery");
        assert_eq!(
            recovered_user.try_get::<String>("", "email").as_deref(),
            Ok("recovery@example.test")
        );
        assert_eq!(
            recovered_user
                .try_get::<String>("", "password_hash")
                .as_deref(),
            Ok("recovery-password-hash")
        );
        assert_eq!(
            recovered_user.try_get::<Option<String>>("", "org_id"),
            Ok(None)
        );

        database.assert_org_scope_schema().await;
    }
}
