//! Security Audit Item 1: User Schema Isolation
//!
//! This migration adds org_id to the users table for multi-tenant user isolation.
//!
//! MIGRATION STRATEGY:
//! - Adds nullable org_id column to users table
//! - Creates partial/functional unique indexes to enforce uniqueness:
//!   - PostgreSQL/SQLite: Partial indexes with WHERE clause
//!   - MySQL 8.0+: Functional index on (email, COALESCE(org_id, ''))
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
                // SQLite requires table recreation to add foreign keys
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
    // SQLite table modification with foreign key dependencies requires special handling.
    // This migration now includes RECOVERY LOGIC for databases left in a corrupted state
    // from previous failed migration attempts.
    async fn up_sqlite<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        // 1. Disable foreign keys during table manipulation
        db.execute_unprepared("PRAGMA foreign_keys = OFF").await?;

        // 2. Check current database state to determine the right recovery path
        let users_exists = self.table_exists(db, "users").await?;
        let users_new_exists = self.table_exists(db, "users_new").await?;

        if !users_exists && users_new_exists {
            // RECOVERY PATH: Previous migration dropped "users" but failed before renaming "users_new"
            // The data is in users_new - we need to check if it has org_id already
            let has_org_id = self.column_exists(db, "users_new", "org_id").await?;

            if has_org_id {
                // users_new already has the new schema - just rename it
                db.execute_unprepared("ALTER TABLE users_new RENAME TO users")
                    .await?;
            } else {
                // users_new has old schema - we need to recreate with new schema
                // First, save the data
                db.execute_unprepared("ALTER TABLE users_new RENAME TO users_old_backup")
                    .await?;

                // Create the proper new table
                db.execute_unprepared(
                    "CREATE TABLE users (
                        id TEXT NOT NULL PRIMARY KEY,
                        email TEXT NOT NULL,
                        org_id TEXT NULL REFERENCES organizations(id) ON DELETE SET NULL,
                        is_platform_owner BOOLEAN NOT NULL DEFAULT 0,
                        password_hash TEXT NULL,
                        email_verified_at TEXT NULL,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT NULL,
                        deleted_at TEXT NULL
                    )",
                )
                .await?;

                // Copy data from backup
                db.execute_unprepared(
                    "INSERT INTO users (id, email, is_platform_owner, password_hash, email_verified_at, created_at, updated_at, deleted_at)
                     SELECT id, email, is_platform_owner, password_hash, email_verified_at, created_at, updated_at, deleted_at FROM users_old_backup"
                ).await?;

                // Drop the backup
                db.execute_unprepared("DROP TABLE users_old_backup").await?;
            }
        } else if users_exists {
            // NORMAL PATH: users table exists, perform standard migration

            // Check if org_id column already exists (migration already partially applied)
            let has_org_id = self.column_exists(db, "users", "org_id").await?;
            if has_org_id {
                // Already migrated, just ensure indexes exist
                db.execute_unprepared("PRAGMA foreign_keys = ON").await?;
                return self.ensure_indexes(manager, db).await;
            }

            // Drop existing indexes on users table (ignore errors)
            let _ = manager
                .drop_index(
                    Index::drop()
                        .name("idx_users_email")
                        .table(Users::Table)
                        .to_owned(),
                )
                .await;

            // Drop any leftover users_new from previous failed attempts
            db.execute_unprepared("DROP TABLE IF EXISTS users_new")
                .await?;

            // Create NEW table with temp name "users_new" including org_id column
            db.execute_unprepared(
                "CREATE TABLE users_new (
                    id TEXT NOT NULL PRIMARY KEY,
                    email TEXT NOT NULL,
                    org_id TEXT NULL REFERENCES organizations(id) ON DELETE SET NULL,
                    is_platform_owner BOOLEAN NOT NULL DEFAULT 0,
                    password_hash TEXT NULL,
                    email_verified_at TEXT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT NULL,
                    deleted_at TEXT NULL
                )",
            )
            .await?;

            // Copy data from old users table to users_new
            db.execute_unprepared(
                "INSERT INTO users_new (id, email, is_platform_owner, password_hash, email_verified_at, created_at, updated_at, deleted_at)
                 SELECT id, email, is_platform_owner, password_hash, email_verified_at, created_at, updated_at, deleted_at FROM users"
            ).await?;

            // Drop the original users table
            manager
                .drop_table(Table::drop().table(Users::Table).to_owned())
                .await?;

            // Rename users_new to users
            db.execute_unprepared("ALTER TABLE users_new RENAME TO users")
                .await?;
        } else {
            // CATASTROPHIC: Neither table exists - cannot proceed
            // This should not happen if initial_schema migration ran properly
            return Err(DbErr::Custom(
                "FATAL: Neither 'users' nor 'users_new' table exists. Database may be corrupted or initial schema was never applied.".to_string()
            ));
        }

        // Re-enable foreign keys
        db.execute_unprepared("PRAGMA foreign_keys = ON").await?;

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
            .drop_index(
                Index::drop()
                    .name("idx_users_org_id")
                    .table(Users::Table)
                    .to_owned(),
            )
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
        manager
            .alter_table(
                Table::alter()
                    .table(Users::Table)
                    .add_column(ColumnDef::new(Users::OrgId).string_len(36).null())
                    .to_owned(),
            )
            .await?;

        // 1b. Drop legacy unique index on email
        let _ = db.execute_unprepared("DROP INDEX email ON users").await;
        let _ = db.execute_unprepared("DROP INDEX email_2 ON users").await; // Sometimes created as duplicate

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

        // 3. MySQL 8.0+ functional index approach
        // Since MySQL doesn't support partial indexes, we use a functional unique index
        // COALESCE(org_id, '') creates empty string for NULL, making (email, '') unique for platform users
        // and (email, actual_org_id) unique for tenant users
        db.execute_unprepared(
            "CREATE UNIQUE INDEX idx_users_email_org ON users ((COALESCE(org_id, '')), email)",
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

    async fn down_mysql<'a>(
        &self,
        manager: &SchemaManager<'a>,
        db: &SchemaManagerConnection<'a>,
    ) -> Result<(), DbErr> {
        db.execute_unprepared("DROP INDEX idx_users_email_org ON users")
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
            .drop_foreign_key(
                ForeignKey::drop()
                    .name("fk_users_org")
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
