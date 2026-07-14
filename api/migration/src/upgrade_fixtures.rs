//! Upgrade-contract fixtures shared by backend qualification tests.
//!
//! SQLite executes these fixtures in normal unit CI. PostgreSQL/MySQL runtime
//! jobs can reuse `assert_head_schema` after provisioning their own supported
//! origin; this module does not claim those external databases were exercised.

#[cfg(feature = "db_sqlite")]
use crate::Migrator;
#[cfg(feature = "db_sqlite")]
use sea_orm_migration::sea_orm::{ConnectOptions, ConnectionTrait, Database, Statement};
use sea_orm_migration::{prelude::*, sea_orm::DatabaseConnection};

#[cfg(feature = "db_sqlite")]
const SUPPORTED_ORIGIN_MIGRATIONS: u32 = 19;

#[cfg(feature = "db_sqlite")]
async fn scalar_i64(db: &DatabaseConnection, sql: &str) -> i64 {
    db.query_one(Statement::from_string(
        db.get_database_backend(),
        sql.to_string(),
    ))
    .await
    .expect("run fixture query")
    .expect("fixture query row")
    .try_get::<i64>("", "value")
    .expect("fixture scalar value")
}

/// Backend-neutral post-upgrade schema assertions for future PostgreSQL and
/// MySQL runtime qualification jobs as well as the SQLite fixture below.
#[allow(dead_code)] // Reused by external-backend CI fixtures when those jobs run.
pub(crate) async fn assert_head_schema(db: &DatabaseConnection) {
    let manager = SchemaManager::new(db);
    for (table, columns) in [
        ("sessions", &["refresh_token_hash"] as &[&str]),
        ("webhooks", &["secret_encrypted", "encryption_key_id"]),
        ("saml_signing_keys", &["publish_until", "retired_at"]),
        ("users", &["org_id"]),
    ] {
        assert!(
            manager.has_table(table).await.expect("check table"),
            "{table}"
        );
        for column in columns {
            assert!(
                manager
                    .has_column(table, column)
                    .await
                    .expect("check column"),
                "missing {table}.{column}"
            );
        }
    }
    for table in ["session_refresh_token_history", "audit_outbox"] {
        assert!(
            manager.has_table(table).await.expect("check head table"),
            "{table}"
        );
    }
}

#[cfg(feature = "db_sqlite")]
async fn sqlite_database(label: &str) -> (DatabaseConnection, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("authos-{label}-{}.db", uuid::Uuid::new_v4()));
    let mut options = ConnectOptions::new(format!("sqlite:{}?mode=rwc", path.display()));
    options.min_connections(1).max_connections(1);
    let db = Database::connect(options)
        .await
        .expect("connect fixture SQLite");
    (db, path)
}

#[cfg(feature = "db_sqlite")]
fn remove_sqlite_files(path: &std::path::Path) {
    for suffix in ["", "-shm", "-wal"] {
        let _ = std::fs::remove_file(format!("{}{}", path.display(), suffix));
    }
}

#[cfg(feature = "db_sqlite")]
#[tokio::test]
async fn supported_origin_upgrades_to_head_and_preserves_representative_data() {
    let (db, path) = sqlite_database("supported-upgrade").await;
    Migrator::up(&db, Some(SUPPORTED_ORIGIN_MIGRATIONS))
        .await
        .expect("migrate to supported origin");

    db.execute_unprepared(
        "INSERT INTO users (
             id, email, org_id, is_platform_owner, password_hash, created_at
         ) VALUES (
             'upgrade-user', 'upgrade@example.test', NULL, 0, 'preserved-hash', CURRENT_TIMESTAMP
         );
         INSERT INTO organizations (
             id, slug, name, owner_user_id, status, created_at, updated_at
         ) VALUES (
             'upgrade-org', 'upgrade-org', 'Upgrade Org', 'upgrade-user', 'active',
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         );
         INSERT INTO sessions (
             id, user_id, token_hash, expires_at, refresh_token,
             refresh_token_expires_at, created_at
         ) VALUES (
             'upgrade-session', 'upgrade-user', 'access-hash', '2099-01-01 00:00:00',
             'legacy-refresh-bearer', '2099-01-01 00:00:00', CURRENT_TIMESTAMP
         );
         INSERT INTO webhooks (
             id, org_id, name, url, secret, events, is_active, created_at, updated_at
         ) VALUES (
             'upgrade-webhook', 'upgrade-org', 'Upgrade Webhook',
             'https://example.test/hook', 'legacy-secret', '[\"user.created\"]', 1,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         );",
    )
    .await
    .expect("seed supported origin");

    Migrator::up(&db, None)
        .await
        .expect("upgrade supported origin to head");
    assert_head_schema(&db).await;

    assert_eq!(
        scalar_i64(
            &db,
            "SELECT COUNT(*) AS value FROM users
             WHERE id = 'upgrade-user' AND email = 'upgrade@example.test'
               AND password_hash = 'preserved-hash'",
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            &db,
            "SELECT COUNT(*) AS value FROM sessions
             WHERE id = 'upgrade-session' AND refresh_token IS NULL
               AND refresh_token_hash IS NULL",
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            &db,
            "SELECT COUNT(*) AS value FROM webhooks
             WHERE id = 'upgrade-webhook' AND secret = 'legacy-secret'
               AND secret_encrypted IS NULL AND encryption_key_id IS NULL",
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            &db,
            "SELECT COUNT(*) AS value FROM pragma_foreign_key_check"
        )
        .await,
        0
    );

    db.close().await.expect("close supported-upgrade database");
    remove_sqlite_files(&path);
}

#[cfg(feature = "db_sqlite")]
#[tokio::test]
async fn migration_runner_failure_rolls_back_preserves_data_and_retries_cleanly() {
    let (db, path) = sqlite_database("failed-upgrade").await;
    Migrator::up(&db, Some(23))
        .await
        .expect("migrate immediately before repair");
    db.execute_unprepared(
        "INSERT INTO users (id, email, is_platform_owner, password_hash, created_at)
         VALUES ('rollback-user', 'rollback@example.test', 0, 'rollback-hash', CURRENT_TIMESTAMP);
         DROP INDEX idx_users_email_org;
         CREATE TABLE fixture_index_collision (value TEXT);
         CREATE INDEX idx_users_email_org ON fixture_index_collision(value);",
    )
    .await
    .expect("seed failed migration fixture");

    Migrator::up(&db, None)
        .await
        .expect_err("index collision must fail the migration runner");
    assert_eq!(
        scalar_i64(
            &db,
            "SELECT COUNT(*) AS value FROM users
             WHERE id = 'rollback-user' AND password_hash = 'rollback-hash'",
        )
        .await,
        1
    );
    assert_eq!(
        scalar_i64(
            &db,
            "SELECT COUNT(*) AS value FROM sqlite_master
             WHERE type = 'table' AND name = 'users_tenant_scope_new'",
        )
        .await,
        0
    );
    assert_eq!(
        scalar_i64(
            &db,
            "SELECT COUNT(*) AS value FROM seaql_migrations
             WHERE version = 'm20260714_000005_fix_sqlite_user_email_scope'",
        )
        .await,
        0
    );

    db.execute_unprepared("DROP TABLE fixture_index_collision")
        .await
        .expect("remove injected failure");
    Migrator::up(&db, None)
        .await
        .expect("retry migration runner after rollback");
    assert_head_schema(&db).await;

    db.close().await.expect("close failed-upgrade database");
    remove_sqlite_files(&path);
}
