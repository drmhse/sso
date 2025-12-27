pub mod models;

use crate::config::Config;
use migration::MigratorTrait;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbErr};

/// Initialize the database connection with configurable pool settings.
///
/// # Arguments
/// * `config` - Application configuration containing database URL and pool settings
///
/// # Pool Settings (from environment or defaults):
/// * `DB_MAX_CONNECTIONS` - Maximum connections in pool (default: 200)
/// * `DB_MIN_CONNECTIONS` - Minimum connections to maintain (default: 5)
/// * `DB_ACQUIRE_TIMEOUT_SECS` - Timeout for acquiring connection (default: 30)
/// * `DB_IDLE_TIMEOUT_SECS` - Idle connection timeout (default: 600)
/// * `DB_MAX_LIFETIME_SECS` - Maximum connection lifetime (default: 1800)
pub async fn init_db(config: &Config) -> Result<DatabaseConnection, DbErr> {
    let mut opt = ConnectOptions::new(&config.database_url);
    opt.max_connections(config.db_max_connections)
        .min_connections(config.db_min_connections)
        .acquire_timeout(std::time::Duration::from_secs(
            config.db_acquire_timeout_secs,
        ))
        .idle_timeout(std::time::Duration::from_secs(config.db_idle_timeout_secs))
        .max_lifetime(std::time::Duration::from_secs(config.db_max_lifetime_secs))
        .sqlx_logging(false); // We use tracing for logging

    // Set SQLite PRAGMAs using map_sqlx_sqlite_opts
    #[cfg(feature = "db_sqlite")]
    opt.map_sqlx_sqlite_opts(|opt| {
        opt.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_millis(30000))
            .pragma("cache_size", "-128000")
            .pragma("wal_autocheckpoint", "0")
            .pragma("temp_store", "MEMORY")
            .pragma("mmap_size", "536870912")
            .pragma("locking_mode", "NORMAL")
    });

    let db = Database::connect(opt).await?;

    // Run migrations from our `migration` crate
    migration::Migrator::up(&db, None).await?;

    Ok(db)
}

/// SQLite-only: Initialize a single-connection writer pool.
/// All write transactions should go through this connection to prevent nested transaction issues.
/// This connection uses BEGIN IMMEDIATE for proper busy_timeout handling.
#[cfg(feature = "db_sqlite")]
pub async fn init_db_writer(config: &Config) -> Result<DatabaseConnection, DbErr> {
    let mut opt = ConnectOptions::new(&config.database_url);
    
    // Single connection for serialized writes
    opt.max_connections(1)
        .min_connections(1)
        .acquire_timeout(std::time::Duration::from_secs(60)) // Longer timeout for writer
        .idle_timeout(std::time::Duration::from_secs(config.db_idle_timeout_secs))
        .max_lifetime(std::time::Duration::from_secs(config.db_max_lifetime_secs))
        .sqlx_logging(false);

    // Set SQLite PRAGMAs for writer connection
    opt.map_sqlx_sqlite_opts(|opt| {
        opt.journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .synchronous(sqlx::sqlite::SqliteSynchronous::Normal)
            .busy_timeout(std::time::Duration::from_millis(3000)) // Fail fast (3s) instead of waiting 30s
            .pragma("cache_size", "-128000")
            .pragma("temp_store", "MEMORY")
            .pragma("locking_mode", "NORMAL")
    });

    let db = Database::connect(opt).await?;

    tracing::info!("SQLite writer connection pool initialized (single connection)");

    Ok(db)
}
