pub mod models;

use sqlx::{sqlite::SqlitePoolOptions, SqlitePool};

pub async fn init_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    // Extract database file path
    let db_path = database_url.strip_prefix("sqlite:").unwrap_or(database_url);
    let db_exists = std::path::Path::new(db_path).exists();

    // Create parent directory if it doesn't exist
    if let Some(parent) = std::path::Path::new(db_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| sqlx::Error::Io(e))?;
    }

    let pool = SqlitePoolOptions::new()
        .max_connections(100) // Increased from 5 to 100 for high concurrency
        .min_connections(10) // Keep 10 connections alive
        .acquire_timeout(std::time::Duration::from_secs(30))
        .idle_timeout(std::time::Duration::from_secs(600))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(database_url)
        .await?;

    // Set page_size ONLY if database doesn't exist (must be set before any tables)
    if !db_exists {
        sqlx::query("PRAGMA page_size = 8192;")
            .execute(&pool)
            .await?;
    }

    // Enable WAL mode for better concurrency
    sqlx::query("PRAGMA journal_mode = WAL;")
        .execute(&pool)
        .await?;

    // Optimize WAL mode performance
    sqlx::query("PRAGMA synchronous = NORMAL;") // Faster than FULL, still safe with WAL
        .execute(&pool)
        .await?;

    sqlx::query("PRAGMA busy_timeout = 10000;") // Wait up to 10 seconds on locks
        .execute(&pool)
        .await?;

    sqlx::query("PRAGMA cache_size = -128000;") // 128MB cache (negative = KB)
        .execute(&pool)
        .await?;

    sqlx::query("PRAGMA wal_autocheckpoint = 0;") // Disable auto-checkpoint, manual control
        .execute(&pool)
        .await?;

    sqlx::query("PRAGMA temp_store = MEMORY;") // Use memory for temp tables
        .execute(&pool)
        .await?;

    sqlx::query("PRAGMA mmap_size = 536870912;") // 512MB memory-mapped I/O
        .execute(&pool)
        .await?;

    sqlx::query("PRAGMA locking_mode = NORMAL;") // Allow multiple processes
        .execute(&pool)
        .await?;

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;

    Ok(pool)
}
