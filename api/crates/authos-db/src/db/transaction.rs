//! Transaction helpers: retrying write transactions and deadlock backoff.
//!
//! Lives in the db layer rather than beside the error types because it is
//! connection machinery; `error` re-exports it for existing call sites.

use crate::db::connection::DB;
use crate::error::{is_deadlock_app_error, is_deadlock_error, AppError, Result};

/// Run a write transaction, retrying on contention.
///
/// Takes a fourth `db_writer` argument under `db_sqlite` (writes go through the
/// single-connection writer pool) and three arguments otherwise.
#[cfg(feature = "db_sqlite")]
pub async fn with_retrying_transaction<F, T>(
    _db: &sea_orm::DatabaseConnection, // Reader pool - not used for writes on SQLite
    db_writer: &sea_orm::DatabaseConnection, // Single-connection writer pool
    operation_name: &str,
    operation: F,
) -> Result<T>
where
    F: for<'a> Fn(
        DB<'a>,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>>,
    T: Send,
{
    use sea_orm::TransactionTrait;

    let max_retries = 25u32;
    let mut attempts = 0u32;

    loop {
        attempts += 1;

        // Use the single-connection writer pool for all writes
        // We use begin() to get a DatabaseTransaction which holds the connection exclusive
        let txn = match db_writer.begin().await {
            Ok(txn) => txn,
            Err(e) => {
                if is_deadlock_error(&e) && attempts <= max_retries {
                    let delay_ms = calculate_retry_delay(attempts);
                    tracing::warn!(
                        operation = %operation_name,
                        attempt = attempts,
                        phase = "begin",
                        "SQLite busy on begin(), retrying"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    continue;
                }
                return Err(AppError::SeaOrmDatabase(e));
            }
        };

        // Execute operation using the transaction wrapper
        // passing DB::Tx guarantees operations use the transaction connection
        let result = match operation(DB::Tx(&txn)).await {
            Ok(result) => result,
            Err(e) => {
                // Rollback on error
                let _ = txn.rollback().await;
                if is_deadlock_app_error(&e) && attempts <= max_retries {
                    let delay_ms = calculate_retry_delay(attempts);
                    tracing::warn!(
                        operation = %operation_name,
                        attempt = attempts,
                        phase = "execute",
                        "Database contention, retrying"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    continue;
                }
                return Err(e);
            }
        };

        // Commit transaction
        match txn.commit().await {
            Ok(_) => return Ok(result),
            Err(e) => {
                if is_deadlock_error(&e) && attempts <= max_retries {
                    let delay_ms = calculate_retry_delay(attempts);
                    tracing::warn!(
                        operation = %operation_name,
                        attempt = attempts,
                        phase = "commit",
                        "Database contention on commit, retrying"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                    continue;
                }
                return Err(AppError::SeaOrmDatabase(e));
            }
        }
    }
}

/// Execute a transactional operation with automatic retry on deadlock errors.
/// PostgreSQL/MySQL version using standard SeaORM transactions.
#[cfg(not(feature = "db_sqlite"))]
pub async fn with_retrying_transaction<F, T>(
    db: &sea_orm::DatabaseConnection,
    operation_name: &str,
    operation: F,
) -> Result<T>
where
    F: for<'a> Fn(
        DB<'a>,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>>,
    T: Send,
{
    let max_retries = 25u32;
    let mut attempts = 0u32;

    loop {
        attempts += 1;

        // PostgreSQL/MySQL: Use standard SeaORM transactions
        #[cfg(not(feature = "db_sqlite"))]
        {
            use sea_orm::TransactionTrait;

            let tx = match db.begin().await {
                Ok(tx) => tx,
                Err(e) => {
                    if is_deadlock_error(&e) && attempts <= max_retries {
                        let delay_ms = calculate_retry_delay(attempts);
                        tracing::warn!(
                            operation = %operation_name,
                            attempt = attempts,
                            phase = "begin",
                            "Database contention, retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(AppError::SeaOrmDatabase(e));
                }
            };

            // Execute operation using DB::Tx
            let result = match operation(DB::Tx(&tx)).await {
                Ok(result) => result,
                Err(e) => {
                    // Rollback is manual here since we want to handle retry logic
                    let _ = tx.rollback().await;

                    if is_deadlock_app_error(&e) && attempts <= max_retries {
                        let delay_ms = calculate_retry_delay(attempts);
                        tracing::warn!(
                            operation = %operation_name,
                            attempt = attempts,
                            phase = "execute",
                            "Database contention, retrying"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(e);
                }
            };

            // Commit with retry
            match tx.commit().await {
                Ok(_) => return Ok(result),
                Err(e) => {
                    if is_deadlock_error(&e) && attempts <= max_retries {
                        let delay_ms = calculate_retry_delay(attempts);
                        tracing::warn!(
                            operation = %operation_name,
                            attempt = attempts,
                            phase = "commit",
                            "Database contention, retrying entire transaction"
                        );
                        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                        continue;
                    }
                    return Err(AppError::SeaOrmDatabase(e));
                }
            }
        }
    }
}

/// Calculate retry delay with exponential backoff and jitter
/// For SQLite with 8 workers, we need faster retries to fit within SDK timeout (30s)
fn calculate_retry_delay(attempt: u32) -> u64 {
    // Reduced delays: 20ms, 40ms, 80ms, ... up to ~1280ms (vs previous ~5120ms)
    let base_delay_ms = 10 * (1 << attempt.min(7));
    let jitter_ms = rand::random::<u64>() % (base_delay_ms / 2);
    base_delay_ms + jitter_ms
}

/// Execute a database operation with automatic retry on deadlock errors
/// Uses exponential backoff with jitter for retry delays
pub async fn with_deadlock_retry<F, Fut, T>(
    operation_name: &str,
    max_retries: u32,
    operation: F,
) -> std::result::Result<T, sea_orm::DbErr>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = std::result::Result<T, sea_orm::DbErr>>,
{
    let mut attempts = 0;
    loop {
        attempts += 1;
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) if is_deadlock_error(&e) && attempts <= max_retries => {
                // Calculate delay with exponential backoff and jitter
                let base_delay_ms = 10 * (1 << attempts.min(6)); // 20ms, 40ms, 80ms, ... up to 640ms
                let jitter_ms = rand::random::<u64>() % (base_delay_ms / 2);
                let delay_ms = base_delay_ms + jitter_ms;

                tracing::warn!(
                    operation = %operation_name,
                    attempt = attempts,
                    max_retries = max_retries,
                    delay_ms = delay_ms,
                    "Deadlock detected, retrying operation"
                );

                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
            Err(e) => {
                if is_deadlock_error(&e) {
                    tracing::error!(
                        operation = %operation_name,
                        attempts = attempts,
                        "Deadlock retry exhausted, operation failed"
                    );
                }
                return Err(e);
            }
        }
    }
}
