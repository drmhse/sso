use axum::{
    async_trait,
    body::Body,
    extract::rejection::JsonRejection,
    extract::FromRequest,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)] // Some error variants are kept for future use
pub enum AppError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("SeaORM database error: {0}")]
    SeaOrmDatabase(#[from] sea_orm::DbErr),

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Audit error: {0}")]
    Audit(#[from] anyhow::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Feature not available in tier: {0}")]
    FeatureNotAvailableInTier(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Duplicate constraint violation: {0}")]
    DuplicateConstraint(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("Stripe error: {0}")]
    Stripe(String),

    #[error("Billing error: {0}")]
    Billing(String),

    #[error("Token expired")]
    TokenExpired,

    #[error("Device code expired")]
    DeviceCodeExpired,

    #[error("Device code pending")]
    DeviceCodePending,

    #[error("Service limit exceeded: {0}")]
    ServiceLimitExceeded(String),

    #[error("Team limit exceeded: {0}")]
    TeamLimitExceeded(String),

    #[error("Invitation expired")]
    InvitationExpired,

    #[error("Organization not active")]
    OrganizationNotActive,

    #[error("Too many requests: {0}")]
    TooManyRequests(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Generic error: {0}")]
    Generic(String),
}

impl From<Box<dyn std::error::Error>> for AppError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        AppError::Generic(err.to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Database(ref e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
            AppError::SeaOrmDatabase(ref e) => {
                tracing::error!("SeaORM database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
            AppError::Jwt(ref e) => {
                tracing::error!("JWT error: {:?}", e);
                (StatusCode::UNAUTHORIZED, "Invalid token")
            }
            AppError::Audit(ref e) => {
                tracing::error!("Audit error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Audit logging error")
            }
            AppError::NotFound(ref msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            AppError::Unauthorized(ref msg) => (StatusCode::UNAUTHORIZED, msg.as_str()),
            AppError::Forbidden(ref msg) => (StatusCode::FORBIDDEN, msg.as_str()),
            AppError::FeatureNotAvailableInTier(ref msg) => (StatusCode::FORBIDDEN, msg.as_str()),
            AppError::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::DuplicateConstraint(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::InternalServerError(ref msg) => {
                tracing::error!("Internal server error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str())
            }
            AppError::OAuth(ref msg) => {
                tracing::error!("OAuth error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str())
            }
            AppError::Stripe(ref msg) => {
                tracing::error!("Stripe error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str())
            }
            AppError::Billing(ref msg) => {
                tracing::error!("Billing error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str())
            }
            AppError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired"),
            AppError::DeviceCodeExpired => (StatusCode::BAD_REQUEST, "Device code expired"),
            AppError::DeviceCodePending => (StatusCode::BAD_REQUEST, "Authorization pending"),
            AppError::ServiceLimitExceeded(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::TeamLimitExceeded(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::InvitationExpired => (StatusCode::BAD_REQUEST, "Invitation has expired"),
            AppError::OrganizationNotActive => {
                (StatusCode::FORBIDDEN, "Organization is not active")
            }
            AppError::TooManyRequests(ref msg) => (StatusCode::TOO_MANY_REQUESTS, msg.as_str()),
            AppError::Io(ref e) => {
                tracing::error!("IO error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal IO error")
            }
            AppError::Generic(ref msg) => {
                tracing::error!("Generic error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, msg.as_str())
            }
        };

        let body = Json(json!({
            "error": error_message,
            "error_code": match self {
                AppError::ServiceLimitExceeded(_) => "SERVICE_LIMIT_EXCEEDED",
                AppError::TeamLimitExceeded(_) => "TEAM_LIMIT_EXCEEDED",
                AppError::InvitationExpired => "INVITATION_EXPIRED",
                AppError::OrganizationNotActive => "ORGANIZATION_NOT_ACTIVE",
                AppError::DeviceCodeExpired => "DEVICE_CODE_EXPIRED",
                AppError::DeviceCodePending => "DEVICE_CODE_PENDING",
                AppError::NotFound(_) => "NOT_FOUND",
                AppError::Unauthorized(_) => "UNAUTHORIZED",
                AppError::Forbidden(_) => "FORBIDDEN",
                AppError::FeatureNotAvailableInTier(_) => "FEATURE_NOT_AVAILABLE_IN_TIER",
                AppError::BadRequest(_) => "BAD_REQUEST",
                AppError::DuplicateConstraint(_) => "DUPLICATE_CONSTRAINT",
                AppError::TokenExpired => "TOKEN_EXPIRED",
                AppError::Database(_) => "DATABASE_ERROR",
                AppError::SeaOrmDatabase(_) => "DATABASE_ERROR",
                AppError::Jwt(_) => "JWT_ERROR",
                AppError::InternalServerError(_) => "INTERNAL_SERVER_ERROR",
                AppError::OAuth(_) => "OAUTH_ERROR",
                AppError::Stripe(_) => "STRIPE_ERROR",
                AppError::Billing(_) => "BILLING_ERROR",
                AppError::Audit(_) => "AUDIT_ERROR",
                AppError::TooManyRequests(_) => "TOO_MANY_REQUESTS",
                AppError::Io(_) => "IO_ERROR",
                AppError::Generic(_) => "GENERIC_ERROR",
            },
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }));

        (status, body).into_response()
    }
}

/// Custom JSON extractor that returns 400 Bad Request instead of 422 Unprocessable Entity
/// for JSON deserialization errors. This provides better REST API semantics for validation errors.
pub struct Json400<T>(pub T);

#[async_trait]
impl<S, T> FromRequest<S, Body> for Json400<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(
        req: axum::http::Request<Body>,
        state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(json) => Ok(Json400(json.0)),
            Err(rejection) => {
                let error_msg = match rejection {
                    JsonRejection::JsonDataError(err) => {
                        format!("Invalid JSON data: {}", err)
                    }
                    JsonRejection::JsonSyntaxError(err) => {
                        format!("JSON syntax error: {}", err)
                    }
                    JsonRejection::MissingJsonContentType(_) => {
                        "Content-Type must be application/json".to_string()
                    }
                    _ => {
                        format!("JSON parsing error: {}", rejection)
                    }
                };

                Err(AppError::BadRequest(error_msg))
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

/// Convert SeaORM database errors to appropriate error types
/// This handles unique constraint violations by converting them to 400 Bad Request errors
pub fn handle_sea_orm_error(e: sea_orm::DbErr) -> AppError {
    let err_str = e.to_string().to_lowercase();

    if err_str.contains("unique")
        || err_str.contains("duplicate")
        || err_str.contains("already exists")
        || err_str.contains("constraint")
    {
        // For memberships, we want a specific error, for others we can be more generic
        let msg = if err_str.contains("memberships") {
            "User is already a member of this organization".to_string()
        } else if err_str.contains("services") && err_str.contains("slug") {
            "Service with this slug already exists in this organization".to_string()
        } else if err_str.contains("plans") && err_str.contains("name") {
            "A plan with this name already exists for this service".to_string()
        } else if err_str.contains("users") && err_str.contains("email") {
            "Email is already taken".to_string()
        } else {
            "A record with this information already exists".to_string()
        };
        AppError::DuplicateConstraint(msg)
    } else {
        AppError::SeaOrmDatabase(e)
    }
}

/// Check if a SeaORM error is a retryable deadlock/lock error
/// MySQL error 1213: Deadlock found when trying to get lock
/// MySQL error 1205: Lock wait timeout exceeded
pub fn is_deadlock_error(e: &sea_orm::DbErr) -> bool {
    let err_str = e.to_string().to_lowercase();
    err_str.contains("deadlock")
        || err_str.contains("1213")
        || err_str.contains("lock wait timeout")
        || err_str.contains("1205")
        || err_str.contains("database is locked")
        || err_str.contains("busy")
        || err_str.contains("timed out")
}

/// Check if an AppError is a retryable deadlock/lock error
/// This checks both SeaORM database errors and SQLx errors wrapped in AppError
pub fn is_deadlock_app_error(e: &AppError) -> bool {
    match e {
        AppError::SeaOrmDatabase(db_err) => is_deadlock_error(db_err),
        AppError::Database(sqlx_err) => {
            let err_str = sqlx_err.to_string().to_lowercase();
            err_str.contains("deadlock")
                || err_str.contains("1213")
                || err_str.contains("lock wait timeout")
                || err_str.contains("1205")
                || err_str.contains("database is locked")
                || err_str.contains("busy")
                || err_str.contains("timed out")
        }
        _ => false,
    }
}

/// Execute a transactional operation with automatic retry on SQLite busy/deadlock errors.
/// This is the recommended way to handle database contention in handlers.
///
/// # Arguments
/// * `db` - Main database connection (used for reads on PostgreSQL/MySQL, and as fallback)
/// * `db_writer` (SQLite only) - Dedicated single-connection writer pool
/// * `operation_name` - Name for logging
/// * `operation` - Closure receiving DB enum
///
/// # Example
/// ```ignore
/// // For SQLite:
/// with_retrying_transaction(&state.db, &state.db_writer, "create_org", |db| { ... }).await?;
/// // For PostgreSQL/MySQL:
/// with_retrying_transaction(&state.db, "create_org", |db| { ... }).await?;
/// ```
#[cfg(feature = "db_sqlite")]
pub async fn with_retrying_transaction<F, T>(
    _db: &sea_orm::DatabaseConnection, // Reader pool - not used for writes on SQLite
    db_writer: &sea_orm::DatabaseConnection, // Single-connection writer pool
    operation_name: &str,
    operation: F,
) -> Result<T>
where
    F: for<'a> Fn(
        crate::store::DB<'a>,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>>,
    T: Send,
{
    use crate::store::DB;
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
        crate::store::DB<'a>,
    )
        -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T>> + Send + 'a>>,
    T: Send,
{
    use crate::store::DB;

    let max_retries = 25u32;
    let mut attempts = 0u32;

    loop {
        attempts += 1;

        // ===== PostgreSQL/MySQL: Use standard SeaORM transactions =====
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
