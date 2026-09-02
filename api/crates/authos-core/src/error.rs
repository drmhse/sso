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

    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

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
            AppError::ServiceUnavailable(ref msg) => {
                (StatusCode::SERVICE_UNAVAILABLE, msg.as_str())
            }
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
                AppError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
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
