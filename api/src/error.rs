use axum::{
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

    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("OAuth error: {0}")]
    OAuth(String),

    #[error("Stripe error: {0}")]
    Stripe(String),

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
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::Database(ref e) => {
                tracing::error!("Database error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Database error")
            }
            AppError::Jwt(ref e) => {
                tracing::error!("JWT error: {:?}", e);
                (StatusCode::UNAUTHORIZED, "Invalid token")
            }
            AppError::NotFound(ref msg) => (StatusCode::NOT_FOUND, msg.as_str()),
            AppError::Unauthorized(ref msg) => (StatusCode::UNAUTHORIZED, msg.as_str()),
            AppError::Forbidden(ref msg) => (StatusCode::FORBIDDEN, msg.as_str()),
            AppError::BadRequest(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
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
            AppError::TokenExpired => (StatusCode::UNAUTHORIZED, "Token expired"),
            AppError::DeviceCodeExpired => (StatusCode::BAD_REQUEST, "Device code expired"),
            AppError::DeviceCodePending => (StatusCode::BAD_REQUEST, "Authorization pending"),
            AppError::ServiceLimitExceeded(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::TeamLimitExceeded(ref msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            AppError::InvitationExpired => (StatusCode::BAD_REQUEST, "Invitation has expired"),
            AppError::OrganizationNotActive => {
                (StatusCode::FORBIDDEN, "Organization is not active")
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
                AppError::BadRequest(_) => "BAD_REQUEST",
                AppError::TokenExpired => "TOKEN_EXPIRED",
                AppError::Database(_) => "DATABASE_ERROR",
                AppError::Jwt(_) => "JWT_ERROR",
                AppError::InternalServerError(_) => "INTERNAL_SERVER_ERROR",
                AppError::OAuth(_) => "OAUTH_ERROR",
                AppError::Stripe(_) => "STRIPE_ERROR",
            },
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }));

        (status, body).into_response()
    }
}

pub type Result<T> = std::result::Result<T, AppError>;
