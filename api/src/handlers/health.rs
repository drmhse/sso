use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use sea_orm::{ConnectionTrait, DatabaseConnection, Statement};
use serde::Serialize;

const BUILD_VERSION: &str = env!("AUTHOS_BUILD_VERSION");

#[derive(Serialize)]
pub struct HealthResponse {
    status: &'static str,
    version: &'static str,
}

#[derive(Serialize)]
pub struct ReadinessResponse {
    status: &'static str,
    version: &'static str,
    database: &'static str,
}

/// Simple health check endpoint
/// Returns 200 OK if the service is running
pub async fn health() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "healthy",
            version: BUILD_VERSION,
        }),
    )
}

/// Liveness probe endpoint
/// Returns 200 OK if the service is alive (minimal check)
pub async fn liveness() -> StatusCode {
    StatusCode::OK
}

/// Readiness probe endpoint
/// Returns 200 OK if the service is ready to accept traffic (checks DB connection)
pub async fn readiness(db: State<DatabaseConnection>) -> (StatusCode, Json<ReadinessResponse>) {
    // Try to ping the database
    let db_status = match db
        .execute(Statement::from_string(
            db.get_database_backend(),
            "SELECT 1".to_string(),
        ))
        .await
    {
        Ok(_) => "connected",
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ReadinessResponse {
                    status: "unhealthy",
                    version: BUILD_VERSION,
                    database: "disconnected",
                }),
            )
        }
    };

    (
        StatusCode::OK,
        Json(ReadinessResponse {
            status: "ready",
            version: BUILD_VERSION,
            database: db_status,
        }),
    )
}
