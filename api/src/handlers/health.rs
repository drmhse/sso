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

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ConnectOptions, Database, TransactionTrait};
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn public_health_responses_have_a_bounded_non_tenant_shape() {
        let (status, Json(body)) = health().await;
        assert_eq!(status, StatusCode::OK);
        let value = serde_json::to_value(body).expect("serialize health");
        let object = value.as_object().expect("health object");
        assert_eq!(object.len(), 2);
        assert_eq!(
            object.get("status").and_then(|v| v.as_str()),
            Some("healthy")
        );
        assert!(object.get("version").and_then(|v| v.as_str()).is_some());

        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let (status, Json(body)) = readiness(State(db)).await;
        assert_eq!(status, StatusCode::OK);
        let value = serde_json::to_value(body).expect("serialize readiness");
        let object = value.as_object().expect("readiness object");
        assert_eq!(object.len(), 3);
        assert_eq!(object.get("status").and_then(|v| v.as_str()), Some("ready"));
        assert_eq!(
            object.get("database").and_then(|v| v.as_str()),
            Some("connected")
        );
        assert!(object.get("version").and_then(|v| v.as_str()).is_some());
        for forbidden in ["tenant", "organization", "user", "email", "database_url"] {
            assert!(!object.contains_key(forbidden));
        }
    }

    #[tokio::test]
    async fn readiness_fails_closed_after_database_disconnect() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        let readiness_db = db.clone();
        db.close().await.expect("close database pool");

        let (status, Json(body)) = readiness(State(readiness_db)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let value = serde_json::to_value(body).expect("serialize readiness");
        assert_eq!(value["status"], "unhealthy");
        assert_eq!(value["database"], "disconnected");
    }

    #[tokio::test]
    async fn readiness_fails_within_the_pool_acquire_bound_when_exhausted() {
        let mut options = ConnectOptions::new("sqlite::memory:");
        options
            .min_connections(1)
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(100));
        let db = Database::connect(options).await.expect("connect sqlite");
        let transaction = db.begin().await.expect("occupy only connection");

        let started = Instant::now();
        let (status, Json(body)) = readiness(State(db.clone())).await;
        let elapsed = started.elapsed();
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            serde_json::to_value(body).expect("serialize readiness")["database"],
            "disconnected"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "readiness exceeded configured acquisition bound: {elapsed:?}"
        );

        transaction.rollback().await.expect("release connection");
        let (recovered, _) = readiness(State(db)).await;
        assert_eq!(recovered, StatusCode::OK);
    }
}
