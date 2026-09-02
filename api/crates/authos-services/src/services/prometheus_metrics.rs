use crate::error::Result;
use metrics::{counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend};

/// Prometheus metrics service for tracking platform-wide operational metrics
/// Exposes metrics in Prometheus format via /metrics endpoint
pub struct PrometheusMetricsService {
    db: DatabaseConnection,
}

impl PrometheusMetricsService {
    pub fn new(db: DatabaseConnection) -> Self {
        // Register metric descriptions (called once during initialization)
        Self::register_metrics();
        Self { db }
    }

    /// Register all custom metrics with descriptions
    fn register_metrics() {
        // Active users gauge
        describe_gauge!(
            "sso_active_users_total",
            "Total number of active users across all organizations"
        );

        // Login failures counter
        describe_counter!(
            "sso_login_failures_total",
            "Total number of failed login attempts, labeled by failure reason"
        );

        // Job queue depth gauge
        describe_gauge!(
            "sso_job_queue_depth",
            "Number of pending jobs in the system job queue"
        );

        // Webhook delivery latency histogram
        describe_histogram!(
            "sso_webhook_delivery_latency_seconds",
            "Time taken to deliver webhooks to endpoints"
        );

        // Additional useful metrics
        describe_gauge!(
            "sso_total_organizations",
            "Total number of organizations in the platform"
        );

        describe_gauge!(
            "sso_pending_jobs_total",
            "Total number of pending jobs by status"
        );

        describe_counter!(
            "sso_auth_tokens_issued_total",
            "Total number of authentication tokens issued"
        );

        describe_counter!(
            "sso_mfa_challenges_total",
            "Total number of MFA challenges issued"
        );

        // API request metrics
        describe_counter!(
            "sso_api_requests_total",
            "Total API requests by endpoint, method, and status code"
        );

        describe_counter!(
            "sso_api_errors_total",
            "Total API errors by endpoint and error type"
        );

        // Authentication metrics
        describe_counter!(
            "sso_auth_attempts_total",
            "Authentication attempts by method (password, passkey, oauth) and result (success, failure)"
        );

        // MFA adoption metrics
        describe_gauge!(
            "sso_mfa_adoption_percentage",
            "Percentage of users with MFA enabled"
        );

        describe_gauge!(
            "sso_mfa_enabled_users_total",
            "Total number of users with MFA enabled"
        );

        // SIEM delivery metrics
        describe_counter!(
            "sso_siem_delivery_total",
            "Total SIEM audit log deliveries by result (success, failure)"
        );

        describe_counter!(
            "sso_siem_delivery_failures_total",
            "Total failed SIEM deliveries by provider type"
        );

        // Job processing metrics
        describe_histogram!(
            "sso_job_processing_duration_seconds",
            "Time taken to process jobs by job type"
        );

        // HTTP request latency metrics
        describe_histogram!(
            "sso_http_request_duration_seconds",
            "HTTP request duration in seconds by method, route pattern, and status class"
        );

        // Database pool metrics
        describe_gauge!(
            "sso_db_pool_connections_total",
            "Current number of connections in the database pool"
        );

        describe_gauge!(
            "sso_db_pool_connections_idle",
            "Number of idle connections in the database pool"
        );

        describe_gauge!(
            "sso_db_pool_connections_max",
            "Maximum configured connections in the database pool"
        );
    }

    /// Update active users count (called periodically)
    pub async fn update_active_users(&self) -> Result<()> {
        let count = self.active_user_count().await?;
        self.record_active_user_metrics(count);

        Ok(())
    }

    async fn active_user_count(&self) -> Result<u64> {
        use crate::entities::prelude::Users;
        use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};

        Ok(Users::find()
            .filter(crate::entities::users::Column::DeletedAt.is_null())
            .count(&self.db)
            .await?)
    }

    fn record_active_user_metrics(&self, active_users: u64) {
        gauge!("sso_active_users_total", active_users as f64);
    }

    /// Update total organizations count (called periodically)
    pub async fn update_organizations_count(&self) -> Result<()> {
        use crate::entities::prelude::Organizations;
        use sea_orm::{EntityTrait, PaginatorTrait};

        let count = Organizations::find().count(&self.db).await?;

        gauge!("sso_total_organizations", count as f64);

        Ok(())
    }

    /// Update job queue depth (called periodically)
    pub async fn update_job_queue_depth(&self) -> Result<()> {
        use crate::db::DB;
        use crate::store::system_jobs::SystemJobStore;

        let counts =
            SystemJobStore::count_by_statuses(DB::Conn(&self.db), &["pending", "processing"])
                .await?;
        let pending_count = *counts.get("pending").unwrap_or(&0) as u64;
        let processing_count = *counts.get("processing").unwrap_or(&0) as u64;
        gauge!("sso_job_queue_depth", pending_count as f64);

        gauge!("sso_pending_jobs_total", pending_count as f64, "status" => "pending");
        gauge!("sso_pending_jobs_total", processing_count as f64, "status" => "processing");

        Ok(())
    }

    /// Publish pool gauges. Worth doing on SQLite too: sqlx still pools, so
    /// total climbing while idle does not is a connection leak.
    pub fn update_db_pool_metrics(&self) {
        match self.db.get_database_backend() {
            #[cfg(feature = "db_sqlite")]
            DbBackend::Sqlite => {
                let pool = self.db.get_sqlite_connection_pool();
                let total = pool.size();
                let idle = pool.num_idle();
                let max = pool.options().get_max_connections();

                gauge!("sso_db_pool_connections_total", total as f64, "backend" => "sqlite");
                gauge!("sso_db_pool_connections_idle", idle as f64, "backend" => "sqlite");
                gauge!("sso_db_pool_connections_max", max as f64, "backend" => "sqlite");

                tracing::debug!(total = total, idle = idle, max = max, "SQLite pool stats");
            }
            #[cfg(feature = "db_psql")]
            DbBackend::Postgres => {
                let pool = self.db.get_postgres_connection_pool();
                let total = pool.size();
                let idle = pool.num_idle();
                let max = pool.options().get_max_connections();

                gauge!("sso_db_pool_connections_total", total as f64, "backend" => "postgres");
                gauge!("sso_db_pool_connections_idle", idle as f64, "backend" => "postgres");
                gauge!("sso_db_pool_connections_max", max as f64, "backend" => "postgres");

                tracing::debug!(
                    total = total,
                    idle = idle,
                    max = max,
                    "PostgreSQL pool stats"
                );
            }
            #[cfg(feature = "db_mysql")]
            DbBackend::MySql => {
                let pool = self.db.get_mysql_connection_pool();
                let total = pool.size();
                let idle = pool.num_idle();
                let max = pool.options().get_max_connections();

                gauge!("sso_db_pool_connections_total", total as f64, "backend" => "mysql");
                gauge!("sso_db_pool_connections_idle", idle as f64, "backend" => "mysql");
                gauge!("sso_db_pool_connections_max", max as f64, "backend" => "mysql");

                tracing::debug!(total = total, idle = idle, max = max, "MySQL pool stats");
            }
            #[allow(unreachable_patterns)]
            _ => {
                tracing::trace!("No pool stats available for database backend");
            }
        }
    }

    /// Record a login failure
    pub fn record_login_failure(reason: &str) {
        counter!("sso_login_failures_total", 1, "reason" => reason.to_string());
    }

    /// Record a webhook delivery attempt with latency
    pub fn record_webhook_delivery(duration_seconds: f64) {
        histogram!("sso_webhook_delivery_latency_seconds", duration_seconds);
    }

    /// Record an authentication token issuance
    pub fn record_token_issued() {
        counter!("sso_auth_tokens_issued_total", 1);
    }

    /// Record an MFA challenge
    pub fn record_mfa_challenge() {
        counter!("sso_mfa_challenges_total", 1);
    }

    /// Record an API request
    pub fn record_api_request(endpoint: &str, method: &str, status: u16) {
        counter!(
            "sso_api_requests_total", 1,
            "endpoint" => endpoint.to_string(),
            "method" => method.to_string(),
            "status" => status.to_string()
        );
    }

    /// Record an API error
    pub fn record_api_error(endpoint: &str, error_type: &str) {
        counter!(
            "sso_api_errors_total", 1,
            "endpoint" => endpoint.to_string(),
            "error_type" => error_type.to_string()
        );
    }

    /// Record an authentication attempt
    pub fn record_auth_attempt(method: &str, result: &str) {
        counter!(
            "sso_auth_attempts_total", 1,
            "method" => method.to_string(),
            "result" => result.to_string()
        );
    }

    /// Record a SIEM delivery attempt
    pub fn record_siem_delivery(success: bool) {
        let result = if success { "success" } else { "failure" };
        counter!("sso_siem_delivery_total", 1, "result" => result.to_string());
    }

    /// Record a failed SIEM delivery
    pub fn record_siem_delivery_failure(provider_type: &str) {
        counter!(
            "sso_siem_delivery_failures_total", 1,
            "provider_type" => provider_type.to_string()
        );
    }

    /// Record job processing duration
    pub fn record_job_processing(job_type: &str, duration_seconds: f64) {
        histogram!(
            "sso_job_processing_duration_seconds",
            duration_seconds,
            "job_type" => job_type.to_string()
        );
    }

    /// Update MFA adoption percentage (called periodically)
    pub async fn update_mfa_adoption(&self) -> Result<()> {
        let total_users = self.active_user_count().await?;
        let mfa_users = self.mfa_user_count().await?;

        self.record_mfa_adoption_metrics(total_users, mfa_users);

        Ok(())
    }

    async fn mfa_user_count(&self) -> Result<u64> {
        use crate::entities::user_totp_secrets;
        use sea_orm::{EntityTrait, PaginatorTrait};

        Ok(user_totp_secrets::Entity::find().count(&self.db).await?)
    }

    fn record_mfa_adoption_metrics(&self, total_users: u64, mfa_users: u64) {
        gauge!("sso_mfa_enabled_users_total", mfa_users as f64);

        let adoption_percentage = if total_users > 0 {
            (mfa_users as f64 / total_users as f64) * 100.0
        } else {
            0.0
        };
        gauge!("sso_mfa_adoption_percentage", adoption_percentage);
    }

    async fn update_user_security_metrics(&self) -> Result<()> {
        let total_users = self.active_user_count().await?;
        let mfa_users = self.mfa_user_count().await?;

        self.record_active_user_metrics(total_users);
        self.record_mfa_adoption_metrics(total_users, mfa_users);

        Ok(())
    }

    /// Update all metrics (called periodically by a background task)
    pub async fn update_all(&self) -> Result<()> {
        self.update_user_security_metrics().await?;
        self.update_organizations_count().await?;
        self.update_job_queue_depth().await?;
        self.update_db_pool_metrics();
        Ok(())
    }

    /// Initialize metrics exporter and return recorder handle
    /// This should be called once during application startup
    pub fn initialize_exporter() -> std::io::Result<metrics_exporter_prometheus::PrometheusHandle> {
        let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
        let handle = builder
            .install_recorder()
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        Ok(handle)
    }
}

/// Background task to update metrics periodically
pub async fn metrics_updater_task(db: DatabaseConnection) {
    let service = PrometheusMetricsService::new(db);
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        interval.tick().await;

        if let Err(e) = service.update_all().await {
            tracing::error!("Failed to update Prometheus metrics: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::DB;
    use crate::store::users::UserStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    async fn db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    #[tokio::test]
    async fn metric_updates_run_clean_queries_against_live_tables() {
        let db = db().await;
        UserStore::create(DB::Conn(&db), "metrics-user@example.test", None, false)
            .await
            .expect("create user");

        let service = PrometheusMetricsService::new(db.clone());
        service.update_active_users().await.expect("active users");
        service
            .update_organizations_count()
            .await
            .expect("org count");
        service.update_job_queue_depth().await.expect("queue depth");
        service.update_db_pool_metrics();
        service.update_mfa_adoption().await.expect("mfa adoption");
    }

    #[test]
    fn labeled_recorders_accept_every_metric_shorthand() {
        PrometheusMetricsService::record_login_failure("bad_password");
        PrometheusMetricsService::record_webhook_delivery(0.42);
        PrometheusMetricsService::record_token_issued();
        PrometheusMetricsService::record_mfa_challenge();
        PrometheusMetricsService::record_api_request("/api/user", "GET", 200);
        PrometheusMetricsService::record_api_error("/api/user", "db");
        PrometheusMetricsService::record_auth_attempt("password", "success");
        PrometheusMetricsService::record_siem_delivery(true);
        PrometheusMetricsService::record_siem_delivery_failure("splunk");
        PrometheusMetricsService::record_job_processing("send_email", 0.1);
    }
}
