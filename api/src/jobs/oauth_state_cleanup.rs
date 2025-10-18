use chrono::Utc;
use sqlx::SqlitePool;

pub struct OAuthStateCleanupJob {
    pool: SqlitePool,
}

impl OAuthStateCleanupJob {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn start(self) {
        // Run cleanup every 10 minutes
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600));

        loop {
            interval.tick().await;

            if let Err(e) = self.cleanup_expired_states().await {
                tracing::error!("OAuth state cleanup job failed: {}", e);
            }
        }
    }

    async fn cleanup_expired_states(&self) -> Result<(), Box<dyn std::error::Error>> {
        let now = Utc::now();

        // Delete all expired OAuth states
        let result = sqlx::query(
            "DELETE FROM oauth_states WHERE expires_at < ?"
        )
        .bind(now)
        .execute(&self.pool)
        .await?;

        let deleted_count = result.rows_affected();

        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired OAuth states", deleted_count);
        }

        Ok(())
    }
}
