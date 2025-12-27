use crate::error::Result;
use crate::store::{saml_states::SamlStateStore, DB};
use sea_orm::DatabaseConnection;

pub struct SamlStateCleanupJob {
    db: DatabaseConnection,
}

impl SamlStateCleanupJob {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn start(self) {
        // Run every 60x the base interval (default: every 10 minutes)
        let mut interval = tokio::time::interval(super::get_cleanup_job_interval(60));

        loop {
            interval.tick().await;

            if let Err(e) = self.cleanup_expired_states().await {
                tracing::error!("SAML state cleanup job failed: {}", e);
            }
        }
    }

    async fn cleanup_expired_states(&self) -> Result<()> {
        let deleted_count = SamlStateStore::delete_expired(DB::Conn(&self.db)).await?;

        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired SAML states", deleted_count);
        }

        Ok(())
    }
}
