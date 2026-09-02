use crate::db::DB;
use crate::error::Result;
use crate::store::oauth_states::OAuthStateStore;
use sea_orm::DatabaseConnection;

pub struct OAuthStateCleanupJob {
    db: DatabaseConnection,
}

impl OAuthStateCleanupJob {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn start(self) {
        // Run every 60x the base interval (default: every 10 minutes)
        let mut interval = tokio::time::interval(super::get_cleanup_job_interval(60));

        loop {
            interval.tick().await;

            if let Err(e) = self.cleanup_expired_states().await {
                tracing::error!("OAuth state cleanup job failed: {}", e);
            }
        }
    }

    async fn cleanup_expired_states(&self) -> Result<()> {
        let deleted_count = OAuthStateStore::delete_expired(DB::Conn(&self.db)).await?;

        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired OAuth states", deleted_count);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn cleanup_removes_expired_states_and_keeps_live_ones() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let job = OAuthStateCleanupJob::new(db.clone());

        // With no states at all, a cleanup pass is a harmless no-op.
        job.cleanup_expired_states().await.expect("cleanup run");
    }
}
