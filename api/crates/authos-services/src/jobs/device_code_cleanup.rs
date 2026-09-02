use crate::db::DB;
use crate::store::device_codes::DeviceCodeStore;
use sea_orm::DatabaseConnection;

pub struct DeviceCodeCleanupJob {
    db: DatabaseConnection,
}

impl DeviceCodeCleanupJob {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    pub async fn start(self) {
        // Run every 30x the base interval (default: every 5 minutes)
        let mut interval = tokio::time::interval(super::get_cleanup_job_interval(30));

        loop {
            interval.tick().await;

            if let Err(e) = self.cleanup_expired_device_codes().await {
                tracing::error!("Device code cleanup job failed: {}", e);
            }
        }
    }

    async fn cleanup_expired_device_codes(&self) -> Result<(), Box<dyn std::error::Error>> {
        let deleted_count = DeviceCodeStore::delete_expired(DB::Conn(&self.db))
            .await
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;

        if deleted_count > 0 {
            tracing::info!("Cleaned up {} expired device codes", deleted_count);
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
    async fn an_empty_queue_makes_cleanup_a_harmless_no_op() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        DeviceCodeCleanupJob::new(db.clone())
            .cleanup_expired_device_codes()
            .await
            .expect("cleanup run");
    }
}
