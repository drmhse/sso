use crate::entities::distributed_locks;
use crate::entities::prelude::DistributedLocks;
use crate::error::Result;
use crate::store::DB;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, ModelTrait, Set};

pub struct DistributedLockStore;

impl DistributedLockStore {
    /// Try to acquire a lock
    pub async fn try_acquire_lock(
        db: DB<'_>,
        lock_key: &str,
        owner_id: &str,
        ttl_seconds: i64,
    ) -> Result<bool> {
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_seconds);

        let now_naive = now.naive_utc();
        let expires_naive = expires_at.naive_utc();

        // First, clean up expired locks
        use sea_orm::ColumnTrait;
        use sea_orm::QueryFilter;
        DistributedLocks::delete_many()
            .filter(distributed_locks::Column::ExpiresAt.lte(now_naive))
            .exec(&db)
            .await?;

        // Try to find existing lock
        let existing_lock = DistributedLocks::find_by_id(lock_key).one(&db).await?;

        if existing_lock.is_some() {
            // Lock already exists and is not expired
            return Ok(false);
        }

        // Try to create the lock
        let lock = distributed_locks::ActiveModel {
            lock_key: Set(lock_key.to_string()),
            owner_id: Set(owner_id.to_string()),
            acquired_at: Set(now_naive),
            expires_at: Set(expires_naive),
        };

        match lock.insert(&db).await {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Race condition: someone else acquired it
        }
    }

    /// Release a lock
    pub async fn release_lock(db: DB<'_>, lock_key: &str, owner_id: &str) -> Result<bool> {
        let lock = DistributedLocks::find_by_id(lock_key).one(&db).await?;

        if let Some(lock) = lock {
            // Only release if we own the lock
            if lock.owner_id == owner_id {
                lock.delete(&db).await?;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Extend lock TTL
    pub async fn extend_lock(
        db: DB<'_>,
        lock_key: &str,
        owner_id: &str,
        ttl_seconds: i64,
    ) -> Result<bool> {
        let lock = DistributedLocks::find_by_id(lock_key).one(&db).await?;

        if let Some(lock) = lock {
            if lock.owner_id == owner_id {
                let expires_at = Utc::now() + chrono::Duration::seconds(ttl_seconds);
                let expires_naive = expires_at.naive_utc();

                let mut lock: distributed_locks::ActiveModel = lock.into_active_model();
                lock.expires_at = Set(expires_naive);
                lock.update(&db).await?;

                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Cleanup expired locks
    pub async fn cleanup_expired_locks(db: DB<'_>) -> Result<u64> {
        use sea_orm::ColumnTrait;
        use sea_orm::QueryFilter;

        let now = Utc::now().naive_utc();

        let result = DistributedLocks::delete_many()
            .filter(distributed_locks::Column::ExpiresAt.lte(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn locks_are_exclusive_per_key_and_owner_scoped() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        assert!(DistributedLockStore::try_acquire_lock(
            DB::Conn(&db),
            "job:nightly",
            "worker-a",
            60
        )
        .await
        .unwrap());
        assert!(
            !DistributedLockStore::try_acquire_lock(DB::Conn(&db), "job:nightly", "worker-b", 60)
                .await
                .unwrap(),
            "a second acquirer must lose while held"
        );

        // Only the owner can release.
        assert!(
            !DistributedLockStore::release_lock(DB::Conn(&db), "job:nightly", "worker-b")
                .await
                .unwrap()
        );
        assert!(
            DistributedLockStore::release_lock(DB::Conn(&db), "job:nightly", "worker-a")
                .await
                .unwrap()
        );
        assert!(
            DistributedLockStore::try_acquire_lock(DB::Conn(&db), "job:nightly", "worker-b", 60)
                .await
                .unwrap(),
            "released locks are re-acquirable"
        );
    }

    #[tokio::test]
    async fn expired_locks_are_swept_and_extend_refreshes_them() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        // Seed an already-expired lock directly.
        let expired = distributed_locks::ActiveModel {
            lock_key: Set("job:stale".to_string()),
            owner_id: Set("dead-worker".to_string()),
            acquired_at: Set((Utc::now() - chrono::Duration::minutes(5)).naive_utc()),
            expires_at: Set((Utc::now() - chrono::Duration::minutes(1)).naive_utc()),
        };
        expired.insert(&db).await.expect("seed expired lock");

        // Acquisition by a new worker sweeps the stale lock and succeeds.
        assert!(DistributedLockStore::try_acquire_lock(
            DB::Conn(&db),
            "job:stale",
            "new-worker",
            60
        )
        .await
        .unwrap());

        // Extending refreshes the TTL for the current owner.
        assert!(
            DistributedLockStore::extend_lock(DB::Conn(&db), "job:stale", "new-worker", 120)
                .await
                .expect("extend")
        );
        DistributedLockStore::cleanup_expired_locks(DB::Conn(&db))
            .await
            .expect("cleanup runs");
    }
}
