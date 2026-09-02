use crate::db::DB;
use crate::entities::prelude::TokenRefreshLocks;
use crate::entities::token_refresh_locks;
use crate::error::Result;
use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

pub struct TokenRefreshLockStore;

impl TokenRefreshLockStore {
    /// Try to acquire a refresh lock for a user
    /// Returns true if lock was acquired, false if already locked
    pub async fn acquire_lock(db: DB<'_>, user_id: &str, timeout_seconds: i64) -> Result<bool> {
        let now = Utc::now();
        let expires_at = now + Duration::seconds(timeout_seconds);

        // Clean up expired locks first
        Self::cleanup_expired_locks(db.clone()).await?;

        // Try to insert lock
        let new_lock = token_refresh_locks::ActiveModel {
            user_id: Set(user_id.to_string()),
            acquired_at: Set(now.naive_utc()),
            expires_at: Set(expires_at.naive_utc()),
        };

        match new_lock.insert(&db).await {
            Ok(_) => Ok(true),
            Err(sea_orm::DbErr::Exec(sea_orm::RuntimeErr::SqlxError(sqlx::Error::Database(
                db_err,
            )))) if db_err.is_unique_violation() => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    /// Release a refresh lock for a user
    pub async fn release_lock(db: DB<'_>, user_id: &str) -> Result<()> {
        TokenRefreshLocks::delete_many()
            .filter(token_refresh_locks::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;

        Ok(())
    }

    /// Clean up expired locks
    pub async fn cleanup_expired_locks(db: DB<'_>) -> Result<()> {
        let now = Utc::now().naive_utc();

        TokenRefreshLocks::delete_many()
            .filter(token_refresh_locks::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn locks_are_exclusive_until_released() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        assert!(
            TokenRefreshLockStore::acquire_lock(DB::Conn(&db), "user-1", 60)
                .await
                .unwrap(),
            "first acquisition wins"
        );
        assert!(
            !TokenRefreshLockStore::acquire_lock(DB::Conn(&db), "user-1", 60)
                .await
                .unwrap(),
            "a second concurrent acquisition must lose"
        );

        // A different user is unaffected.
        assert!(
            TokenRefreshLockStore::acquire_lock(DB::Conn(&db), "user-2", 60)
                .await
                .unwrap()
        );

        TokenRefreshLockStore::release_lock(DB::Conn(&db), "user-1")
            .await
            .expect("release");
        assert!(
            TokenRefreshLockStore::acquire_lock(DB::Conn(&db), "user-1", 60)
                .await
                .unwrap(),
            "released locks are re-acquirable"
        );
    }

    #[tokio::test]
    async fn expired_locks_are_swept_on_the_next_acquisition() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        // A lock that expired a minute ago.
        let stale = token_refresh_locks::ActiveModel {
            user_id: Set("stale-user".to_string()),
            acquired_at: Set((Utc::now() - Duration::minutes(2)).naive_utc()),
            expires_at: Set((Utc::now() - Duration::minutes(1)).naive_utc()),
        };
        stale.insert(&db).await.expect("seed expired lock");

        assert!(
            TokenRefreshLockStore::acquire_lock(DB::Conn(&db), "other-user", 60)
                .await
                .unwrap(),
            "acquiring for anyone sweeps the expired lock"
        );
        assert!(
            TokenRefreshLockStore::acquire_lock(DB::Conn(&db), "stale-user", 60)
                .await
                .unwrap(),
            "the swept lock's owner can re-acquire"
        );
    }
}
