use crate::entities::prelude::TokenRefreshLocks;
use crate::entities::token_refresh_locks;
use crate::error::Result;
use crate::store::DB;
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
