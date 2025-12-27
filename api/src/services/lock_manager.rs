//! Distributed Locking Service - Database-native locks without Redis

use crate::error::Result;
use crate::store::distributed_locks::DistributedLockStore;
use crate::store::DB;
use async_trait::async_trait;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use uuid::Uuid;

/// Lock Manager trait for database-agnostic distributed locking
#[async_trait]
pub trait LockManager: Send + Sync {
    /// Try to acquire a lock with a given key and TTL
    async fn try_acquire_lock(&self, lock_key: &str, ttl_seconds: i64)
        -> Result<Option<LockGuard>>;

    /// Release a lock
    async fn release_lock(&self, guard: LockGuard) -> Result<bool>;

    /// Get the database backend type
    fn backend_type(&self) -> DbBackend;
}

/// Lock guard that holds lock information
#[derive(Debug, Clone)]
pub struct LockGuard {
    pub lock_key: String,
    pub owner_id: String,
    pub backend: DbBackend,
}

/// PostgreSQL Lock Manager using advisory locks
pub struct PostgresLockManager {
    db: DatabaseConnection,
}

impl PostgresLockManager {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }

    /// Convert lock key to a 64-bit integer for PostgreSQL advisory lock
    fn lock_key_to_id(lock_key: &str) -> i64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        lock_key.hash(&mut hasher);
        hasher.finish() as i64
    }
}

#[async_trait]
impl LockManager for PostgresLockManager {
    async fn try_acquire_lock(
        &self,
        lock_key: &str,
        _ttl_seconds: i64,
    ) -> Result<Option<LockGuard>> {
        let lock_id = Self::lock_key_to_id(lock_key);

        // Use pg_try_advisory_lock for non-blocking lock acquisition
        let result = self
            .db
            .query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT pg_try_advisory_lock($1)",
                vec![lock_id.into()],
            ))
            .await?;

        if let Some(row) = result {
            let acquired: bool = row.try_get("", "pg_try_advisory_lock")?;
            if acquired {
                let guard = LockGuard {
                    lock_key: lock_key.to_string(),
                    owner_id: Uuid::new_v4().to_string(),
                    backend: DbBackend::Postgres,
                };
                return Ok(Some(guard));
            }
        }

        Ok(None)
    }

    async fn release_lock(&self, guard: LockGuard) -> Result<bool> {
        let lock_id = Self::lock_key_to_id(&guard.lock_key);

        let result = self
            .db
            .query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT pg_advisory_unlock($1)",
                vec![lock_id.into()],
            ))
            .await?;

        if let Some(row) = result {
            let released: bool = row.try_get("", "pg_advisory_unlock")?;
            return Ok(released);
        }

        Ok(false)
    }

    fn backend_type(&self) -> DbBackend {
        DbBackend::Postgres
    }
}

/// MySQL Lock Manager using GET_LOCK
pub struct MySqlLockManager {
    db: DatabaseConnection,
}

impl MySqlLockManager {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl LockManager for MySqlLockManager {
    async fn try_acquire_lock(
        &self,
        lock_key: &str,
        ttl_seconds: i64,
    ) -> Result<Option<LockGuard>> {
        // MySQL GET_LOCK returns 1 if acquired, 0 if timeout, NULL if error
        let result = self
            .db
            .query_one(Statement::from_sql_and_values(
                DbBackend::MySql,
                "SELECT GET_LOCK(?, ?)",
                vec![lock_key.into(), ttl_seconds.into()],
            ))
            .await?;

        if let Some(row) = result {
            if let Ok(acquired) = row.try_get::<i32>("", "GET_LOCK(?, ?)") {
                if acquired == 1 {
                    let guard = LockGuard {
                        lock_key: lock_key.to_string(),
                        owner_id: Uuid::new_v4().to_string(),
                        backend: DbBackend::MySql,
                    };
                    return Ok(Some(guard));
                }
            }
        }

        Ok(None)
    }

    async fn release_lock(&self, guard: LockGuard) -> Result<bool> {
        let result = self
            .db
            .query_one(Statement::from_sql_and_values(
                DbBackend::MySql,
                "SELECT RELEASE_LOCK(?)",
                vec![guard.lock_key.into()],
            ))
            .await?;

        if let Some(row) = result {
            if let Ok(released) = row.try_get::<i32>("", "RELEASE_LOCK(?)") {
                return Ok(released == 1);
            }
        }

        Ok(false)
    }

    fn backend_type(&self) -> DbBackend {
        DbBackend::MySql
    }
}

/// SQLite Lock Manager using distributed_locks table
pub struct SqliteLockManager {
    db: DatabaseConnection,
}

impl SqliteLockManager {
    pub fn new(db: DatabaseConnection) -> Self {
        Self { db }
    }
}

#[async_trait]
impl LockManager for SqliteLockManager {
    async fn try_acquire_lock(
        &self,
        lock_key: &str,
        ttl_seconds: i64,
    ) -> Result<Option<LockGuard>> {
        let owner_id = Uuid::new_v4().to_string();

        let acquired = DistributedLockStore::try_acquire_lock(
            DB::Conn(&self.db),
            lock_key,
            &owner_id,
            ttl_seconds,
        )
        .await?;

        if acquired {
            let guard = LockGuard {
                lock_key: lock_key.to_string(),
                owner_id,
                backend: DbBackend::Sqlite,
            };
            return Ok(Some(guard));
        }

        Ok(None)
    }

    async fn release_lock(&self, guard: LockGuard) -> Result<bool> {
        DistributedLockStore::release_lock(DB::Conn(&self.db), &guard.lock_key, &guard.owner_id)
            .await
    }

    fn backend_type(&self) -> DbBackend {
        DbBackend::Sqlite
    }
}

/// Enum wrapper for different lock manager implementations
pub enum LockManagerImpl {
    Postgres(PostgresLockManager),
    MySql(MySqlLockManager),
    Sqlite(SqliteLockManager),
}

#[async_trait]
impl LockManager for LockManagerImpl {
    async fn try_acquire_lock(
        &self,
        lock_key: &str,
        ttl_seconds: i64,
    ) -> Result<Option<LockGuard>> {
        match self {
            LockManagerImpl::Postgres(m) => m.try_acquire_lock(lock_key, ttl_seconds).await,
            LockManagerImpl::MySql(m) => m.try_acquire_lock(lock_key, ttl_seconds).await,
            LockManagerImpl::Sqlite(m) => m.try_acquire_lock(lock_key, ttl_seconds).await,
        }
    }

    async fn release_lock(&self, guard: LockGuard) -> Result<bool> {
        match self {
            LockManagerImpl::Postgres(m) => m.release_lock(guard).await,
            LockManagerImpl::MySql(m) => m.release_lock(guard).await,
            LockManagerImpl::Sqlite(m) => m.release_lock(guard).await,
        }
    }

    fn backend_type(&self) -> DbBackend {
        match self {
            LockManagerImpl::Postgres(m) => m.backend_type(),
            LockManagerImpl::MySql(m) => m.backend_type(),
            LockManagerImpl::Sqlite(m) => m.backend_type(),
        }
    }
}

/// Factory function to create the appropriate lock manager based on database backend
pub fn create_lock_manager(db: DatabaseConnection) -> LockManagerImpl {
    match db.get_database_backend() {
        DbBackend::Postgres => LockManagerImpl::Postgres(PostgresLockManager::new(db)),
        DbBackend::MySql => LockManagerImpl::MySql(MySqlLockManager::new(db)),
        DbBackend::Sqlite => LockManagerImpl::Sqlite(SqliteLockManager::new(db)),
    }
}

/// Helper function to execute code with a distributed lock
pub async fn with_lock<F, Fut, T, M>(
    lock_manager: &M,
    lock_key: &str,
    ttl_seconds: i64,
    f: F,
) -> Result<Option<T>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
    M: LockManager,
{
    if let Some(guard) = lock_manager.try_acquire_lock(lock_key, ttl_seconds).await? {
        let result = f().await;
        lock_manager.release_lock(guard).await?;
        return Ok(Some(result?));
    }

    Ok(None)
}
