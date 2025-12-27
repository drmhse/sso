//! Concurrency control utilities for high-throughput operations

use std::sync::LazyLock;
use tokio::sync::Semaphore;

/// Semaphore limiting concurrent Argon2 password verifications.
///
/// Argon2 is CPU-intensive (~50-100ms per hash). Without limits, a login
/// flood could spawn hundreds of blocking tasks and exhaust Tokio's
/// blocking thread pool (default 512 threads).
///
/// Limit = 2x CPU cores provides good throughput while preventing saturation.
pub static ARGON2_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| {
    let cpus = num_cpus::get();
    let limit = cpus * 2;
    tracing::info!("Argon2 semaphore initialized with {} permits", limit);
    Semaphore::new(limit)
});
