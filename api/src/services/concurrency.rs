//! Concurrency control utilities for high-throughput operations

use crate::error::{AppError, Result};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use std::{sync::LazyLock, time::Duration};
use tokio::sync::Semaphore;

/// Password inputs are intentionally much smaller than the global HTTP body
/// limit. This keeps validation and Argon2 input processing bounded while
/// still allowing long generated passwords and passphrases.
pub const MAX_PASSWORD_BYTES: usize = 1024;
const ARGON2_QUEUE_TIMEOUT: Duration = Duration::from_secs(2);

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

async fn acquire_argon2_permit() -> Result<tokio::sync::SemaphorePermit<'static>> {
    tokio::time::timeout(ARGON2_QUEUE_TIMEOUT, ARGON2_SEMAPHORE.acquire())
        .await
        .map_err(|_| {
            AppError::TooManyRequests(
                "Password processing is busy. Please try again shortly.".to_string(),
            )
        })?
        .map_err(|_| AppError::ServiceUnavailable("Password processing unavailable".to_string()))
}

fn validate_password_size(password: &str) -> Result<()> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::BadRequest(format!(
            "Password must not exceed {MAX_PASSWORD_BYTES} UTF-8 bytes"
        )));
    }
    Ok(())
}

/// Hash a password off the async runtime with a global concurrency and queue
/// bound shared by every request-time Argon2 operation.
pub async fn hash_password_bounded(password: String) -> Result<String> {
    validate_password_size(&password)?;
    let _permit = acquire_argon2_permit().await?;
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|hash| hash.to_string())
            .map_err(|error| {
                AppError::InternalServerError(format!("Failed to hash password: {error}"))
            })
    })
    .await
    .map_err(|error| {
        AppError::InternalServerError(format!("Password hashing task failed: {error}"))
    })?
}

/// Verify an encoded Argon2 password hash under the same work bounds used for
/// hashing. Invalid stored hashes fail closed without panicking.
pub async fn verify_password_bounded(password: String, encoded_hash: String) -> Result<bool> {
    validate_password_size(&password)?;
    let _permit = acquire_argon2_permit().await?;
    tokio::task::spawn_blocking(move || {
        let parsed_hash = match PasswordHash::new(&encoded_hash) {
            Ok(hash) => hash,
            Err(error) => {
                tracing::error!(%error, "Corrupted password hash in database");
                return false;
            }
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    })
    .await
    .map_err(|error| {
        AppError::InternalServerError(format!("Password verification task failed: {error}"))
    })
}

/// Bound expensive asymmetric-key generation so certificate provisioning
/// cannot consume Tokio's blocking pool during an authenticated request flood.
pub static ASYMMETRIC_KEYGEN_SEMAPHORE: LazyLock<Semaphore> = LazyLock::new(|| {
    let limit = (num_cpus::get() / 2).clamp(1, 4);
    tracing::info!(limit, "asymmetric key-generation semaphore initialized");
    Semaphore::new(limit)
});

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_argon2_round_trip_and_input_limit_are_deterministic() {
        let password = "correct horse battery staple".to_string();
        let hash = hash_password_bounded(password.clone())
            .await
            .expect("hash password");
        assert!(verify_password_bounded(password, hash.clone())
            .await
            .expect("verify password"));
        assert!(!verify_password_bounded("wrong".to_string(), hash)
            .await
            .expect("reject wrong password"));

        let oversized = "x".repeat(MAX_PASSWORD_BYTES + 1);
        assert!(matches!(
            hash_password_bounded(oversized.clone()).await,
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            verify_password_bounded(oversized, "not-a-hash".to_string()).await,
            Err(AppError::BadRequest(_))
        ));
    }
}
