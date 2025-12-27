pub mod device_code_cleanup;
pub mod job_processor;
pub mod oauth_state_cleanup;
pub mod saml_state_cleanup;
pub mod token_refresh;
pub mod user_cleanup;

use std::time::Duration;

/// Get the job processor interval from config.
/// This is used by all background jobs to determine how often they should run.
/// Default is 10 seconds, but can be configured via JOB_PROCESSOR_INTERVAL_SECS.
pub fn get_job_interval() -> Duration {
    let interval_secs = crate::config::Config::from_env()
        .map(|c| c.job_processor_interval_secs)
        .unwrap_or(10);
    Duration::from_secs(interval_secs)
}

/// Get interval for cleanup jobs (runs less frequently).
/// This is a multiplier of the base job interval for less time-sensitive operations.
/// For example, OAuth state cleanup runs every 60x the base interval (default: 10min).
pub fn get_cleanup_job_interval(multiplier: u64) -> Duration {
    let base_interval = get_job_interval();
    Duration::from_secs(base_interval.as_secs() * multiplier)
}
