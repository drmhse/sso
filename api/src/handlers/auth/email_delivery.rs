use crate::error::{AppError, Result};
use crate::state::AppState;

pub(crate) fn ensure_email_delivery_configured(state: &AppState, flow_name: &str) -> Result<()> {
    if state.email_service.is_some() {
        return Ok(());
    }

    Err(AppError::ServiceUnavailable(format!(
        "Email delivery is not configured on this AuthOS instance, so {} is unavailable. Use the bootstrap owner link to open Platform Setup and configure SMTP before enabling this flow.",
        flow_name
    )))
}
