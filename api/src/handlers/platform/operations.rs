use crate::entities::{siem_configs, system_jobs, webhook_deliveries};
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use axum::{extract::State, Extension, Json};
use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PlatformOperationsStatus {
    pub jobs_pending: u64,
    pub jobs_running: u64,
    pub jobs_failed: u64,
    pub webhook_deliveries_failed: u64,
    pub siem_configs_enabled: u64,
    pub siem_configs_with_failures: u64,
}

/// GET /api/platform/operations/status
/// Platform-wide operational counters for admins.
pub async fn get_operations_status(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<PlatformOperationsStatus>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let jobs_pending = system_jobs::Entity::find()
        .filter(system_jobs::Column::Status.eq("pending"))
        .count(&state.db)
        .await?;
    let jobs_running = system_jobs::Entity::find()
        .filter(system_jobs::Column::Status.eq("processing"))
        .count(&state.db)
        .await?;
    let jobs_failed = system_jobs::Entity::find()
        .filter(system_jobs::Column::Status.eq("failed"))
        .count(&state.db)
        .await?;
    let webhook_deliveries_failed = webhook_deliveries::Entity::find()
        .filter(webhook_deliveries::Column::Delivered.eq(false))
        .filter(webhook_deliveries::Column::DeliveryError.is_not_null())
        .count(&state.db)
        .await?;
    let siem_configs_enabled = siem_configs::Entity::find()
        .filter(siem_configs::Column::Enabled.eq(true))
        .count(&state.db)
        .await?;
    let siem_configs_with_failures = siem_configs::Entity::find()
        .filter(siem_configs::Column::FailureCount.gt(0))
        .count(&state.db)
        .await?;

    Ok(Json(PlatformOperationsStatus {
        jobs_pending,
        jobs_running,
        jobs_failed,
        webhook_deliveries_failed,
        siem_configs_enabled,
        siem_configs_with_failures,
    }))
}
