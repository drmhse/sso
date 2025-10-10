use crate::billing::stripe::StripeService;
use crate::error::{AppError, Result};
use axum::{body::Bytes, extract::State, http::StatusCode, response::IntoResponse, Json};
use serde_json::json;
use std::sync::Arc;

#[derive(Clone)]
pub struct WebhookState {
    pub pool: sqlx::SqlitePool,
    pub stripe_service: Arc<StripeService>,
}

/// Handle Stripe webhooks
pub async fn stripe_webhook(
    State(state): State<WebhookState>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse> {
    // Get Stripe signature header
    let signature = headers
        .get("stripe-signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing stripe-signature header".to_string()))?;

    // Convert body to string
    let payload = String::from_utf8(body.to_vec())
        .map_err(|_| AppError::BadRequest("Invalid payload encoding".to_string()))?;

    // Verify webhook signature and parse event
    let event = state.stripe_service.verify_webhook(&payload, signature)?;

    tracing::info!("Received Stripe webhook: {:?}", event.type_);

    // Process the event
    StripeService::process_webhook_event(&state.pool, event).await?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "status": "success"
        })),
    ))
}
