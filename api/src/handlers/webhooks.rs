//! Webhook management endpoints for organizations

use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_WEBHOOKS_MANAGE};
use crate::state::AppState;
use crate::store::{
    organizations::OrganizationStore, webhook_deliveries::WebhookDeliveryStore,
    webhooks::WebhookStore, DB,
};
use axum::{
    extract::{Path, Query, State},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

async fn require_webhook_manager(state: &AppState, org_id: &str, user_id: &str) -> Result<()> {
    if PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_WEBHOOKS_MANAGE).await? {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to manage webhooks".to_string(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWebhookRequest {
    pub name: Option<String>,
    pub url: Option<String>,
    pub events: Option<Vec<String>>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct WebhookResponse {
    pub id: String,
    pub name: String,
    pub url: String,
    pub events: Vec<String>,
    pub is_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WebhookListResponse {
    pub webhooks: Vec<WebhookResponse>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct WebhookDeliveryQuery {
    pub page: Option<i64>,
    pub limit: Option<i64>,
    pub event_type: Option<String>,
    pub delivered: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct WebhookDeliveryResponse {
    pub id: String,
    pub webhook_id: String,
    pub webhook_name: String,
    pub event_type: String,
    pub payload: serde_json::Value,
    pub response_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub next_retry_at: Option<chrono::DateTime<Utc>>,
    pub delivered: bool,
    pub delivery_error: Option<String>,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct WebhookDeliveryListResponse {
    pub deliveries: Vec<WebhookDeliveryResponse>,
    pub pagination: PaginationInfo,
}

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub page: i64,
    pub limit: i64,
    pub total: i64,
    pub total_pages: i64,
    pub has_next: bool,
    pub has_prev: bool,
}

/// Available webhook event types
pub const WEBHOOK_EVENT_TYPES: &[&str] = &[
    // User lifecycle events
    "user.signup.success",
    "user.login.success",
    "user.login.failed",
    "user.logout",
    // User MFA events
    "user.mfa.enabled",
    "user.mfa.disabled",
    "user.mfa.verify.success",
    "user.mfa.verify.failed",
    // User management (admin actions)
    "user.invited",
    "user.joined",
    "user.removed",
    "user.role_updated",
    // Service management
    "service.created",
    "service.updated",
    "service.deleted",
    "service.oauth_credentials.updated",
    // Organization management
    "organization.updated",
    "organization.smtp.configured",
    "organization.smtp.removed",
    // Plan management
    "plan.created",
    "plan.updated",
    "plan.deleted",
    // Subscription management
    "subscription.created",
    "subscription.updated",
    "subscription.canceled",
    // Invitation management
    "invitation.accepted",
    "invitation.declined",
    "invitation.expired",
    "invitation.revoked",
    // Security events (admin-level)
    "security.mfa.enabled",
    "security.mfa.disabled",
    "security.password.changed",
    // API Key management
    "api_key.created",
    "api_key.deleted",
    // Custom domain and branding
    "domain.set",
    "domain.verified",
    "domain.deleted",
    "branding.updated",
];

/// Create a new webhook (owner/admin only)
pub async fn create_webhook(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<Json<WebhookResponse>> {
    // Validate input
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Webhook name cannot be empty".to_string(),
        ));
    }

    if req.url.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Webhook URL cannot be empty".to_string(),
        ));
    }

    // Validate URL format (basic check)
    if !req.url.starts_with("http://") && !req.url.starts_with("https://") {
        return Err(AppError::BadRequest(
            "Webhook URL must start with http:// or https://".to_string(),
        ));
    }

    if req.events.is_empty() {
        return Err(AppError::BadRequest(
            "At least one event must be specified".to_string(),
        ));
    }

    // Validate event types
    let mut valid_events: HashSet<&str> = HashSet::new();
    valid_events.extend(WEBHOOK_EVENT_TYPES);

    for event in &req.events {
        if !valid_events.contains(event.as_str()) {
            return Err(AppError::BadRequest(format!(
                "Invalid event type: {}. Valid types: {}",
                event,
                WEBHOOK_EVENT_TYPES.join(", ")
            )));
        }
    }

    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_webhook_manager(&state, &organization.id, &auth_user.user.id).await?;

    // Check for duplicate webhook name
    let existing_webhook =
        WebhookStore::find_by_org_and_name(DB::Conn(&state.db), &organization.id, &req.name)
            .await?;

    if existing_webhook.is_some() {
        return Err(AppError::BadRequest(
            "A webhook with this name already exists".to_string(),
        ));
    }

    // Create webhook
    let webhook_id = Uuid::new_v4().to_string();
    let secret = generate_webhook_secret();
    let events_json = serde_json::to_string(&req.events).unwrap();
    let now = Utc::now().naive_utc();

    match WebhookStore::create(
        DB::Conn(&state.db),
        &webhook_id,
        &organization.id,
        &req.name,
        &req.url,
        &secret,
        &events_json,
        true,
        now,
        now,
    )
    .await
    {
        Ok(_) => (),
        Err(crate::error::AppError::SeaOrmDatabase(e)) => {
            return Err(crate::error::handle_sea_orm_error(e));
        }
        Err(e) => return Err(e),
    }

    // Fetch the created webhook
    let webhook = WebhookStore::find_by_id(DB::Conn(&state.db), &webhook_id)
        .await?
        .ok_or_else(|| AppError::InternalServerError("Failed to create webhook".to_string()))?;

    // Parse events for response
    let events: Vec<String> = serde_json::from_str(&webhook.events).unwrap_or_default();

    Ok(Json(WebhookResponse {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
        events,
        is_active: webhook.is_active,
        secret: Some(secret),
        created_at: chrono::DateTime::from_naive_utc_and_offset(webhook.created_at, Utc),
        updated_at: chrono::DateTime::from_naive_utc_and_offset(webhook.updated_at, Utc),
    }))
}

/// List webhooks for an organization (owner/admin only)
pub async fn list_webhooks(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<WebhookListResponse>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_webhook_manager(&state, &organization.id, &auth_user.user.id).await?;

    // Get webhooks
    let webhooks =
        WebhookStore::find_by_organization(DB::Conn(&state.db), &organization.id).await?;

    // Get total count
    let total = WebhookStore::count_by_organization(DB::Conn(&state.db), &organization.id).await?;

    // Convert to response format
    let webhook_responses: Vec<WebhookResponse> = webhooks
        .into_iter()
        .map(|w| {
            let events: Vec<String> = serde_json::from_str(&w.events).unwrap_or_default();
            WebhookResponse {
                id: w.id,
                name: w.name,
                url: w.url,
                events,
                is_active: w.is_active,
                secret: None,
                created_at: DateTime::from_naive_utc_and_offset(w.created_at, Utc),
                updated_at: DateTime::from_naive_utc_and_offset(w.updated_at, Utc),
            }
        })
        .collect();

    Ok(Json(WebhookListResponse {
        webhooks: webhook_responses,
        total,
    }))
}

/// Get a specific webhook (owner/admin only)
pub async fn get_webhook(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, webhook_id)): Path<(String, String)>,
) -> Result<Json<WebhookResponse>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_webhook_manager(&state, &organization.id, &auth_user.user.id).await?;

    // Get webhook
    let webhook = WebhookStore::find_by_id(DB::Conn(&state.db), &webhook_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    // Verify webhook belongs to organization
    if webhook.org_id != organization.id {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    // Parse events for response
    let events: Vec<String> = serde_json::from_str(&webhook.events).unwrap_or_default();

    Ok(Json(WebhookResponse {
        id: webhook.id,
        name: webhook.name,
        url: webhook.url,
        events,
        is_active: webhook.is_active,
        secret: None,
        created_at: chrono::DateTime::from_naive_utc_and_offset(webhook.created_at, Utc),
        updated_at: chrono::DateTime::from_naive_utc_and_offset(webhook.updated_at, Utc),
    }))
}

/// Update a webhook (owner/admin only)
pub async fn update_webhook(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, webhook_id)): Path<(String, String)>,
    Json(req): Json<UpdateWebhookRequest>,
) -> Result<Json<WebhookResponse>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_webhook_manager(&state, &organization.id, &auth_user.user.id).await?;

    // Get existing webhook
    let existing_webhook = WebhookStore::find_by_id(DB::Conn(&state.db), &webhook_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    // Verify webhook belongs to organization
    if existing_webhook.org_id != organization.id {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    // Validate input if provided
    if let Some(ref name) = req.name {
        if name.trim().is_empty() {
            return Err(AppError::BadRequest(
                "Webhook name cannot be empty".to_string(),
            ));
        }

        // Check for duplicate webhook name (if changed)
        if name != &existing_webhook.name {
            let duplicate_webhook =
                WebhookStore::find_by_org_and_name(DB::Conn(&state.db), &organization.id, name)
                    .await?;

            if duplicate_webhook.is_some() {
                return Err(AppError::BadRequest(
                    "A webhook with this name already exists".to_string(),
                ));
            }
        }
    }

    if let Some(ref url) = req.url {
        if url.trim().is_empty() {
            return Err(AppError::BadRequest(
                "Webhook URL cannot be empty".to_string(),
            ));
        }

        // Validate URL format
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return Err(AppError::BadRequest(
                "Webhook URL must start with http:// or https://".to_string(),
            ));
        }
    }

    if let Some(ref events) = req.events {
        if events.is_empty() {
            return Err(AppError::BadRequest(
                "At least one event must be specified".to_string(),
            ));
        }

        // Validate event types
        let mut valid_events: HashSet<&str> = HashSet::new();
        valid_events.extend(WEBHOOK_EVENT_TYPES);

        for event in events {
            if !valid_events.contains(event.as_str()) {
                return Err(AppError::BadRequest(format!(
                    "Invalid event type: {}. Valid types: {}",
                    event,
                    WEBHOOK_EVENT_TYPES.join(", ")
                )));
            }
        }
    }

    // Use individual update statements for simplicity
    let now = Utc::now().naive_utc();

    if let Some(ref name) = req.name {
        WebhookStore::update_name(
            DB::Conn(&state.db),
            &webhook_id,
            &organization.id,
            name,
            now,
        )
        .await?;
    }

    if let Some(ref url) = req.url {
        WebhookStore::update_url(DB::Conn(&state.db), &webhook_id, &organization.id, url, now)
            .await?;
    }

    if let Some(ref events) = req.events {
        let events_json = serde_json::to_string(events).unwrap();
        WebhookStore::update_events(
            DB::Conn(&state.db),
            &webhook_id,
            &organization.id,
            &events_json,
            now,
        )
        .await?;
    }

    if let Some(is_active) = req.is_active {
        WebhookStore::update_is_active(
            DB::Conn(&state.db),
            &webhook_id,
            &organization.id,
            is_active,
            now,
        )
        .await?;
    }

    // Fetch updated webhook
    let updated_webhook = WebhookStore::find_by_id(DB::Conn(&state.db), &webhook_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    // Parse events for response
    let events: Vec<String> = serde_json::from_str(&updated_webhook.events).unwrap_or_default();

    Ok(Json(WebhookResponse {
        id: updated_webhook.id,
        name: updated_webhook.name,
        url: updated_webhook.url,
        events,
        is_active: updated_webhook.is_active,
        secret: None,
        created_at: DateTime::from_naive_utc_and_offset(updated_webhook.created_at, Utc),
        updated_at: DateTime::from_naive_utc_and_offset(updated_webhook.updated_at, Utc),
    }))
}

/// Delete a webhook (owner/admin only)
pub async fn delete_webhook(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, webhook_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_webhook_manager(&state, &organization.id, &auth_user.user.id).await?;

    // Check if webhook exists
    let existing_webhook = WebhookStore::find_by_id(DB::Conn(&state.db), &webhook_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    // Verify webhook belongs to organization
    if existing_webhook.org_id != organization.id {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    // Delete webhook (cascades to webhook_deliveries)
    WebhookStore::delete(DB::Conn(&state.db), &webhook_id, &organization.id).await?;

    Ok(Json(()))
}

/// Get webhook delivery history for a webhook (owner/admin only)
pub async fn get_webhook_deliveries(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, webhook_id)): Path<(String, String)>,
    Query(query): Query<WebhookDeliveryQuery>,
) -> Result<Json<WebhookDeliveryListResponse>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_webhook_manager(&state, &organization.id, &auth_user.user.id).await?;

    // Check if webhook exists
    let _existing_webhook = WebhookStore::find_by_id(DB::Conn(&state.db), &webhook_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    // Verify webhook belongs to organization
    if _existing_webhook.org_id != organization.id {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    // Set default pagination values
    let page = query.page.unwrap_or(1).max(1);
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = (page - 1) * limit;

    // Get deliveries with filters
    let deliveries = WebhookDeliveryStore::get_deliveries_with_filters(
        DB::Conn(&state.db),
        &webhook_id,
        query.event_type.as_deref(),
        query.delivered,
        limit,
        offset,
    )
    .await?;

    // Get total count for pagination
    let total = WebhookDeliveryStore::count_deliveries_with_filters(
        DB::Conn(&state.db),
        &webhook_id,
        query.event_type.as_deref(),
        query.delivered,
    )
    .await?;

    let total_pages = (total + limit - 1) / limit;

    // Convert to response format
    let delivery_responses: Vec<WebhookDeliveryResponse> = deliveries
        .into_iter()
        .map(|d| {
            let payload: serde_json::Value = serde_json::from_str(&d.payload).unwrap_or_default();
            WebhookDeliveryResponse {
                id: d.id,
                webhook_id: d.webhook_id,
                webhook_name: d.webhook_name,
                event_type: d.event_type,
                payload,
                response_status_code: d.response_status_code,
                response_body: d.response_body,
                attempt_count: d.attempt_count,
                max_attempts: d.max_attempts,
                next_retry_at: d.next_retry_at,
                delivered: d.delivered,
                delivery_error: d.delivery_error,
                created_at: d.created_at,
                updated_at: d.updated_at,
            }
        })
        .collect();

    let pagination = PaginationInfo {
        page,
        limit,
        total,
        total_pages,
        has_next: page < total_pages,
        has_prev: page > 1,
    };

    Ok(Json(WebhookDeliveryListResponse {
        deliveries: delivery_responses,
        pagination,
    }))
}

/// Trigger a test webhook event (owner/admin only)
pub async fn test_webhook(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, webhook_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    // Get organization
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_webhook_manager(&state, &organization.id, &auth_user.user.id).await?;

    // Check if webhook exists
    let existing_webhook = WebhookStore::find_by_id(DB::Conn(&state.db), &webhook_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Webhook not found".to_string()))?;

    // Verify webhook belongs to organization
    if existing_webhook.org_id != organization.id {
        return Err(AppError::NotFound("Webhook not found".to_string()));
    }

    // Create test payload
    let test_payload = serde_json::json!({
        "event": "webhook.test.ping",
        "timestamp": Utc::now().to_rfc3339(),
        "organization_id": organization.id,
        "actor_user_id": auth_user.user.id,
        "message": "This is a test event triggered from the AuthOS dashboard.",
    });

    use crate::services::job_queue::JobQueueService;

    // Enqueue delivery
    let (job_id, delivery_id) = JobQueueService::enqueue_webhook(
        DB::Conn(&state.db),
        &webhook_id,
        "webhook.test.ping",
        &test_payload,
    )
    .await?;

    Ok(Json(serde_json::json!({
        "success": true,
        "job_id": job_id,
        "delivery_id": delivery_id
    })))
}

/// Get available webhook event types
pub async fn get_webhook_event_types(
    State(_state): State<AppState>,
    _auth_user: AuthUser,
    Path(_org_slug): Path<String>,
) -> Result<Json<Vec<EventTypeInfo>>> {
    let event_types = WEBHOOK_EVENT_TYPES
        .iter()
        .map(|&event| {
            let parts: Vec<&str> = event.split('.').collect();
            let category = match parts[0] {
                "user" => "User Management",
                "service" => "Service Management",
                "organization" => "Organization Management",
                "plan" => "Plan Management",
                "subscription" => "Subscription Management",
                "invitation" => "Invitation Management",
                "security" => "Security",
                "api_key" => "API Keys",
                "domain" => "Custom Domains",
                "branding" => "Branding",
                _ => "Other",
            };

            EventTypeInfo {
                value: event.to_string(),
                label: event.replace(['.', '_'], " ").to_uppercase(),
                category: category.to_string(),
            }
        })
        .collect();

    Ok(Json(event_types))
}

#[derive(Debug, Serialize)]
pub struct EventTypeInfo {
    pub value: String,
    pub label: String,
    pub category: String,
}

/// Generate a secure webhook secret
fn generate_webhook_secret() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use rand::Rng;

    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);

    STANDARD.encode(bytes)
}
