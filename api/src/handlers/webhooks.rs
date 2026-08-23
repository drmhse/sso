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
    crate::handlers::organizations::ensure_organization_active(&state.db, org_id).await?;
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

#[derive(Debug, Default, Deserialize)]
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
    let encryption = state.encryption.as_ref().ok_or_else(|| {
        AppError::InternalServerError(
            "Encryption service is required to store webhook secrets".to_string(),
        )
    })?;
    let secret_encrypted = encryption
        .encrypt_with_context(
            &secret,
            crate::encryption::EncryptionContext::new("webhooks", &webhook_id, "secret_encrypted"),
        )
        .map_err(|_| {
            AppError::InternalServerError("Failed to encrypt webhook secret".to_string())
        })?;
    let events_json = serde_json::to_string(&req.events).unwrap();
    let now = Utc::now().naive_utc();

    match WebhookStore::create(
        DB::Conn(&state.db),
        &webhook_id,
        &organization.id,
        &req.name,
        &req.url,
        secret_encrypted,
        encryption.key_id(),
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
    let (page, limit, offset) =
        crate::utils::pagination::signed_page(query.page, query.limit, 50, 100);

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
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<EventTypeInfo>>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    require_webhook_manager(&state, &organization.id, &auth_user.user.id).await?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtService;
    use crate::auth::sso::OAuthClient;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::entities::users;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        audit_actor::AuditHandle, events::EventDispatcher, metrics::MfaMetricsService,
        risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore, users::UserStore, DB,
    };
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    fn encryption() -> crate::encryption::EncryptionService {
        crate::encryption::EncryptionService::from_keyring_values("active", &"11".repeat(32), None)
            .expect("create encryption service")
    }

    fn test_config() -> Config {
        Config {
            database_url: "sqlite::memory:".to_string(),
            jwt_expiration_hours: 24,
            db_max_connections: 5,
            db_min_connections: 1,
            db_acquire_timeout_secs: 30,
            db_idle_timeout_secs: 600,
            db_max_lifetime_secs: 1800,
            platform_github_client_id: None,
            platform_github_client_secret: None,
            platform_github_redirect_uri: None,
            platform_google_client_id: None,
            platform_google_client_secret: None,
            platform_google_redirect_uri: None,
            platform_microsoft_client_id: None,
            platform_microsoft_client_secret: None,
            platform_microsoft_redirect_uri: None,
            platform_github_auth_url: None,
            platform_github_token_url: None,
            platform_github_user_api_url: None,
            platform_google_auth_url: None,
            platform_google_token_url: None,
            platform_google_user_api_url: None,
            platform_microsoft_auth_url: None,
            platform_microsoft_token_url: None,
            platform_microsoft_user_api_url: None,
            stripe_secret_key: None,
            stripe_webhook_secret: None,
            stripe_api_base_url: None,
            server_host: "127.0.0.1".to_string(),
            server_port: 3001,
            base_url: "http://localhost:3001".to_string(),
            platform_dashboard_base_url: "http://localhost:3001".to_string(),
            full_web_client_base_url: None,
            platform_owner_email: None,
            platform_owner_password: None,
            managed_config_path: None,
            managed_state_path: None,
            managed_status_path: None,
            managed_request_path: None,
            disable_rate_limiting: true,
            job_processor_interval_secs: 10,
            job_processor_batch_size: 10,
        }
    }

    fn test_jwt_service(config: &Config) -> JwtService {
        let rsa = GeneratedKey::generate().expect("generate test rsa key");
        let private_key = STANDARD.encode(
            rsa.private_key_pem()
                .expect("encode private key pem for tests"),
        );
        let public_key = STANDARD.encode(
            rsa.public_key_pem()
                .expect("encode public key pem for tests"),
        );
        JwtService::new(
            &private_key,
            &public_key,
            config.jwt_expiration_hours,
            "test-key",
            &config.base_url,
        )
        .expect("create test jwt service")
    }

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        member: AuthUser,
        org_slug: String,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));

        let owner_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "webhook-owner@example.test",
            crate::store::users::UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let member_model =
            UserStore::create(DB::Conn(&db), "webhook-member@example.test", None, false)
                .await
                .expect("create member");

        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "acme",
            "Acme",
            &owner_model.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        MembershipStore::create(DB::Conn(&db), &org.id, &member_model.id, "member")
            .await
            .expect("create membership");

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client,
            jwt_service: jwt_service.clone(),
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: Some(Arc::new(encryption())),
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("create risk engine")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        };

        let auth_user_for = |user: &users::Model| -> AuthUser {
            let token = jwt_service
                .create_token(
                    &user.id,
                    &user.email,
                    user.is_platform_owner,
                    Some(&org.slug),
                    None,
                )
                .expect("create token");
            let claims = jwt_service.validate_token(&token).expect("validate token");
            AuthUser {
                claims,
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "webhook-test".to_string(),
                current_session_id: None,
            }
        };

        Fixture {
            owner: auth_user_for(&owner_model),
            member: auth_user_for(&member_model),
            org_slug: org.slug,
            state,
        }
    }

    fn valid_create(name: &str) -> CreateWebhookRequest {
        CreateWebhookRequest {
            name: name.to_string(),
            url: "https://hooks.example.test/ingest".to_string(),
            events: vec!["user.signup.success".to_string()],
        }
    }

    async fn create_err(f: &Fixture, req: CreateWebhookRequest) -> String {
        match create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(req),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => message,
            Err(other) => panic!("expected BadRequest, got {other:?}"),
            Ok(_) => panic!("expected an error, got a response"),
        }
    }

    #[tokio::test]
    async fn create_webhook_persists_and_returns_the_signing_secret_once() {
        let f = fixture().await;
        let Json(response) = create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("billing")),
        )
        .await
        .expect("create webhook");

        assert_eq!(response.name, "billing");
        assert_eq!(response.url, "https://hooks.example.test/ingest");
        assert_eq!(response.events, vec!["user.signup.success"]);
        assert!(response.is_active);
        // The signing secret is only ever shown at creation time.
        assert!(response.secret.as_deref().is_some_and(|s| s.len() >= 32));
    }

    #[tokio::test]
    async fn create_webhook_rejects_blank_names() {
        let f = fixture().await;
        let message = create_err(&f, valid_create("   ")).await;
        assert!(message.contains("name"), "{message}");
    }

    #[tokio::test]
    async fn create_webhook_rejects_non_http_urls() {
        let f = fixture().await;
        let mut req = valid_create("ftp-hook");
        req.url = "ftp://hooks.example.test".to_string();
        let message = create_err(&f, req).await;
        assert!(message.contains("must start with"), "{message}");
    }

    #[tokio::test]
    async fn create_webhook_rejects_empty_event_lists() {
        let f = fixture().await;
        let mut req = valid_create("no-events");
        req.events.clear();
        let message = create_err(&f, req).await;
        assert!(message.contains("At least one event"), "{message}");
    }

    #[tokio::test]
    async fn create_webhook_rejects_unknown_event_types() {
        let f = fixture().await;
        let mut req = valid_create("bad-event");
        req.events = vec!["not.a.real.event".to_string()];
        let message = create_err(&f, req).await;
        assert!(message.contains("Invalid event type"), "{message}");
    }

    #[tokio::test]
    async fn create_webhook_rejects_duplicate_names() {
        let f = fixture().await;
        let _ = create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("dupe")),
        )
        .await
        .expect("first create");
        let message = create_err(&f, valid_create("dupe")).await;
        assert!(message.contains("already exists"), "{message}");
    }

    #[tokio::test]
    async fn create_webhook_requires_the_encryption_service() {
        let mut f = fixture().await;
        f.state.encryption = None;
        match create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("no-encryption")),
        )
        .await
        {
            Err(AppError::InternalServerError(_)) => {}
            other => panic!("expected internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_webhook_denies_plain_members() {
        let f = fixture().await;
        match create_webhook(
            State(f.state.clone()),
            f.member.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("member-made")),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_get_update_and_delete_round_trip() {
        let f = fixture().await;
        let Json(first) = create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("one")),
        )
        .await
        .expect("create one");

        let _ = create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("two")),
        )
        .await
        .expect("create two");

        let Json(list) = list_webhooks(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
        )
        .await
        .expect("list webhooks");
        assert_eq!(list.webhooks.len(), 2);

        let Json(fetched) = get_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), first.id.clone())),
        )
        .await
        .expect("get webhook");
        assert_eq!(fetched.id, first.id);
        assert!(fetched.secret.is_none(), "secrets stay sealed on read");

        let Json(updated) = update_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), first.id.clone())),
            Json(UpdateWebhookRequest {
                name: Some("one-renamed".to_string()),
                url: Some("https://hooks.example.test/v2".to_string()),
                events: Some(vec![
                    "user.login.success".to_string(),
                    "user.logout".to_string(),
                ]),
                is_active: Some(false),
            }),
        )
        .await
        .expect("update webhook");
        assert_eq!(updated.name, "one-renamed");
        assert!(!updated.is_active);
        assert_eq!(updated.events.len(), 2);

        let _ = delete_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), first.id)),
        )
        .await
        .expect("delete webhook");

        match get_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), "missing".to_string())),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found, got {other:?}"),
        }

        let Json(list) = list_webhooks(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
        )
        .await
        .expect("list after delete");
        assert_eq!(list.webhooks.len(), 1);
    }

    #[tokio::test]
    async fn update_webhook_rejects_unknown_ids_and_name_conflicts() {
        let f = fixture().await;
        let Json(created) = create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("keep")),
        )
        .await
        .expect("create");

        match update_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), "nope".to_string())),
            Json(UpdateWebhookRequest {
                name: Some("x".to_string()),
                url: None,
                events: None,
                is_active: None,
            }),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found, got {other:?}"),
        }

        let _ = create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("other")),
        )
        .await
        .expect("create other");
        let conflict = UpdateWebhookRequest {
            name: Some("other".to_string()),
            url: None,
            events: None,
            is_active: None,
        };
        let message = match update_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), created.id.clone())),
            Json(conflict),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => message,
            other => panic!("expected BadRequest, got {other:?}"),
        };
        assert!(message.contains("already exists"), "{message}");

        match update_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), created.id)),
            Json(UpdateWebhookRequest {
                name: None,
                url: Some("gopher://x".to_string()),
                events: None,
                is_active: None,
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("must start with")),
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn deliveries_list_and_test_ping_work_together() {
        let f = fixture().await;
        let Json(created) = create_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
            Json(valid_create("pinged")),
        )
        .await
        .expect("create");

        let Json(deliveries) = get_webhook_deliveries(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), created.id.clone())),
            Query(WebhookDeliveryQuery::default()),
        )
        .await
        .expect("list deliveries");
        assert!(deliveries.deliveries.is_empty());

        let Json(ping) = test_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), created.id.clone())),
        )
        .await
        .expect("enqueue test ping");
        assert_eq!(ping["success"], serde_json::json!(true));
        assert!(ping["delivery_id"].as_str().is_some());

        match test_webhook(
            State(f.state.clone()),
            f.owner.clone(),
            Path((f.org_slug.clone(), "missing".to_string())),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn event_types_are_listed_but_members_are_denied() {
        let f = fixture().await;
        let Json(types) = get_webhook_event_types(
            State(f.state.clone()),
            f.owner.clone(),
            Path(f.org_slug.clone()),
        )
        .await
        .expect("event types");
        assert!(!types.is_empty());
        assert!(types.iter().all(|t| !t.value.is_empty()));

        match get_webhook_event_types(
            State(f.state.clone()),
            f.member.clone(),
            Path(f.org_slug.clone()),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }
    }
}
