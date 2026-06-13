use crate::auth::jwt::JwtService;
use crate::auth::sso::Provider;
use crate::constants::DEVICE_CODE_EXPIRE_MINUTES;
use crate::db::models::User;
use crate::error::{AppError, Result};
use crate::state::AppState;
use crate::store::{
    device_codes::DeviceCodeStore, identities::IdentityStore, organizations::OrganizationStore,
    services::ServiceStore, sessions::SessionStore, subscriptions::SubscriptionStore,
    totp::TotpStore, DB,
};
use axum::{extract::State, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const PLATFORM_ADMIN_CLI_CLIENT_ID: &str = "platform-admin-cli";

// Re-export common types for use in other modules
pub use crate::auth::device_flow::DeviceFlowService;
pub use crate::error::Json400;

// Device Code Request
#[derive(Debug, Deserialize)]
pub struct DeviceCodeRequest {
    pub client_id: String,
    pub org: String,
    pub service: String,
}

// Device Code Response
#[derive(Debug, Serialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: i64,
    pub interval: i64,
}

// Device Verify Request
#[derive(Debug, Deserialize)]
pub struct DeviceVerifyRequest {
    pub user_code: String,
}

// Device Verify Response
#[derive(Debug, Serialize)]
pub struct DeviceVerifyResponse {
    pub org_slug: String,
    pub service_slug: String,
    pub available_providers: Vec<String>,
}

// Token Request
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub client_id: String,
    pub device_code: String,
    pub grant_type: String,
    pub resource: Option<String>,
}

// Token Response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Device Flow: Create device code
pub async fn device_code(
    State(state): State<AppState>,
    Json400(req): Json400<DeviceCodeRequest>,
) -> Result<Json<DeviceCodeResponse>> {
    // Validate input lengths to prevent database issues
    if req.client_id.len() > 500 {
        return Err(AppError::BadRequest(
            "client_id too long (max 500 characters)".to_string(),
        ));
    }
    if req.org.len() > 100 {
        return Err(AppError::BadRequest(
            "org slug too long (max 100 characters)".to_string(),
        ));
    }
    if req.service.len() > 100 {
        return Err(AppError::BadRequest(
            "service slug too long (max 100 characters)".to_string(),
        ));
    }

    // Validate characters (allow alphanumeric, hyphens, underscores)
    let valid_chars = |s: &str| -> bool {
        s.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    };

    if !valid_chars(&req.client_id) {
        return Err(AppError::BadRequest(
            "client_id contains invalid characters".to_string(),
        ));
    }
    if !valid_chars(&req.org) {
        return Err(AppError::BadRequest(
            "org slug contains invalid characters".to_string(),
        ));
    }
    if !valid_chars(&req.service) {
        return Err(AppError::BadRequest(
            "service slug contains invalid characters".to_string(),
        ));
    }

    // Get config for platform device activation URI
    let config = crate::config::Config::from_env()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    // Check if this is a platform-level device flow or service-level
    let verification_uri = if req.org == "platform"
        && req.service == "admin-cli"
        && req.client_id == PLATFORM_ADMIN_CLI_CLIENT_ID
    {
        // Platform-level device flow for admin CLI - use configured platform device activation URI
        format!("{}/activate", config.platform_dashboard_base_url)
    } else {
        // Service-level device flow - validate service exists
        let service = ServiceStore::find_by_client_id_and_slugs(
            DB::Conn(&state.db),
            &req.client_id,
            &req.org,
            &req.service,
        )
        .await?
        .map(crate::db::models::Service::from)
        .ok_or_else(|| AppError::BadRequest("Invalid client credentials".to_string()))?;

        // Use service's device_activation_uri if set
        service.device_activation_uri.ok_or_else(|| {
            AppError::BadRequest(
                "Device activation URI not configured for this service".to_string(),
            )
        })?
    };

    // --- Perform CPU-bound work here, in the parallel handler ---
    let device_code = DeviceFlowService::generate_device_code();
    let user_code = DeviceFlowService::generate_user_code();
    // --- End CPU-bound work ---

    // Create device code directly in the database
    let expires_at =
        (Utc::now() + chrono::Duration::minutes(DEVICE_CODE_EXPIRE_MINUTES)).naive_utc();
    let _created_device_code = DeviceCodeStore::create(
        DB::Conn(&state.db),
        &device_code,
        &user_code,
        &req.client_id,
        &req.org,
        &req.service,
        &expires_at,
    )
    .await?;

    Ok(Json(DeviceCodeResponse {
        device_code,
        user_code,
        verification_uri,
        expires_in: DEVICE_CODE_EXPIRE_MINUTES * 60, // Convert minutes to seconds
        interval: 5,                                 // Poll every 5 seconds
    }))
}

/// Device Flow: Verify user code and return context for frontend
pub async fn device_verify(
    State(state): State<AppState>,
    Json400(req): Json400<DeviceVerifyRequest>,
) -> Result<Json<DeviceVerifyResponse>> {
    // Validate user code length and format (should be "XXXX-XXXX")
    if req.user_code.len() != 9 || !req.user_code.contains('-') {
        return Err(AppError::BadRequest("Invalid user code format".to_string()));
    }

    // User codes should contain only characters that are easy to distinguish (alphanumeric + dash)
    let valid_chars = |s: &str| -> bool { s.chars().all(|c| c.is_alphanumeric() || c == '-') };

    if !valid_chars(&req.user_code) {
        return Err(AppError::BadRequest("Invalid user code format".to_string()));
    }

    // Find device code with retry to handle batch processing timing
    let mut device_code = None;
    for attempt in 0..3 {
        match DeviceFlowService::find_by_user_code(&state.db, &req.user_code).await {
            Ok(Some(dc)) => {
                device_code = Some(dc);
                break;
            }
            Ok(None) => {
                if attempt < 2 {
                    // Wait a bit for batch writer to process
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
            Err(e) => return Err(e),
        }
    }

    let device_code =
        device_code.ok_or_else(|| AppError::BadRequest("Invalid user code".to_string()))?;

    // Check if expired
    if DeviceFlowService::is_expired(&device_code) {
        return Err(AppError::DeviceCodeExpired);
    }

    // Check if already authorized
    if DeviceFlowService::is_authorized(&device_code) {
        return Err(AppError::BadRequest(
            "Device already authorized".to_string(),
        ));
    }

    // Check if this is a platform-level admin device flow
    if device_code.org_slug == "platform" && device_code.service_slug == "admin-cli" {
        // Platform-level device flow - return all available admin providers
        let available_providers = vec![
            "github".to_string(),
            "google".to_string(),
            "microsoft".to_string(),
        ];

        return Ok(Json(DeviceVerifyResponse {
            org_slug: device_code.org_slug,
            service_slug: device_code.service_slug,
            available_providers,
        }));
    }

    // Service-level device flow - fetch organization and service
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &device_code.org_slug)
        .await?
        .map(crate::db::models::Organization::from)
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let _service =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &device_code.service_slug)
            .await?
            .map(crate::db::models::Service::from)
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    // Fetch organization OAuth credentials to see which providers are configured
    let available_providers =
        OrganizationStore::list_oauth_providers(DB::Conn(&state.db), &org.id).await?;

    // Return the context needed for the frontend to initiate the correct login flow
    Ok(Json(DeviceVerifyResponse {
        org_slug: device_code.org_slug,
        service_slug: device_code.service_slug,
        available_providers,
    }))
}

/// Device Flow: Exchange device code for token
pub async fn token_exchange(
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>> {
    // Validate grant type
    if req.grant_type != "urn:ietf:params:oauth:grant-type:device_code" {
        return Err(AppError::BadRequest("Invalid grant type".to_string()));
    }

    // Validate and get device code with retry to handle batch processing timing
    let mut device_code = None;
    for attempt in 0..3 {
        match DeviceFlowService::validate_for_token_exchange(
            &state.db,
            &req.device_code,
            &req.client_id,
        )
        .await
        {
            Ok(dc) => {
                device_code = Some(dc);
                break;
            }
            Err(e) => {
                // Only retry on "not found" type errors
                let error_msg = e.to_string().to_lowercase();
                if attempt < 2
                    && (error_msg.contains("not found")
                        || error_msg.contains("invalid")
                        || error_msg.contains("expired"))
                {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                } else {
                    return Err(e);
                }
            }
        }
    }

    let device_code =
        device_code.ok_or_else(|| AppError::BadRequest("Invalid device code".to_string()))?;

    let user_id = device_code
        .user_id
        .ok_or_else(|| AppError::Unauthorized("Not authorized".to_string()))?;

    // Get user info
    let user = crate::store::users::UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .map(User::from)
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Check if user has MFA enabled - device flows cannot proceed without completing MFA
    let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;
    if mfa_enabled {
        return Err(AppError::BadRequest(
            "MFA verification required. Please complete MFA verification in your browser before the device can be authorized.".to_string()
        ));
    }

    // Check if this is a platform-level device flow
    if device_code.org_slug == "platform" && device_code.service_slug == "admin-cli" {
        // Generate platform JWT for admin CLI
        let token = state.jwt_service.create_token(
            &user.id,
            &user.email,
            user.is_platform_owner,
            None,
            None,
        )?;

        // Generate refresh token
        let refresh_token = Uuid::new_v4().to_string();

        // Store session with refresh token
        let token_hash = JwtService::hash_token(&token);
        let now = Utc::now();
        let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
        let refresh_expires_at = now + chrono::Duration::days(30);

        if !DeviceCodeStore::consume_authorized(
            DB::Conn(&state.db),
            &device_code.id,
            &req.client_id,
        )
        .await?
        {
            return Err(AppError::BadRequest("Invalid device code".to_string()));
        }

        SessionStore::create(
            DB::Conn(&state.db),
            &user_id,
            &token_hash,
            expires_at.naive_utc(),
            Some(&refresh_token),
            Some(refresh_expires_at.naive_utc()),
            None, // org_slug
            None, // service_id
            None, // resource
            None, // user_agent
            None, // ip_address
        )
        .await?;

        return Ok(Json(TokenResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in: state.config.jwt_expiration_hours * 3600, // Convert hours to seconds
        }));
    }

    // Service-level device flow - get service and plan info
    let result = SubscriptionStore::get_service_with_subscription(
        DB::Conn(&state.db),
        &user_id,
        &device_code.org_slug,
        &device_code.service_slug,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &result.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    let requested_resource = crate::utils::resource_indicators::validate_requested_resource(
        req.resource.as_deref(),
        service.resource_uris.as_deref(),
    )?;

    // Generate JWT
    let token = state.jwt_service.create_token_with_resource(
        &user.id,
        &user.email,
        user.is_platform_owner,
        Some(&result.org_slug),
        Some(&result.service_slug),
        requested_resource.as_deref(),
    )?;

    // Generate refresh token
    let refresh_token = Uuid::new_v4().to_string();

    // Store session with refresh token
    let token_hash = JwtService::hash_token(&token);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    if !DeviceCodeStore::consume_authorized(DB::Conn(&state.db), &device_code.id, &req.client_id)
        .await?
    {
        return Err(AppError::BadRequest("Invalid device code".to_string()));
    }

    SessionStore::create(
        DB::Conn(&state.db),
        &user_id,
        &token_hash,
        expires_at.naive_utc(),
        Some(&refresh_token),
        Some(refresh_expires_at.naive_utc()),
        Some(&result.org_slug),
        Some(&result.service_id),
        requested_resource.as_deref(),
        None, // user_agent
        None, // ip_address
    )
    .await?;

    // Record login event - get provider from most recent identity
    let provider_opt = if let Ok(Some(provider_str)) =
        IdentityStore::get_latest_provider(DB::Conn(&state.db), &user_id).await
    {
        if let Ok(provider) = Provider::from_str(&provider_str) {
            record_login_event(&state.audit_actor, &user_id, &result.service_id, provider).await;
            Some(provider.as_str())
        } else {
            None
        }
    } else {
        None
    };

    // Publish login success event for webhooks
    crate::handlers::auth::oauth::publish_login_event(
        &state.event_dispatcher,
        &user_id,
        &user.email,
        Some(&result.org_slug),
        Some(&result.service_id),
        provider_opt,
    )
    .await;

    Ok(Json(TokenResponse {
        access_token: token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt_expiration_hours * 3600, // Convert hours to seconds
    }))
}

// Helper functions

/// Check if a user has MFA enabled
async fn is_mfa_enabled(pool: &sea_orm::DatabaseConnection, user_id: &str) -> Result<bool> {
    TotpStore::is_enabled(DB::Conn(pool), user_id).await
}

/// Record login event for analytics (via buffered audit actor)
async fn record_login_event(
    audit_actor: &crate::services::audit_actor::AuditHandle,
    user_id: &str,
    service_id: &str,
    provider: Provider,
) {
    use crate::entities::login_events;
    use sea_orm::Set;

    let event_model = login_events::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_id: Set(user_id.to_string()),
        service_id: Set(Some(service_id.to_string())),
        provider: Set(provider.as_str().to_string()),
        ..Default::default()
    };

    // Non-blocking: queues to actor, doesn't wait for DB
    audit_actor.log_login(event_model).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::sso::OAuthClient;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::services::{
        audit_actor::AuditHandle, events::EventDispatcher, metrics::MfaMetricsService,
        risk_engine::RiskEngine,
    };
    use crate::store::{
        organizations::OrganizationStore,
        services::ServiceStore,
        users::{UserCreationOptions, UserStore},
    };
    use axum::extract::State;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use openssl::rsa::Rsa;
    use sea_orm::Database;
    use std::sync::Arc;

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
        let rsa = Rsa::generate(2048).expect("generate test rsa key");
        let private_key = STANDARD.encode(
            rsa.private_key_to_pem()
                .expect("encode private key pem for tests"),
        );
        let public_key = STANDARD.encode(
            rsa.public_key_to_pem()
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

    async fn setup_state() -> AppState {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));

        AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client,
            jwt_service,
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
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
        }
    }

    #[tokio::test]
    async fn token_exchange_accepts_only_registered_resource() {
        let state = setup_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "device-user@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0;
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&state.db),
            "acme",
            "Acme",
            &user.id,
            Some("tier_enterprise"),
        )
        .await
        .expect("create org");
        let service = ServiceStore::create(
            DB::Conn(&state.db),
            &org.id,
            "portal",
            "Portal",
            "web",
            "client-portal",
        )
        .await
        .expect("create service");
        let resource = "https://api.example.com/mcp";
        let resource_json = serde_json::to_string(&vec![resource]).unwrap();
        ServiceStore::update_dynamic(
            DB::Conn(&state.db),
            &org.id,
            &service.slug,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&resource_json),
        )
        .await
        .expect("set resource URIs");
        let expires_at = (Utc::now() + chrono::Duration::minutes(10)).naive_utc();
        let device_code = DeviceCodeStore::create(
            DB::Conn(&state.db),
            "device-code",
            "USER-CODE",
            "client-portal",
            &org.slug,
            &service.slug,
            &expires_at,
        )
        .await
        .expect("create device code");
        DeviceCodeStore::authorize(DB::Conn(&state.db), &device_code.id, &user.id)
            .await
            .expect("authorize device code");

        let invalid = token_exchange(
            State(state.clone()),
            Json(TokenRequest {
                client_id: "client-portal".to_string(),
                device_code: "device-code".to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                resource: Some("https://other.example.com/mcp".to_string()),
            }),
        )
        .await;
        assert!(matches!(
            invalid,
            Err(AppError::BadRequest(ref message)) if message.contains("invalid_target")
        ));

        let Json(response) = token_exchange(
            State(state.clone()),
            Json(TokenRequest {
                client_id: "client-portal".to_string(),
                device_code: "device-code".to_string(),
                grant_type: "urn:ietf:params:oauth:grant-type:device_code".to_string(),
                resource: Some(resource.to_string()),
            }),
        )
        .await
        .expect("exchange token");
        let claims = state
            .jwt_service
            .validate_token(&response.access_token)
            .expect("validate token");
        assert_eq!(claims.org.as_deref(), Some("acme"));
        assert_eq!(claims.service.as_deref(), Some("portal"));
        assert_eq!(claims.aud.as_deref(), Some(resource));
    }
}
