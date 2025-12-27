mod auth;
mod billing;
mod config;
mod constants;
mod db;
mod email;
mod encryption;
mod entities;
mod error;
mod handlers;
mod jobs;
mod middleware;
mod router;
mod services;
mod state;
mod store;

use crate::auth::jwt::JwtService;
use crate::auth::sso::OAuthClient;
use crate::billing::{BillingProvider, BillingProviderType, PolarProvider, StripeProvider};
use crate::config::Config;
use crate::encryption::EncryptionService;
use crate::handlers::health::readiness;
use crate::handlers::webhook::{billing_webhook, stripe_webhook, WebhookState};
use crate::jobs::device_code_cleanup::DeviceCodeCleanupJob;
use crate::jobs::job_processor::JobProcessor;
use crate::jobs::oauth_state_cleanup::OAuthStateCleanupJob;
use crate::jobs::saml_state_cleanup::SamlStateCleanupJob;
use crate::jobs::token_refresh::TokenRefreshJob;
use crate::state::AppState;
use axum::extract::State;
use axum::Json;
use axum::{
    routing::{get, post},
    Router,
};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use sea_orm::DatabaseConnection;
use serde::Serialize;
use std::env;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use webauthn_rs::prelude::*;

/// Ensures a platform owner exists with the given email.
/// If the user exists, updates is_platform_owner to true.
/// If the user doesn't exist, creates one.
async fn ensure_platform_owner(db: &DatabaseConnection, email: &str) -> anyhow::Result<()> {
    use crate::store::users::UserStore;
    use crate::store::DB as DbEnum;

    let db_conn = DbEnum::Conn(db);

    // Try to find the user by email
    match UserStore::find_by_email(db_conn.clone(), email).await {
        Ok(Some(user)) => {
            // User exists, ensure they are a platform owner
            if !user.is_platform_owner {
                UserStore::set_platform_owner(db_conn, &user.id, true).await?;
                tracing::info!("Platform owner status granted to existing user: {}", email);
            } else {
                tracing::info!("User is already a platform owner: {}", email);
            }
        }
        Ok(None) => {
            // User doesn't exist, create them as a platform owner
            UserStore::create(db_conn, email, None, true).await?;
            tracing::info!("Platform owner created: {}", email);
        }
        Err(e) => {
            tracing::error!("Failed to ensure platform owner: {}", e);
            return Err(e.into());
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct Jwk {
    kty: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    kid: String,
    n: String,
    e: String,
}

#[derive(Serialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

#[derive(Serialize)]
struct OidcDiscoveryResponse {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    device_authorization_endpoint: String,
    revocation_endpoint: String,
    jwks_uri: String,
    response_types_supported: Vec<String>,
    grant_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    scopes_supported: Vec<String>,
    token_endpoint_auth_methods_supported: Vec<String>,
    claims_supported: Vec<String>,
}

/// Prometheus metrics endpoint
async fn metrics_handler(
    prometheus_handle: axum::extract::Extension<Arc<metrics_exporter_prometheus::PrometheusHandle>>,
) -> String {
    prometheus_handle.render()
}

async fn oidc_discovery_handler(
    State(state): State<AppState>,
) -> Result<Json<OidcDiscoveryResponse>, axum::http::StatusCode> {
    let base_url = &state.base_url;
    let discovery = OidcDiscoveryResponse {
        issuer: base_url.clone(),
        authorization_endpoint: format!("{}/auth/{{provider}}", base_url),
        token_endpoint: format!("{}/auth/token", base_url),
        device_authorization_endpoint: format!("{}/auth/device/authorize", base_url),
        revocation_endpoint: format!("{}/auth/revoke", base_url),
        jwks_uri: format!("{}/.well-known/jwks.json", base_url),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        scopes_supported: vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
        ],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post".to_string(),
            "client_secret_basic".to_string(),
        ],
        claims_supported: vec![
            "sub".to_string(),
            "iss".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "email".to_string(),
            "name".to_string(),
        ],
    };

    Ok(Json(discovery))
}

async fn jwks_handler() -> Result<Json<JwksResponse>, axum::http::StatusCode> {
    let public_key_base64 = env::var("JWT_PUBLIC_KEY_BASE64")
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;
    let key_id = env::var("JWT_KID").map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let public_key_pem = STANDARD
        .decode(&public_key_base64)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let pem_str = String::from_utf8(public_key_pem)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let rsa_key = rsa::RsaPublicKey::from_public_key_pem(&pem_str)
        .map_err(|_| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let n = URL_SAFE_NO_PAD.encode(rsa_key.n().to_bytes_be());
    let e = URL_SAFE_NO_PAD.encode(rsa_key.e().to_bytes_be());

    let jwk = Jwk {
        kty: "RSA".to_string(),
        alg: "RS256".to_string(),
        key_use: "sig".to_string(),
        kid: key_id,
        n,
        e,
    };

    Ok(Json(JwksResponse { keys: vec![jwk] }))
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,sso=debug,sqlx::query=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load environment variables
    dotenvy::dotenv().ok();

    // Load configuration
    let config = Config::from_env().expect("Failed to load configuration");

    // Initialize database using SeaORM
    tracing::info!(
        "Connecting to database: {} (pool: {}-{} connections)",
        config.database_url,
        config.db_min_connections,
        config.db_max_connections
    );
    let db = db::init_db(&config)
        .await
        .expect("Failed to initialize database");
    tracing::info!("Database initialized and migrated successfully");

    // SQLite-only: Initialize writer connection pool (single connection)
    #[cfg(feature = "db_sqlite")]
    let db_writer = db::init_db_writer(&config)
        .await
        .expect("Failed to initialize SQLite writer connection");

    // Bootstrap platform owner if configured
    // If both email and password are set, use password-based bootstrap
    // Otherwise fall back to OAuth-only bootstrap
    if let (Some(email), Some(password)) = (
        config.platform_owner_email.as_ref(),
        config.platform_owner_password.as_ref(),
    ) {
        use crate::store::users::UserStore;
        use crate::store::DB as DbEnum;
        UserStore::bootstrap_platform_owner(DbEnum::Conn(&db), email, password).await?;
    } else if let Some(email) = config.platform_owner_email.as_ref() {
        ensure_platform_owner(&db, email).await?;
    }

    // Initialize encryption service (optional)
    let encryption = EncryptionService::new().ok();
    if encryption.is_some() {
        tracing::info!("Encryption service initialized");
    } else {
        tracing::warn!("Encryption service not available - tokens will be stored in plaintext");
    }

    // Initialize email service (optional)
    let email_service = crate::email::EmailService::from_env().ok();
    if let Some(ref svc) = email_service {
        // Test SMTP connection at startup to catch configuration issues early
        // Test SMTP connection at startup to catch configuration issues early
        // Wrap in timeout to prevent hanging startup if SMTP server is unresponsive
        match tokio::time::timeout(std::time::Duration::from_secs(5), svc.test_connection()).await {
            Ok(Ok(())) => tracing::info!("Email service ready - SMTP connection verified"),
            Ok(Err(e)) => tracing::warn!(
                "Email service SMTP connection test failed: {} - emails may fail",
                e
            ),
            Err(_) => {
                tracing::warn!("Email service SMTP connection test timed out - emails may fail")
            }
        }
    } else {
        tracing::warn!("Email service not configured - email features will be disabled");
    }

    // Start background token refresh job
    if let Some(enc) = encryption.clone() {
        let refresh_db = db.clone();
        tokio::spawn(async move {
            let job = TokenRefreshJob::new(refresh_db, Some(enc));
            job.start().await;
        });
        tracing::info!("Token refresh job started");
    }

    // Start background device code cleanup job
    {
        let cleanup_db = db.clone();
        tokio::spawn(async move {
            let job = DeviceCodeCleanupJob::new(cleanup_db);
            job.start().await;
        });
        tracing::info!("Device code cleanup job started");
    }

    // Start background OAuth state cleanup job
    {
        let cleanup_db = db.clone();
        tokio::spawn(async move {
            let job = OAuthStateCleanupJob::new(cleanup_db);
            job.start().await;
        });
        tracing::info!("OAuth state cleanup job started");
    }

    // Start background SAML state cleanup job
    {
        let cleanup_db = db.clone();
        tokio::spawn(async move {
            let job = SamlStateCleanupJob::new(cleanup_db);
            job.start().await;
        });
        tracing::info!("SAML state cleanup job started");
    }

    // Start background user cleanup job for GDPR compliance
    {
        let cleanup_db = db.clone();
        tokio::spawn(async move {
            let job = crate::jobs::user_cleanup::UserCleanupJob::new(cleanup_db);
            job.start().await;
        });
        tracing::info!("User cleanup job started (GDPR compliance)");
    }

    // Start background job processor (new queue-based system)
    {
        let processor_db = db.clone();
        #[cfg(feature = "db_sqlite")]
        let processor_db_writer = db_writer.clone();

        let processor_email = email_service.clone().map(Arc::new);
        let batch_size = config.job_processor_batch_size;
        tokio::spawn(async move {
            let processor = JobProcessor::new(
                processor_db,
                #[cfg(feature = "db_sqlite")]
                processor_db_writer,
                processor_email,
                batch_size,
            );
            processor.start().await;
        });
        tracing::info!(
            batch_size = config.job_processor_batch_size,
            "Job processor started"
        );
    }

    // Initialize Prometheus metrics exporter
    let prometheus_handle =
        crate::services::prometheus_metrics::PrometheusMetricsService::initialize_exporter()
            .expect("Failed to initialize Prometheus metrics exporter");
    tracing::info!("Prometheus metrics exporter initialized");

    // Start Prometheus metrics updater task
    {
        let metrics_db = db.clone();
        tokio::spawn(async move {
            crate::services::prometheus_metrics::metrics_updater_task(metrics_db).await;
        });
        tracing::info!("Prometheus metrics updater task started");
    }

    // Initialize services
    let oauth_client =
        Arc::new(OAuthClient::new(&config).expect("Failed to initialize OAuth client"));

    let private_key =
        env::var("JWT_PRIVATE_KEY_BASE64").expect("JWT_PRIVATE_KEY_BASE64 must be set");
    let public_key = env::var("JWT_PUBLIC_KEY_BASE64").expect("JWT_PUBLIC_KEY_BASE64 must be set");
    let key_id = env::var("JWT_KID").expect("JWT_KID must be set");

    let jwt_service = Arc::new(
        JwtService::new(
            &private_key,
            &public_key,
            config.jwt_expiration_hours,
            &key_id,
        )
        .expect("Failed to initialize JWT service"),
    );
    // Initialize billing provider based on BILLING_PROVIDER env var
    let billing_provider_type = std::env::var("BILLING_PROVIDER")
        .unwrap_or_else(|_| "stripe".to_string())
        .parse::<BillingProviderType>()
        .unwrap_or(BillingProviderType::Stripe);

    let billing_provider: Arc<dyn BillingProvider> = match billing_provider_type {
        BillingProviderType::Stripe => {
            let provider = if let Some(ref base_url) = config.stripe_api_base_url {
                StripeProvider::new_with_base_url(
                    config.stripe_secret_key.clone(),
                    config.stripe_webhook_secret.clone(),
                    base_url,
                )
            } else {
                StripeProvider::new(
                    config.stripe_secret_key.clone(),
                    config.stripe_webhook_secret.clone(),
                )
            };
            tracing::info!("Billing provider: Stripe");
            Arc::new(provider)
        }
        BillingProviderType::Polar => {
            let polar_api_key = std::env::var("POLAR_API_KEY")
                .expect("POLAR_API_KEY must be set when BILLING_PROVIDER=polar");
            let polar_webhook_secret = std::env::var("POLAR_WEBHOOK_SECRET")
                .expect("POLAR_WEBHOOK_SECRET must be set when BILLING_PROVIDER=polar");
            let provider = PolarProvider::new(polar_api_key, polar_webhook_secret);
            tracing::info!("Billing provider: Polar");
            Arc::new(provider)
        }
    };

    // Initialize metrics service
    let metrics_service = Arc::new(crate::services::metrics::MfaMetricsService::new(db.clone()));

    // Initialize centralized event dispatcher
    let event_dispatcher = Arc::new(crate::services::events::EventDispatcher::new(db.clone()));

    // Initialize risk engine for adaptive authentication
    let risk_engine = Arc::new(
        crate::services::risk_engine::RiskEngine::new().expect("Failed to initialize RiskEngine"),
    );

    // Check GeoIP database status and warn operator if unavailable
    if std::env::var("GEOIP_DISABLED").unwrap_or_default() != "true" {
        let geoip_db_path = std::env::var("GEOIP_DATABASE_PATH")
            .unwrap_or_else(|_| "data/GeoLite2-City.mmdb".to_string());

        if !std::path::Path::new(&geoip_db_path).exists() {
            tracing::warn!(
                "⚠️  GEOGRAPHIC SECURITY FEATURES DISABLED: GeoIP database not found at {}",
                geoip_db_path
            );
            tracing::warn!("   To enable impossible travel detection and geo-risk analysis:");
            tracing::warn!("   1. Run: ./scripts/setup_geoip.sh");
            tracing::warn!("   2. Or set: GEOIP_DISABLED=true (not recommended for production)");
        } else {
            tracing::info!("✓ GeoIP database available: {}", geoip_db_path);
        }
    } else {
        tracing::info!("GeoIP features explicitly disabled via GEOIP_DISABLED=true");
    }

    // Initialize WebAuthn service if base URL is available
    let webauthn_service = if !config.base_url.is_empty() {
        // Extract the host from base_url to use as rp_id
        let rp_id = match Url::parse(&config.base_url) {
            Ok(parsed_url) => parsed_url.host_str().unwrap_or("localhost").to_string(),
            Err(_) => {
                tracing::warn!(
                    "Invalid base_url format for WebAuthn service: {}",
                    config.base_url
                );
                "localhost".to_string()
            }
        };

        match crate::services::webauthn::WebAuthnService::new(
            &rp_id,
            &config.base_url,
            Some("SSO Platform"),
        ) {
            Ok(service) => Some(Arc::new(service)),
            Err(e) => {
                tracing::warn!("Failed to initialize WebAuthn service: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Initialize permission cache
    // TTL: 60 seconds (balances security/revocation speed with performance)
    // Max capacity: 10,000 users (adjust based on available RAM)
    use moka::future::Cache;
    use std::time::Duration;
    let permission_cache = Cache::builder()
        .time_to_live(Duration::from_secs(60))
        .max_capacity(10_000)
        .build();

    // Initialize user model cache
    // TTL: 30 seconds (shorter for security - faster detection of user changes)
    // Max capacity: 10,000 users
    // IMPORTANT: Invalidate on user updates (password change, role change, etc.)
    let user_cache: Cache<String, crate::entities::users::Model> = Cache::builder()
        .time_to_live(Duration::from_secs(30))
        .max_capacity(10_000)
        .build();

    // Initialize buffered audit actor
    // Uses db_writer for SQLite to avoid contention with main db pool
    #[cfg(feature = "db_sqlite")]
    let audit_actor = crate::services::audit_actor::AuditHandle::new(db_writer.clone());
    #[cfg(not(feature = "db_sqlite"))]
    let audit_actor = crate::services::audit_actor::AuditHandle::new(db.clone());

    // Create application state
    let app_state = AppState {
        db: db.clone(),
        #[cfg(feature = "db_sqlite")]
        db_writer: db_writer.clone(),
        oauth_client: oauth_client.clone(),
        jwt_service: jwt_service.clone(),
        base_url: config.base_url.clone(),
        web_client_url: config.platform_dashboard_base_url.clone(),
        encryption: encryption.clone().map(Arc::new),
        email_service: email_service.map(Arc::new),
        metrics_service: metrics_service.clone(),
        event_dispatcher: event_dispatcher.clone(),
        billing_provider: billing_provider.clone(),
        risk_engine: risk_engine.clone(),
        webauthn_service: webauthn_service.clone(),
        permission_cache,
        user_cache,
        audit_actor: audit_actor.clone(),
        config: config.clone(),
    };

    let webhook_state = WebhookState {
        db: db.clone(),
        #[cfg(feature = "db_sqlite")]
        db_writer: db_writer.clone(),
        billing_provider: billing_provider.clone(),
    };

    // Build routes using the router module
    let active_org_routes = router::active_org_routes(&app_state);
    let protected_routes = router::protected_routes(&app_state);
    let analytics_routes = router::analytics_routes(&app_state);
    let mfa_routes = router::mfa_routes(&app_state, &config);
    let mfa_verification_routes = router::mfa_verification_routes(&config);
    let platform_routes = router::platform_routes(&app_state);
    let service_api_routes = router::service_api_routes(&app_state);
    let scim_routes = router::scim_routes(&app_state);
    let public_routes = router::public_routes(&config);

    // Combine all routes
    let app = Router::new()
        // OIDC Discovery and JWKS endpoints (require state)
        .route(
            "/.well-known/openid-configuration",
            get(oidc_discovery_handler),
        )
        .route("/.well-known/jwks.json", get(jwks_handler))
        .merge(public_routes)
        .merge(protected_routes)
        .merge(mfa_routes)
        .merge(mfa_verification_routes)
        .merge(platform_routes)
        .merge(service_api_routes)
        .merge(scim_routes)
        .merge(analytics_routes)
        .with_state(app_state.clone())
        // Health readiness check (needs DB access)
        .route("/health/ready", get(readiness))
        .with_state(db.clone())
        // Webhook routes (separate state)
        .route("/webhooks/stripe", post(stripe_webhook))
        .route("/webhooks/billing", post(billing_webhook))
        .with_state(webhook_state)
        // Prometheus metrics endpoint
        .route("/metrics", get(metrics_handler))
        .layer(axum::Extension(Arc::new(prometheus_handle)))
        // Request info extraction (IP and User-Agent) - must be before auth
        .layer(axum::middleware::from_fn(
            crate::middleware::extract_request_info_middleware,
        ))
        // CORS
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        // Request timeout: Fail fast at 30 seconds to prevent runaway requests
        // Note: 5s was too aggressive - SAML cert generation (RSA) needs ~10-20s under load
        // 30s provides protection while allowing legitimate slow crypto operations
        .layer(tower_http::timeout::TimeoutLayer::new(Duration::from_secs(30)))
        // HTTP request duration metrics - outermost layer to capture full request lifecycle
        // This measures time including CORS handling, auth, and all other middleware
        .layer(axum::middleware::from_fn(
            crate::middleware::http_metrics_middleware,
        ));

    // --- More Aggressive WAL Checkpointing (SQLite only) ---
    #[cfg(feature = "db_sqlite")]
    {
        let checkpoint_db = db.clone();
        tokio::spawn(async move {
            use sea_orm::ConnectionTrait;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10)); // Checkpoint more frequently
            loop {
                interval.tick().await;
                // Use TRUNCATE to shrink the WAL file, which is more effective under heavy load
                if let Err(e) = checkpoint_db
                    .execute_unprepared("PRAGMA wal_checkpoint(TRUNCATE);")
                    .await
                {
                    tracing::warn!("WAL checkpoint failed: {}", e);
                } else {
                    tracing::debug!("WAL checkpoint (TRUNCATE) completed");
                }
            }
        });
    }

    // Start server
    let addr = format!("{}:{}", config.server_host, config.server_port);
    tracing::info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!("Server listening on http://{}", addr);
    tracing::info!("SSO endpoints:");
    tracing::info!("  - GET /auth/github");
    tracing::info!("  - GET /auth/google");
    tracing::info!("  - GET /auth/microsoft");
    tracing::info!("Device flow endpoints:");
    tracing::info!("  - POST /auth/device/code");
    tracing::info!("  - GET /activate");
    tracing::info!("  - POST /auth/token");
    tracing::info!("Protected API endpoints:");
    tracing::info!("  - GET /api/user");
    tracing::info!("  - GET /api/subscription");
    tracing::info!("Service API endpoints (API key auth):");
    tracing::info!("  - GET /api/service/users");
    tracing::info!("  - GET /api/service/subscriptions");
    tracing::info!("  - GET /api/service/analytics");
    tracing::info!("SCIM 2.0 endpoints (Bearer token auth):");
    tracing::info!("  - GET /scim/v2/Users");
    tracing::info!("  - POST /scim/v2/Users");
    tracing::info!("  - GET /scim/v2/Groups");
    tracing::info!("  - PATCH /scim/v2/Groups/:id");
    tracing::info!("Webhook endpoints:");
    tracing::info!("  - POST /webhooks/stripe");

    // Create the server with graceful shutdown support
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal(audit_actor));

    server.await?;

    Ok(())
}

/// Graceful shutdown signal handler
/// Waits for SIGTERM or SIGINT, then flushes audit actor before returning
async fn shutdown_signal(audit_actor: crate::services::audit_actor::AuditHandle) {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received Ctrl+C, initiating graceful shutdown...");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }

    // CRITICAL: Flush all pending audit logs before exiting
    audit_actor.shutdown().await;
}
