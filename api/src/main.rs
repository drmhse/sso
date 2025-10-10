mod auth;
mod billing;
mod config;
mod constants;
mod db;
mod encryption;
mod error;
mod handlers;
mod jobs;
mod middleware;

use crate::auth::jwt::JwtService;
use crate::auth::sso::OAuthClient;
use crate::billing::stripe::StripeService;
use crate::config::Config;
use crate::constants::DEVICE_CODE_EXPIRE_MINUTES;
use crate::db::models::DeviceCode;
use crate::encryption::EncryptionService;
use crate::handlers::analytics::{
    get_login_trends, get_logins_by_provider, get_logins_by_service, get_recent_logins,
    AnalyticsState,
};
use crate::handlers::auth::{
    activate_page, auth_admin_callback, auth_admin_provider, auth_callback, auth_provider,
    device_code, device_verify, logout, token_exchange, AppState, DbRequest,
};
use crate::handlers::identities::{list_identities, start_link, unlink_identity};
use crate::handlers::invitations::{
    accept_invitation, accept_invitation_redirect, cancel_invitation, create_invitation,
    decline_invitation, list_invitations, list_user_invitations,
};
use crate::handlers::organizations::{
    create_organization_public, get_end_user, get_org_oauth_credentials, get_organization,
    list_end_users, list_members, list_user_organizations, remove_member, revoke_end_user_sessions,
    set_org_oauth_credentials, transfer_ownership, update_member_role, update_organization,
};
use crate::handlers::platform::{
    activate_organization, approve_organization, demote_platform_owner, get_audit_log,
    list_organizations, list_tiers, promote_platform_owner, reject_organization,
    suspend_organization, update_organization_tier,
};
use crate::handlers::provider_token::get_provider_token;
use crate::handlers::services::{
    create_plan, create_service, delete_service, get_service, list_organization_services,
    list_service_plans, update_service,
};
use crate::handlers::subscription::{get_subscription, get_user, update_user};
use crate::handlers::webhook::{stripe_webhook, WebhookState};
use crate::jobs::token_refresh::TokenRefreshJob;
use axum::{
    middleware as axum_middleware,
    routing::{delete, get, patch, post},
    Router,
};
use sqlx::{Sqlite, SqlitePool, Transaction};
use std::env;
use std::sync::Arc;
use tokio::sync::mpsc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

const BATCH_SIZE: usize = 256; // Increase batch size for higher throughput
const BATCH_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5); // Decrease timeout

/// Handles a batch of device code creation requests within a single transaction.
async fn handle_create_device_code_batch(
    transaction: &mut Transaction<'_, Sqlite>,
    batch: Vec<DbRequest>,
) {
    if batch.is_empty() {
        return;
    }

    let values_placeholder = "(?, ?, ?, ?, ?, ?, ?, 'pending')";
    let placeholders: Vec<&str> = (0..batch.len()).map(|_| values_placeholder).collect();
    let sql = format!(
        "INSERT INTO device_codes (id, device_code, user_code, client_id, org_slug, service_slug, expires_at, status) VALUES {}",
        placeholders.join(", ")
    );

    let mut query_builder = sqlx::query(&sql);
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(DEVICE_CODE_EXPIRE_MINUTES);

    // Bind all pre-generated values from the batch
    for req in &batch {
        let DbRequest::CreateDeviceCode {
            id,
            device_code,
            user_code,
            client_id,
            org_slug,
            service_slug,
            ..
        } = req;
        query_builder = query_builder
            .bind(id)
            .bind(device_code)
            .bind(user_code)
            .bind(client_id)
            .bind(org_slug)
            .bind(service_slug)
            .bind(expires_at);
    }

    // Execute the single, large query. We don't need RETURNING anymore.
    match query_builder.execute(&mut **transaction).await {
        Ok(_) => {
            for req in batch.into_iter() {
                let DbRequest::CreateDeviceCode {
                    id,
                    device_code,
                    user_code,
                    client_id,
                    org_slug,
                    service_slug,
                    responder,
                } = req;
                let response_code = DeviceCode {
                    id,
                    device_code,
                    user_code,
                    client_id,
                    org_slug,
                    service_slug,
                    expires_at,
                    user_id: None,
                    status: "pending".to_string(),
                };
                let _ = responder.send(Ok(response_code));
            }
        }
        Err(e) => {
            tracing::error!("Batch insert failed: {}", e);
            let error_msg = format!("Database batch insert failed: {}", e);
            for req in batch {
                use crate::error::AppError;
                let DbRequest::CreateDeviceCode { responder, .. } = req;
                let _ = responder.send(Err(AppError::InternalServerError(error_msg.clone())));
            }
        }
    }
}

// The DB writer task logic remains the same, but it will be much faster now.
async fn db_writer_task(pool: SqlitePool, mut rx: mpsc::Receiver<DbRequest>) {
    tracing::info!("Batching DB writer task started");
    let mut batch = Vec::with_capacity(BATCH_SIZE);

    loop {
        let msg = tokio::time::timeout(BATCH_TIMEOUT, rx.recv()).await;

        let should_process_batch = match msg {
            Ok(Some(req)) => {
                batch.push(req);
                batch.len() >= BATCH_SIZE
            }
            Err(_) => !batch.is_empty(),
            Ok(None) => break,
        };

        if should_process_batch {
            // Attempt to start a transaction. If it fails (e.g., db is locked by checkpoint),
            // log the error and continue. The batch will be retried on the next loop.
            match pool.begin().await {
                Ok(mut transaction) => {
                    handle_create_device_code_batch(&mut transaction, std::mem::take(&mut batch))
                        .await;
                    if let Err(e) = transaction.commit().await {
                        tracing::error!("Failed to commit transaction: {}", e);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Could not begin transaction, will retry batch. Error: {}",
                        e
                    );
                }
            }
        }
    }

    // Process any remaining items before shutting down
    if !batch.is_empty() {
        if let Ok(mut transaction) = pool.begin().await {
            handle_create_device_code_batch(&mut transaction, std::mem::take(&mut batch)).await;
            let _ = transaction.commit().await;
        }
    }
    tracing::info!("DB writer task finished");
}

/// Ensures a platform owner exists with the given email.
/// If the user exists, updates is_platform_owner to true.
/// If the user doesn't exist, creates one.
async fn ensure_platform_owner(pool: &SqlitePool, email: &str) -> anyhow::Result<()> {
    let user_id = uuid::Uuid::new_v4().to_string();

    // Try to insert or update the user
    let result = sqlx::query(
        "INSERT INTO users (id, email, is_platform_owner)
         VALUES (?, ?, 1)
         ON CONFLICT(email) DO UPDATE SET is_platform_owner = 1",
    )
    .bind(&user_id)
    .bind(email)
    .execute(pool)
    .await;

    match result {
        Ok(_) => {
            tracing::info!("Platform owner ensured: {}", email);
            Ok(())
        }
        Err(e) => {
            tracing::error!("Failed to ensure platform owner: {}", e);
            Err(e.into())
        }
    }
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

    // Initialize database pool
    tracing::info!("Connecting to database: {}", config.database_url);
    let pool = db::init_pool(&config.database_url)
        .await
        .expect("Failed to initialize database");
    tracing::info!("Database initialized successfully");

    // Bootstrap platform owner if configured
    if let Ok(email) = env::var("PLATFORM_OWNER_EMAIL") {
        ensure_platform_owner(&pool, &email).await?;
    }

    // --- DB Writer Channel Setup ---
    let (tx, rx) = mpsc::channel::<DbRequest>(16384);
    let writer_pool = pool.clone();
    tokio::spawn(db_writer_task(writer_pool, rx));
    // --- End DB Writer Setup ---

    // Initialize encryption service (optional)
    let encryption = EncryptionService::new().ok();
    if encryption.is_some() {
        tracing::info!("Encryption service initialized");
    } else {
        tracing::warn!("Encryption service not available - tokens will be stored in plaintext");
    }

    // Start background token refresh job
    if let Some(enc) = encryption.clone() {
        let refresh_pool = pool.clone();
        tokio::spawn(async move {
            let job = TokenRefreshJob::new(refresh_pool, Some(enc));
            job.start().await;
        });
        tracing::info!("Token refresh job started");
    }

    // Initialize services
    let oauth_client =
        Arc::new(OAuthClient::new(&config).expect("Failed to initialize OAuth client"));
    let jwt_service = Arc::new(JwtService::new(
        &config.jwt_secret,
        config.jwt_expiration_hours,
    ));
    let stripe_service = Arc::new(StripeService::new(
        config.stripe_secret_key.clone(),
        config.stripe_webhook_secret.clone(),
    ));

    // Create application state
    let app_state = AppState {
        pool: pool.clone(),
        oauth_client: oauth_client.clone(),
        jwt_service: jwt_service.clone(),
        base_url: config.base_url.clone(),
        db_tx: tx, // Add the channel sender to the state
        encryption: encryption.clone().map(Arc::new),
    };

    let webhook_state = WebhookState {
        pool: pool.clone(),
        stripe_service: stripe_service.clone(),
    };

    let analytics_state = AnalyticsState {
        pool: pool.clone(),
    };

    // Build routes that require active organization status
    // These routes are restricted when org is pending/suspended
    let active_org_routes = Router::new()
        // OAuth credentials management (BYOO)
        .route(
            "/api/organizations/:org_slug/oauth-credentials/:provider",
            post(set_org_oauth_credentials),
        )
        .route(
            "/api/organizations/:org_slug/oauth-credentials/:provider",
            get(get_org_oauth_credentials),
        )
        // End-user management routes
        .route("/api/organizations/:org_slug/users", get(list_end_users))
        .route(
            "/api/organizations/:org_slug/users/:user_id",
            get(get_end_user),
        )
        .route(
            "/api/organizations/:org_slug/users/:user_id/sessions",
            delete(revoke_end_user_sessions),
        )
        // Service management routes - combine methods for the same path
        .route("/api/organizations/:org_slug/services/:service_slug/plans",
                get(list_service_plans).post(create_plan))
        .route("/api/organizations/:org_slug/services/:service_slug",
                get(get_service).patch(update_service).delete(delete_service))
        .route("/api/organizations/:org_slug/services",
                get(list_organization_services).post(create_service))
        // Apply active organization check middleware
        .route_layer(axum_middleware::from_fn_with_state(
            app_state.clone(),
            crate::middleware::require_active_organization,
        ));

    // Analytics routes (require JWT and org membership)
    let analytics_routes = Router::new()
        .route(
            "/api/organizations/:org_slug/analytics/login-trends",
            get(get_login_trends),
        )
        .route(
            "/api/organizations/:org_slug/analytics/logins-by-service",
            get(get_logins_by_service),
        )
        .route(
            "/api/organizations/:org_slug/analytics/logins-by-provider",
            get(get_logins_by_provider),
        )
        .route(
            "/api/organizations/:org_slug/analytics/recent-logins",
            get(get_recent_logins),
        )
        .with_state(analytics_state)
        .route_layer(axum_middleware::from_fn_with_state(
            (app_state.pool.clone(), app_state.jwt_service.clone()),
            crate::middleware::extract_user_from_jwt,
        ));

    // Build protected routes (require JWT)
    let protected_routes = Router::new()
        .route("/api/user", get(get_user))
        .route("/api/user", patch(update_user))
        .route("/api/subscription", get(get_subscription))
        .route("/api/provider-token/:provider", get(get_provider_token))
        // Identity linking routes
        .route("/api/user/identities", get(list_identities))
        .route("/api/user/identities/:provider/link", post(start_link))
        .route("/api/user/identities/:provider", delete(unlink_identity))
        // Organization routes (not restricted by org status)
        .route("/api/organizations", get(list_user_organizations))
        .route("/api/organizations/:org_slug", get(get_organization))
        .route("/api/organizations/:org_slug", patch(update_organization))
        .route("/api/organizations/:org_slug/members", get(list_members))
        .route(
            "/api/organizations/:org_slug/members/:user_id",
            patch(update_member_role),
        )
        .route(
            "/api/organizations/:org_slug/members/:user_id",
            post(remove_member),
        )
        .route(
            "/api/organizations/:org_slug/transfer-ownership",
            post(transfer_ownership),
        )
        // Invitation routes (not restricted by org status)
        .route(
            "/api/organizations/:org_slug/invitations",
            post(create_invitation),
        )
        .route(
            "/api/organizations/:org_slug/invitations",
            get(list_invitations),
        )
        .route(
            "/api/organizations/:org_slug/invitations/:invitation_id",
            post(cancel_invitation),
        )
        .route("/api/invitations", get(list_user_invitations))
        .route("/api/invitations/accept", post(accept_invitation))
        .route("/api/invitations/decline", post(decline_invitation))
        .route("/invitations/accept", get(accept_invitation_redirect)) // For email links
        // Merge active org routes
        .merge(active_org_routes)
        .route_layer(axum_middleware::from_fn_with_state(
            (app_state.pool.clone(), app_state.jwt_service.clone()),
            crate::middleware::extract_user_from_jwt,
        ));

    // Build platform owner routes (require JWT + platform owner)
    let platform_routes = Router::new()
        .route("/api/platform/tiers", get(list_tiers))
        .route("/api/platform/organizations", get(list_organizations))
        .route(
            "/api/platform/organizations/:id/approve",
            post(approve_organization),
        )
        .route(
            "/api/platform/organizations/:id/reject",
            post(reject_organization),
        )
        .route(
            "/api/platform/organizations/:id/suspend",
            post(suspend_organization),
        )
        .route(
            "/api/platform/organizations/:id/activate",
            post(activate_organization),
        )
        .route(
            "/api/platform/organizations/:id/tier",
            patch(update_organization_tier),
        )
        .route("/api/platform/owners", post(promote_platform_owner))
        .route(
            "/api/platform/owners/:user_id",
            delete(demote_platform_owner),
        )
        .route("/api/platform/audit-log", get(get_audit_log))
        .route_layer(axum_middleware::from_fn(
            crate::middleware::require_platform_owner,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            (app_state.pool.clone(), app_state.jwt_service.clone()),
            crate::middleware::extract_user_from_jwt,
        ));

    // Build public routes
    let public_routes = Router::new()
        // SSO routes
        .route("/auth/:provider", get(auth_provider))
        .route("/auth/:provider/callback", get(auth_callback))
        .route("/api/auth/logout", post(logout))
        // Admin authentication routes
        .route("/auth/admin/:provider", get(auth_admin_provider))
        .route("/auth/admin/:provider/callback", get(auth_admin_callback))
        // Device flow routes
        .route("/auth/device/code", post(device_code))
        .route("/activate", get(activate_page))
        .route("/auth/device/verify", post(device_verify))
        .route("/auth/token", post(token_exchange))
        // Public organization creation
        .route("/api/organizations", post(create_organization_public));

    // Combine all routes
    let app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .merge(platform_routes)
        .with_state(app_state)
        // Analytics routes (separate state)
        .merge(analytics_routes)
        // Webhook routes (separate state)
        .route("/webhooks/stripe", post(stripe_webhook))
        .with_state(webhook_state)
        // CORS
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        );

    // --- More Aggressive WAL Checkpointing ---
    let checkpoint_pool = pool.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10)); // Checkpoint more frequently
        loop {
            interval.tick().await;
            // Use TRUNCATE to shrink the WAL file, which is more effective under heavy load
            if let Err(e) = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE);")
                .execute(&checkpoint_pool)
                .await
            {
                tracing::warn!("WAL checkpoint failed: {}", e);
            } else {
                tracing::debug!("WAL checkpoint (TRUNCATE) completed");
            }
        }
    });

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
    tracing::info!("Webhook endpoints:");
    tracing::info!("  - POST /webhooks/stripe");

    axum::serve(listener, app).await?;

    Ok(())
}
