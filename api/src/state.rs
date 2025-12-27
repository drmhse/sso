use crate::auth::jwt::JwtService;
use crate::auth::sso::OAuthClient;
use crate::billing::BillingProvider;
use axum::extract::FromRef;
use moka::future::Cache;
use sea_orm::DatabaseConnection;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: DatabaseConnection,
    /// SQLite-only: Dedicated writer connection (single connection pool).
    /// All write transactions go through this to prevent nested transaction issues.
    /// For PostgreSQL/MySQL, this is None and `db` is used for all operations.
    #[cfg(feature = "db_sqlite")]
    pub db_writer: DatabaseConnection,
    pub oauth_client: Arc<OAuthClient>,
    pub jwt_service: Arc<JwtService>,
    pub base_url: String,
    pub web_client_url: String,
    pub encryption: Option<Arc<crate::encryption::EncryptionService>>,
    pub email_service: Option<Arc<crate::email::EmailService>>,
    pub metrics_service: Arc<crate::services::metrics::MfaMetricsService>,
    pub event_dispatcher: Arc<crate::services::events::EventDispatcher>,
    /// Provider-agnostic billing service (Stripe, Polar, etc.)
    pub billing_provider: Arc<dyn BillingProvider>,
    pub risk_engine: Arc<crate::services::risk_engine::RiskEngine>,
    pub webauthn_service: Option<Arc<crate::services::webauthn::WebAuthnService>>,

    // Permission Cache: Key = user_id (String), Value = Vec<String> (permissions)
    // TTL: 60 seconds (balances security/revocation speed with performance)
    // Max capacity: 10,000 users (adjust based on available RAM)
    pub permission_cache: Cache<String, Vec<String>>,

    // User Model Cache: Key = user_id (String), Value = User model
    // TTL: 30 seconds (security-conscious - faster permission revocation detection)
    // Max capacity: 10,000 users
    // IMPORTANT: Invalidate cache on user updates (password change, role change, etc.)
    pub user_cache: Cache<String, crate::entities::users::Model>,

    // Buffered audit actor: removes 66% of write pressure from login critical path
    // Batches audit events and writes them asynchronously with retry on DB locks
    pub audit_actor: crate::services::audit_actor::AuditHandle,

    pub config: crate::config::Config,
}

// Implement FromRef to allow extracting the tuple needed by the JWT middleware
impl FromRef<AppState> for (DatabaseConnection, Arc<JwtService>) {
    fn from_ref(state: &AppState) -> Self {
        (state.db.clone(), state.jwt_service.clone())
    }
}

// Implement FromRef to allow extracting the permission cache
impl FromRef<AppState> for Cache<String, Vec<String>> {
    fn from_ref(state: &AppState) -> Self {
        state.permission_cache.clone()
    }
}
