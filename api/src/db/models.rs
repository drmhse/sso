use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Identity {
    pub id: String,
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Option<String>,
    pub last_refreshed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_org_id: Option<String>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Organization {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub owner_user_id: String,
    pub status: String,
    pub tier_id: Option<String>,
    pub max_services: Option<i64>,
    pub max_users: Option<i64>,
    pub approved_by: Option<String>,
    pub approved_at: Option<DateTime<Utc>>,
    pub rejected_by: Option<String>,
    pub rejected_at: Option<DateTime<Utc>>,
    pub rejection_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Membership {
    pub id: String,
    pub org_id: String,
    pub user_id: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub service_type: String,
    pub client_id: String,
    pub github_scopes: Option<String>,
    pub microsoft_scopes: Option<String>,
    pub google_scopes: Option<String>,
    pub redirect_uris: Option<String>,
    pub device_activation_uri: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponse {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub service_type: String,
    pub client_id: String,
    pub github_scopes: Option<Vec<String>>,
    pub microsoft_scopes: Option<Vec<String>>,
    pub google_scopes: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub device_activation_uri: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<Service> for ServiceResponse {
    fn from(service: Service) -> Self {
        Self {
            id: service.id,
            org_id: service.org_id,
            slug: service.slug,
            name: service.name,
            service_type: service.service_type,
            client_id: service.client_id,
            github_scopes: service.github_scopes.and_then(|s| serde_json::from_str(&s).ok()),
            microsoft_scopes: service.microsoft_scopes.and_then(|s| serde_json::from_str(&s).ok()),
            google_scopes: service.google_scopes.and_then(|s| serde_json::from_str(&s).ok()),
            redirect_uris: service.redirect_uris.and_then(|s| serde_json::from_str(&s).ok()),
            device_activation_uri: service.device_activation_uri,
            created_at: service.created_at,
        }
    }
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub price_cents: i64,
    pub currency: String,
    pub features: Option<String>, // JSON string
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub user_id: String,
    pub service_id: String,
    pub plan_id: String,
    pub status: String,
    pub current_period_end: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct DeviceCode {
    pub id: String,
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub org_slug: String,
    pub service_slug: String,
    pub expires_at: DateTime<Utc>,
    pub user_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub org_slug: Option<String>,
    pub service_id: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct StripeCustomer {
    pub id: String,
    pub org_id: String,
    pub stripe_customer_id: String,
}

// Helper structs for queries
#[derive(Debug, Serialize, Deserialize)]
pub struct PlanFeatures {
    pub features: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserWithContext {
    pub user: User,
    pub org: Organization,
    pub membership: Membership,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OAuthState {
    pub state: String,
    pub pkce_verifier: Option<String>,
    pub service_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub org_slug: Option<String>,
    pub service_slug: Option<String>,
    pub is_admin_flow: bool,
    pub user_id_for_linking: Option<String>,
    pub device_user_code: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct TokenRefreshLock {
    pub user_id: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OrganizationTier {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub default_max_services: i64,
    pub default_max_users: i64,
    pub features: Option<String>,
    pub price_cents: i64,
    pub currency: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OrganizationInvitation {
    pub id: String,
    pub org_id: String,
    pub email: String,
    pub role: String,
    pub invited_by: String,
    pub status: String,
    pub token: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct PlatformAuditLog {
    pub id: String,
    pub platform_owner_id: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct LoginEvent {
    pub id: String,
    pub user_id: String,
    pub service_id: String,
    pub provider: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct OrganizationOAuthCredential {
    pub id: String,
    pub org_id: String,
    pub provider: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    #[allow(dead_code)] // Used for database storage only
    pub client_secret_encrypted: Vec<u8>,
    pub encryption_key_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
