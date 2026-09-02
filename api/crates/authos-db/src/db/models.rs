use chrono::{DateTime, NaiveDateTime, Utc};
use sea_orm::FromQueryResult;
use serde::{Deserialize, Serialize};

/// Helper function to convert NaiveDateTime to DateTime<Utc>
fn naive_to_utc(naive: NaiveDateTime) -> DateTime<Utc> {
    DateTime::<Utc>::from_naive_utc_and_offset(naive, Utc)
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub email_verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<crate::entities::users::Model> for User {
    fn from(model: crate::entities::users::Model) -> Self {
        Self {
            id: model.id,
            email: model.email,
            is_platform_owner: model.is_platform_owner,
            password_hash: model.password_hash,
            email_verified_at: model.email_verified_at.map(naive_to_utc),
            created_at: naive_to_utc(model.created_at),
        }
    }
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuing_service_id: Option<String>,
}

impl From<crate::entities::identities::Model> for Identity {
    fn from(model: crate::entities::identities::Model) -> Self {
        Self {
            id: model.id,
            user_id: model.user_id,
            provider: model.provider,
            provider_user_id: model.provider_user_id,
            access_token: model.access_token,
            refresh_token: model.refresh_token,
            expires_at: model.expires_at.map(naive_to_utc),
            scopes: model.scopes,
            last_refreshed_at: model.last_refreshed_at.map(naive_to_utc),
            access_token_encrypted: model.access_token_encrypted,
            refresh_token_encrypted: model.refresh_token_encrypted,
            encryption_key_id: model.encryption_key_id,
            issuing_org_id: model.issuing_org_id,
            issuing_service_id: model.issuing_service_id,
        }
    }
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct UpstreamProvider {
    pub id: String,
    pub org_id: String,
    pub connection_id: String,
    pub name: String,
    pub provider_type: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_encrypted: Vec<u8>,
    pub encryption_key_id: String,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub discovery_url: Option<String>,
    pub scopes: Option<String>,
    pub issuer: Option<String>,
    pub metadata: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<crate::entities::upstream_providers::Model> for UpstreamProvider {
    fn from(model: crate::entities::upstream_providers::Model) -> Self {
        Self {
            id: model.id,
            org_id: model.org_id,
            connection_id: model.connection_id,
            name: model.name,
            provider_type: model.provider_type,
            client_id: model.client_id,
            client_secret_encrypted: model.client_secret_encrypted,
            encryption_key_id: model.encryption_key_id,
            authorization_url: model.authorization_url,
            token_url: model.token_url,
            userinfo_url: model.userinfo_url,
            discovery_url: model.discovery_url,
            scopes: model.scopes,
            issuer: model.issuer,
            metadata: model.metadata,
            enabled: model.enabled,
            created_at: naive_to_utc(model.created_at),
            updated_at: naive_to_utc(model.updated_at),
        }
    }
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
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
    pub custom_domain: Option<String>,
    pub domain_verified: bool,
    pub domain_verification_token: Option<String>,
    pub brand_logo_url: Option<String>,
    pub brand_primary_color: Option<String>,
    pub feature_overrides: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<crate::entities::organizations::Model> for Organization {
    fn from(model: crate::entities::organizations::Model) -> Self {
        Self {
            id: model.id,
            slug: model.slug,
            name: model.name,
            owner_user_id: model.owner_user_id,
            status: model.status,
            tier_id: model.tier_id,
            max_services: model.max_services.map(|v| v as i64),
            max_users: model.max_users.map(|v| v as i64),
            approved_by: model.approved_by,
            approved_at: model.approved_at.map(naive_to_utc),
            rejected_by: model.rejected_by,
            rejected_at: model.rejected_at.map(naive_to_utc),
            rejection_reason: model.rejection_reason,
            custom_domain: model.custom_domain,
            domain_verified: model.domain_verified,
            domain_verification_token: model.domain_verification_token,
            brand_logo_url: model.brand_logo_url,
            brand_primary_color: model.brand_primary_color,
            feature_overrides: model.feature_overrides,
            created_at: naive_to_utc(model.created_at),
            updated_at: naive_to_utc(model.updated_at),
        }
    }
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct Membership {
    pub id: String,
    pub org_id: String,
    pub user_id: String,
    pub role: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub service_type: String,
    pub client_id: String,
    pub client_secret_hash: String,
    pub github_scopes: Option<String>,
    pub microsoft_scopes: Option<String>,
    pub google_scopes: Option<String>,
    pub redirect_uris: Option<String>,
    pub device_activation_uri: Option<String>,
    pub resource_uris: Option<String>,
    // SAML configuration
    pub saml_enabled: bool,
    pub saml_entity_id: Option<String>,
    pub saml_acs_url: Option<String>,
    pub saml_slo_url: Option<String>,
    pub saml_name_id_format: Option<String>,
    pub saml_attribute_mapping: Option<String>, // JSON string
    pub saml_sign_assertions: bool,
    pub saml_sign_response: bool,
    pub created_at: DateTime<Utc>,
}

impl From<crate::entities::services::Model> for Service {
    fn from(model: crate::entities::services::Model) -> Self {
        Self {
            id: model.id,
            org_id: model.org_id,
            slug: model.slug,
            name: model.name,
            service_type: model.service_type,
            client_id: model.client_id,
            client_secret_hash: model.client_secret_hash,
            github_scopes: model.github_scopes,
            microsoft_scopes: model.microsoft_scopes,
            google_scopes: model.google_scopes,
            redirect_uris: model.redirect_uris,
            device_activation_uri: model.device_activation_uri,
            resource_uris: model.resource_uris,
            saml_enabled: model.saml_enabled,
            saml_entity_id: model.saml_entity_id,
            saml_acs_url: model.saml_acs_url,
            saml_slo_url: model.saml_slo_url,
            saml_name_id_format: model.saml_name_id_format,
            saml_attribute_mapping: model.saml_attribute_mapping,
            saml_sign_assertions: model.saml_sign_assertions,
            saml_sign_response: model.saml_sign_response,
            created_at: naive_to_utc(model.created_at),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResponse {
    pub id: String,
    pub org_id: String,
    pub slug: String,
    pub name: String,
    pub service_type: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub github_scopes: Option<Vec<String>>,
    pub microsoft_scopes: Option<Vec<String>>,
    pub google_scopes: Option<Vec<String>>,
    pub redirect_uris: Option<Vec<String>>,
    pub device_activation_uri: Option<String>,
    pub resource_uris: Option<Vec<String>>,
    // SAML configuration
    pub saml_enabled: bool,
    pub saml_entity_id: Option<String>,
    pub saml_acs_url: Option<String>,
    pub saml_slo_url: Option<String>,
    pub saml_name_id_format: Option<String>,
    pub saml_attribute_mapping: Option<std::collections::HashMap<String, String>>,
    pub saml_sign_assertions: bool,
    pub saml_sign_response: bool,
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
            client_secret: None, // Not stored, only shown during creation
            github_scopes: service
                .github_scopes
                .and_then(|s| serde_json::from_str(&s).ok()),
            microsoft_scopes: service
                .microsoft_scopes
                .and_then(|s| serde_json::from_str(&s).ok()),
            google_scopes: service
                .google_scopes
                .and_then(|s| serde_json::from_str(&s).ok()),
            redirect_uris: service
                .redirect_uris
                .and_then(|s| serde_json::from_str(&s).ok()),
            device_activation_uri: service.device_activation_uri,
            resource_uris: service
                .resource_uris
                .and_then(|s| serde_json::from_str(&s).ok()),
            saml_enabled: service.saml_enabled,
            saml_entity_id: service.saml_entity_id,
            saml_acs_url: service.saml_acs_url,
            saml_slo_url: service.saml_slo_url,
            saml_name_id_format: service.saml_name_id_format,
            saml_attribute_mapping: service
                .saml_attribute_mapping
                .and_then(|s| serde_json::from_str(&s).ok()),
            saml_sign_assertions: service.saml_sign_assertions,
            saml_sign_response: service.saml_sign_response,
            created_at: service.created_at,
        }
    }
}

impl ServiceResponse {
    /// Create a ServiceResponse with client_secret (only for creation responses)
    pub fn with_client_secret(
        service: crate::entities::services::Model,
        client_secret: String,
    ) -> Self {
        let mut response = Self::from(service);
        response.client_secret = Some(client_secret);
        response
    }
}

impl From<crate::entities::services::Model> for ServiceResponse {
    fn from(service: crate::entities::services::Model) -> Self {
        Self {
            id: service.id,
            org_id: service.org_id,
            slug: service.slug,
            name: service.name,
            service_type: service.service_type,
            client_id: service.client_id,
            client_secret: None, // Not stored, only shown during creation
            github_scopes: service
                .github_scopes
                .and_then(|s| serde_json::from_str(&s).ok()),
            microsoft_scopes: service
                .microsoft_scopes
                .and_then(|s| serde_json::from_str(&s).ok()),
            google_scopes: service
                .google_scopes
                .and_then(|s| serde_json::from_str(&s).ok()),
            redirect_uris: service
                .redirect_uris
                .and_then(|s| serde_json::from_str(&s).ok()),
            device_activation_uri: service.device_activation_uri,
            resource_uris: service
                .resource_uris
                .and_then(|s| serde_json::from_str(&s).ok()),
            saml_enabled: service.saml_enabled,
            saml_entity_id: service.saml_entity_id,
            saml_acs_url: service.saml_acs_url,
            saml_slo_url: service.saml_slo_url,
            saml_name_id_format: service.saml_name_id_format,
            saml_attribute_mapping: service
                .saml_attribute_mapping
                .and_then(|s| serde_json::from_str(&s).ok()),
            saml_sign_assertions: service.saml_sign_assertions,
            saml_sign_response: service.saml_sign_response,
            created_at: naive_to_utc(service.created_at),
        }
    }
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub description: Option<String>,
    pub price_cents: i64,
    pub currency: String,
    pub features: Option<String>, // JSON string
    pub stripe_price_id: Option<String>,
    pub is_default: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub user_id: String,
    pub service_id: String,
    pub plan_id: String,
    pub status: String,
    pub current_period_end: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
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

impl From<crate::entities::device_codes::Model> for DeviceCode {
    fn from(model: crate::entities::device_codes::Model) -> Self {
        Self {
            id: model.id,
            device_code: model.device_code,
            user_code: model.user_code,
            client_id: model.client_id,
            org_slug: model.org_slug,
            service_slug: model.service_slug,
            expires_at: naive_to_utc(model.expires_at),
            user_id: model.user_id,
            status: model.status,
        }
    }
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub refresh_token: Option<String>,
    pub refresh_token_expires_at: Option<DateTime<Utc>>,
    pub org_slug: Option<String>,
    pub service_id: Option<String>,
    pub resource: Option<String>,
    pub user_agent: Option<String>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<crate::entities::sessions::Model> for Session {
    fn from(model: crate::entities::sessions::Model) -> Self {
        Self {
            id: model.id,
            user_id: model.user_id,
            token_hash: model.token_hash,
            expires_at: naive_to_utc(model.expires_at),
            refresh_token: model.refresh_token,
            refresh_token_expires_at: model.refresh_token_expires_at.map(naive_to_utc),
            org_slug: model.org_slug,
            service_id: model.service_id,
            resource: model.resource,
            user_agent: model.user_agent,
            ip_address: model.ip_address,
            created_at: naive_to_utc(model.created_at),
        }
    }
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
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

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
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
    pub saml_state_id: Option<String>,
    pub upstream_connection_id: Option<String>,
    pub requested_scopes: Option<String>,
    pub client_state: Option<String>,
    pub provider_token_request_state: Option<String>,
    pub resource: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl From<crate::entities::oauth_states::Model> for OAuthState {
    fn from(model: crate::entities::oauth_states::Model) -> Self {
        Self {
            state: model.state,
            pkce_verifier: model.pkce_verifier,
            service_id: model.service_id,
            redirect_uri: model.redirect_uri,
            org_slug: model.org_slug,
            service_slug: model.service_slug,
            is_admin_flow: model.is_admin_flow,
            user_id_for_linking: model.user_id_for_linking,
            device_user_code: model.device_user_code,
            saml_state_id: model.saml_state_id,
            upstream_connection_id: model.upstream_connection_id,
            requested_scopes: model.requested_scopes,
            client_state: model.client_state,
            provider_token_request_state: model.provider_token_request_state,
            resource: model.resource,
            created_at: naive_to_utc(model.created_at),
            expires_at: naive_to_utc(model.expires_at),
        }
    }
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct TokenRefreshLock {
    pub user_id: String,
    pub acquired_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
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

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
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

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct PlatformAuditLog {
    pub id: String,
    pub platform_owner_id: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub metadata: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct LoginEvent {
    pub id: String,
    pub user_id: String,
    pub service_id: String,
    pub provider: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
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

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct UserTotpSecret {
    pub id: String,
    pub user_id: String,
    #[serde(skip_serializing)]
    pub secret_encrypted: Vec<u8>,
    pub encryption_key_id: String,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub enabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct TotpBackupCode {
    pub id: String,
    pub user_id: String,
    #[serde(skip_serializing)]
    pub code_hash: String,
    pub used: bool,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct OrganizationAuditLog {
    pub id: String,
    pub org_id: String,
    pub actor_user_id: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub details: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct OrganizationAuditLogWithUser {
    pub id: String,
    pub org_id: String,
    pub actor_user_id: String,
    pub actor_user_email: Option<String>,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub details: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct Webhook {
    pub id: String,
    pub org_id: String,
    pub name: String,
    pub url: String,
    #[serde(skip_serializing)]
    pub secret: String,
    pub events: String, // JSON array of subscribed events
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct WebhookDelivery {
    pub id: String,
    pub webhook_id: String,
    pub event_type: String,
    pub payload: String,
    pub response_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub delivered: bool,
    pub delivery_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct WebhookDeliveryWithWebhook {
    pub id: String,
    pub webhook_id: String,
    pub webhook_name: String,
    pub webhook_url: String,
    pub event_type: String,
    pub payload: String,
    pub response_status_code: Option<i32>,
    pub response_body: Option<String>,
    pub attempt_count: i32,
    pub max_attempts: i32,
    pub next_retry_at: Option<DateTime<Utc>>,
    pub delivered: bool,
    pub delivery_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub prefix: String,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub permissions: String, // JSON array
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

impl From<crate::entities::api_keys::Model> for ApiKey {
    fn from(entity: crate::entities::api_keys::Model) -> Self {
        Self {
            id: entity.id,
            service_id: entity.service_id,
            name: entity.name,
            prefix: entity.prefix,
            key_hash: entity.key_hash,
            permissions: entity.permissions,
            last_used_at: entity.last_used_at.map(naive_to_utc),
            expires_at: entity.expires_at.map(naive_to_utc),
            created_at: naive_to_utc(entity.created_at),
            created_by: entity.created_by,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyResponse {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub prefix: String,
    pub permissions: Vec<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

impl ApiKeyResponse {
    pub fn from_api_key(api_key: ApiKey) -> Self {
        Self {
            id: api_key.id,
            service_id: api_key.service_id,
            name: api_key.name,
            prefix: api_key.prefix,
            permissions: serde_json::from_str(&api_key.permissions).unwrap_or_default(),
            last_used_at: api_key.last_used_at,
            expires_at: api_key.expires_at,
            created_at: api_key.created_at,
            created_by: api_key.created_by,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyCreateResponse {
    pub id: String,
    pub service_id: String,
    pub name: String,
    pub prefix: String,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub key: String, // The full key is ONLY returned once upon creation
}

// SAML 2.0 Identity Provider models

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct SamlSigningKey {
    pub id: String,
    pub service_id: String,
    #[serde(skip_serializing)]
    pub private_key_encrypted: Vec<u8>,
    pub public_key: String, // X.509 certificate in PEM format
    pub encryption_key_id: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromQueryResult, Serialize, Deserialize)]
pub struct SamlState {
    pub state_id: String,
    pub service_id: String,
    pub saml_request: String, // Base64 encoded SAML AuthnRequest
    pub relay_state: Option<String>,
    pub acs_url: String,
    pub request_id: Option<String>,
    pub issuer: Option<String>,
    pub binding: Option<String>,
    pub user_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlConfiguration {
    pub saml_enabled: bool,
    pub saml_entity_id: Option<String>,
    pub saml_acs_url: Option<String>,
    pub saml_slo_url: Option<String>,
    pub saml_name_id_format: Option<String>,
    pub saml_attribute_mapping: Option<std::collections::HashMap<String, String>>,
    pub saml_sign_assertions: bool,
    pub saml_sign_response: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlCertificateInfo {
    pub public_key: String, // X.509 certificate in PEM format
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub lifecycle_status: String,
    pub expires_in_seconds: i64,
    pub published_previous_certificates: Vec<SamlPublishedCertificateInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamlPublishedCertificateInfo {
    pub public_key: String,
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub publish_until: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

// Custom Domains & Branding models

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrandingConfiguration {
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfiguration {
    pub custom_domain: Option<String>,
    pub domain_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVerificationResponse {
    pub verification_token: String,
    pub verification_methods: Vec<DomainVerificationMethod>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVerificationMethod {
    pub method: String,
    pub instructions: String,
    pub record_type: Option<String>,
    pub record_name: Option<String>,
    pub record_value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainVerificationResult {
    pub verified: bool,
    pub message: String,
}
