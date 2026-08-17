use crate::auth::jwt::JwtService;
use crate::error::AppError;
use crate::state::AppState;
use crate::store::{
    oauth_authorization_grants::OAuthAuthorizationGrantStore, organizations::OrganizationStore,
    services::ServiceStore, sessions::SessionStore, users::UserStore, DB,
};
use crate::utils::{
    client_secret::verify_client_secret, resource_indicators::validate_requested_resource,
};
use axum::{
    extract::{Form, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::Utc;
use serde::{Deserialize, Serialize};

const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_BEARER_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const ID_JAG_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:id-jag";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";

#[derive(Debug, Deserialize)]
pub struct EnterpriseTokenRequest {
    pub grant_type: String,
    pub requested_token_type: Option<String>,
    pub audience: Option<String>,
    pub resource: Option<String>,
    pub scope: Option<String>,
    pub subject_token: Option<String>,
    pub subject_token_type: Option<String>,
    pub assertion: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EnterpriseTokenResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issued_token_type: Option<String>,
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct OAuthErrorBody {
    error: &'static str,
    error_description: String,
}

#[derive(Debug)]
pub(crate) struct OAuthTokenError {
    status: StatusCode,
    error: &'static str,
    description: String,
}

type OAuthResult<T> = std::result::Result<T, OAuthTokenError>;

impl OAuthTokenError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_request",
            description: message.into(),
        }
    }

    fn invalid_grant(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_grant",
            description: message.into(),
        }
    }

    fn invalid_client(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            error: "invalid_client",
            description: message.into(),
        }
    }

    fn invalid_scope(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            error: "invalid_scope",
            description: message.into(),
        }
    }
}

impl From<AppError> for OAuthTokenError {
    fn from(error: AppError) -> Self {
        match error {
            AppError::Unauthorized(message) => OAuthTokenError::invalid_grant(message),
            AppError::Forbidden(message) => OAuthTokenError::invalid_grant(message),
            AppError::Jwt(_) | AppError::TokenExpired => {
                OAuthTokenError::invalid_grant("Invalid or expired token")
            }
            AppError::BadRequest(message) => OAuthTokenError::invalid_request(message),
            AppError::NotFound(message) => OAuthTokenError::invalid_grant(message),
            other => {
                tracing::error!("Enterprise token endpoint failed: {}", other);
                OAuthTokenError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    error: "server_error",
                    description: "Token request failed".to_string(),
                }
            }
        }
    }
}

impl IntoResponse for OAuthTokenError {
    fn into_response(self) -> Response {
        (
            self.status,
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
            ],
            Json(OAuthErrorBody {
                error: self.error,
                error_description: self.description,
            }),
        )
            .into_response()
    }
}

fn token_response(body: EnterpriseTokenResponse) -> Response {
    (
        StatusCode::OK,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        Json(body),
    )
        .into_response()
}

fn normalize_issuer(value: &str) -> String {
    value.trim_end_matches('/').to_string()
}

fn client_credentials(
    headers: &HeaderMap,
    req: &EnterpriseTokenRequest,
) -> OAuthResult<(String, Option<String>)> {
    if let Some(auth) = headers.get(header::AUTHORIZATION).and_then(|value| {
        let value = value.to_str().ok()?;
        let (scheme, credentials) = value.split_once(' ')?;
        scheme.eq_ignore_ascii_case("Basic").then_some(credentials)
    }) {
        let decoded = STANDARD
            .decode(auth)
            .map_err(|_| OAuthTokenError::invalid_client("Invalid client authentication"))?;
        let decoded = String::from_utf8(decoded)
            .map_err(|_| OAuthTokenError::invalid_client("Invalid client authentication"))?;
        let (client_id, client_secret) = decoded
            .split_once(':')
            .ok_or_else(|| OAuthTokenError::invalid_client("Invalid client authentication"))?;
        return Ok((client_id.to_string(), Some(client_secret.to_string())));
    }

    let client_id = req
        .client_id
        .clone()
        .ok_or_else(|| OAuthTokenError::invalid_client("client_id is required"))?;
    Ok((client_id, req.client_secret.clone()))
}

fn verify_optional_client_secret(
    service: &crate::entities::services::Model,
    client_secret: Option<&str>,
) -> OAuthResult<()> {
    if let Some(secret) = client_secret {
        if !verify_client_secret(secret, &service.client_secret_hash) {
            return Err(OAuthTokenError::invalid_client(
                "Invalid client authentication",
            ));
        }
    }
    Ok(())
}

fn verify_required_client_secret(
    service: &crate::entities::services::Model,
    client_secret: Option<&str>,
) -> OAuthResult<()> {
    let Some(secret) = client_secret else {
        return Err(OAuthTokenError::invalid_client(
            "Client authentication is required",
        ));
    };
    verify_optional_client_secret(service, Some(secret))
}

fn normalize_scope(scope: Option<&str>) -> OAuthResult<Option<String>> {
    let Some(scope) = scope else {
        return Ok(None);
    };
    let scopes: Vec<&str> = scope.split_whitespace().collect();
    if scopes.is_empty() {
        return Ok(None);
    }
    if scope.len() > 2048 {
        return Err(OAuthTokenError::invalid_scope("scope is too long"));
    }
    for token in &scopes {
        if !token
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b))
        {
            return Err(OAuthTokenError::invalid_scope(
                "scope contains invalid characters",
            ));
        }
    }
    Ok(Some(scopes.join(" ")))
}

fn scope_is_subset(requested: &str, available: &str) -> bool {
    let available: std::collections::HashSet<&str> = available.split_whitespace().collect();
    requested
        .split_whitespace()
        .all(|scope| available.contains(scope))
}

fn granted_scope(
    requested: Option<&str>,
    subject_scope: Option<&str>,
) -> OAuthResult<Option<String>> {
    let requested = normalize_scope(requested)?;
    let Some(requested_scope) = requested else {
        return Ok(None);
    };
    let Some(subject_scope) = subject_scope else {
        return Err(OAuthTokenError::invalid_scope(
            "Requested scope is not allowed by the subject token",
        ));
    };
    if !scope_is_subset(&requested_scope, subject_scope) {
        return Err(OAuthTokenError::invalid_scope(
            "Requested scope exceeds the subject token scope",
        ));
    }
    Ok(Some(requested_scope))
}

fn service_matches_claims(
    service: &crate::entities::services::Model,
    service_org_slug: &str,
    org_slug: &str,
    service_slug: &str,
) -> bool {
    service.slug == service_slug
        && service_org_slug == org_slug
        && service
            .resource_uris
            .as_ref()
            .map(|_| true)
            .unwrap_or(false)
}

pub async fn enterprise_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(req): Form<EnterpriseTokenRequest>,
) -> std::result::Result<Response, OAuthTokenError> {
    match req.grant_type.as_str() {
        TOKEN_EXCHANGE_GRANT => issue_id_jag(state, headers, req).await,
        JWT_BEARER_GRANT => exchange_id_jag(state, headers, req).await,
        _ => Err(OAuthTokenError::invalid_request("Unsupported grant_type")),
    }
}

async fn issue_id_jag(
    state: AppState,
    headers: HeaderMap,
    req: EnterpriseTokenRequest,
) -> OAuthResult<Response> {
    if req.requested_token_type.as_deref() != Some(ID_JAG_TOKEN_TYPE) {
        return Err(OAuthTokenError::invalid_request(
            "requested_token_type must be urn:ietf:params:oauth:token-type:id-jag",
        ));
    }

    let subject_token_type = req
        .subject_token_type
        .as_deref()
        .ok_or_else(|| OAuthTokenError::invalid_request("subject_token_type is required"))?;
    if subject_token_type != ACCESS_TOKEN_TYPE {
        return Err(OAuthTokenError::invalid_request(
            "Only AuthOS access token subject tokens are supported",
        ));
    }

    let subject_token = req
        .subject_token
        .as_deref()
        .ok_or_else(|| OAuthTokenError::invalid_request("subject_token is required"))?;
    let resource = req
        .resource
        .as_deref()
        .ok_or_else(|| OAuthTokenError::invalid_request("resource is required"))?;
    let audience = normalize_issuer(
        req.audience
            .as_deref()
            .ok_or_else(|| OAuthTokenError::invalid_request("audience is required"))?,
    );
    if audience != normalize_issuer(&state.base_url) {
        return Err(OAuthTokenError::invalid_grant(
            "audience must match this AuthOS authorization server",
        ));
    }

    let (client_id, client_secret) = client_credentials(&headers, &req)?;
    let service = ServiceStore::find_by_client_id(DB::Conn(&state.db), &client_id)
        .await?
        .ok_or_else(|| OAuthTokenError::invalid_client("Invalid client authentication"))?;
    verify_optional_client_secret(&service, client_secret.as_deref())?;

    validate_requested_resource(Some(resource), service.resource_uris.as_deref())?;
    let service_org = OrganizationStore::find_by_id(DB::Conn(&state.db), &service.org_id)
        .await?
        .ok_or_else(|| OAuthTokenError::invalid_client("Unknown client organization"))?;
    if service_org.status != "active" {
        return Err(OAuthTokenError::invalid_grant(
            "Client organization is not active",
        ));
    }

    let claims = state
        .jwt_service
        .validate_token_for_audience(subject_token, resource)?;
    let token_hash = JwtService::hash_token(subject_token);
    let session = SessionStore::find_valid_by_token_hash(DB::Conn(&state.db), &token_hash).await?;
    if session.is_none() {
        return Err(OAuthTokenError::invalid_grant(
            "subject_token session is revoked or expired",
        ));
    }

    if !service_matches_claims(
        &service,
        &service_org.slug,
        claims.org.as_deref().unwrap_or_default(),
        claims.service.as_deref().unwrap_or_default(),
    ) {
        return Err(OAuthTokenError::invalid_grant(
            "subject_token is not scoped to this client",
        ));
    }
    if claims
        .aud
        .as_deref()
        .is_some_and(|subject_resource| subject_resource != resource)
    {
        return Err(OAuthTokenError::invalid_grant(
            "subject_token is not scoped to the requested resource",
        ));
    }

    let scope = granted_scope(req.scope.as_deref(), claims.scope.as_deref())?;
    OAuthAuthorizationGrantStore::delete_expired(DB::Conn(&state.db)).await?;
    let id_jag = state.jwt_service.create_id_jag(
        &claims.sub,
        Some(&claims.email),
        &state.base_url,
        resource,
        &client_id,
        scope.as_deref(),
    )?;
    let id_jag_hash = JwtService::hash_token(&id_jag);
    OAuthAuthorizationGrantStore::create(
        DB::Conn(&state.db),
        &id_jag_hash,
        &claims.sub,
        &service.id,
        &client_id,
        resource,
        scope.as_deref(),
        (Utc::now() + chrono::Duration::minutes(5)).naive_utc(),
    )
    .await?;

    Ok(token_response(EnterpriseTokenResponse {
        issued_token_type: Some(ID_JAG_TOKEN_TYPE.to_string()),
        access_token: id_jag,
        token_type: "N_A".to_string(),
        expires_in: 300,
        scope,
    }))
}

async fn exchange_id_jag(
    state: AppState,
    headers: HeaderMap,
    req: EnterpriseTokenRequest,
) -> OAuthResult<Response> {
    let assertion = req
        .assertion
        .as_deref()
        .ok_or_else(|| OAuthTokenError::invalid_request("assertion is required"))?;
    let (client_id, client_secret) = client_credentials(&headers, &req)?;
    let service = ServiceStore::find_by_client_id(DB::Conn(&state.db), &client_id)
        .await?
        .ok_or_else(|| OAuthTokenError::invalid_client("Invalid client authentication"))?;
    verify_required_client_secret(&service, client_secret.as_deref())?;

    let id_jag = state
        .jwt_service
        .validate_id_jag(assertion, &state.base_url)?;
    if id_jag.client_id != client_id {
        return Err(OAuthTokenError::invalid_grant(
            "assertion client_id does not match authenticated client",
        ));
    }

    validate_requested_resource(Some(&id_jag.resource), service.resource_uris.as_deref())?;

    let user = UserStore::find_by_id(DB::Conn(&state.db), &id_jag.sub)
        .await?
        .ok_or_else(|| OAuthTokenError::invalid_grant("Unknown assertion subject"))?;
    let org = OrganizationStore::find_by_id(DB::Conn(&state.db), &service.org_id)
        .await?
        .ok_or_else(|| OAuthTokenError::invalid_grant("Unknown service organization"))?;
    if org.status != "active" {
        return Err(OAuthTokenError::invalid_grant(
            "Service organization is not active",
        ));
    }

    let assertion_hash = JwtService::hash_token(assertion);
    if !OAuthAuthorizationGrantStore::consume_valid_by_token_hash(
        DB::Conn(&state.db),
        &assertion_hash,
    )
    .await?
    {
        return Err(OAuthTokenError::invalid_grant(
            "assertion has already been used or expired",
        ));
    }

    let access_token = state.jwt_service.create_token_with_resource_and_scope(
        &user.id,
        &user.email,
        user.is_platform_owner,
        Some(&org.slug),
        Some(&service.slug),
        Some(&id_jag.resource),
        id_jag.scope.as_deref(),
    )?;

    let token_hash = JwtService::hash_token(&access_token);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(state.config.jwt_expiration_hours);
    SessionStore::create(
        DB::Conn(&state.db),
        &user.id,
        &token_hash,
        expires_at.naive_utc(),
        None,
        None,
        Some(&org.slug),
        Some(&service.id),
        Some(&id_jag.resource),
        None,
        None,
    )
    .await?;

    Ok(token_response(EnterpriseTokenResponse {
        issued_token_type: None,
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.jwt_expiration_hours * 3600,
        scope: id_jag.scope,
    }))
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
        memberships::MembershipStore,
        organizations::OrganizationStore,
        services::ServiceStore,
        users::{UserCreationOptions, UserStore},
    };
    use crate::utils::client_secret::hash_client_secret;
    use axum::body::to_bytes;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use crate::rsa_keys::GeneratedKey;
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

    async fn response_json(response: Response) -> serde_json::Value {
        let body = to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("read response body");
        serde_json::from_slice(&body).expect("parse response json")
    }

    #[tokio::test]
    async fn token_exchange_and_jwt_bearer_flow_is_end_to_end() {
        let state = setup_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "mcp-user@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0;
        let org = OrganizationStore::create(DB::Conn(&state.db), "acme", "Acme", &user.id, None)
            .await
            .expect("create org");
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .expect("activate org");
        MembershipStore::create(DB::Conn(&state.db), &org.id, &user.id, "owner")
            .await
            .expect("create membership");

        let resource = "https://api.acme.example/mcp";
        let resource_uris = serde_json::to_string(&vec![resource]).unwrap();
        let client_secret = "client-secret";
        let service = ServiceStore::create_with_options(
            DB::Conn(&state.db),
            "service-id",
            &org.id,
            "mcp-server",
            "MCP Server",
            "api",
            "client-id",
            &hash_client_secret(client_secret),
            None,
            None,
            None,
            None,
            None,
            Some(&resource_uris),
        )
        .await
        .expect("create service");

        let subject_token = state
            .jwt_service
            .create_token_with_resource(
                &user.id,
                &user.email,
                user.is_platform_owner,
                Some("acme"),
                Some("mcp-server"),
                Some(resource),
            )
            .expect("create subject token");
        let token_hash = JwtService::hash_token(&subject_token);
        let expires_at = (Utc::now() + chrono::Duration::hours(1)).naive_utc();
        SessionStore::create(
            DB::Conn(&state.db),
            &user.id,
            &token_hash,
            expires_at,
            None,
            None,
            Some("acme"),
            Some(&service.id),
            Some(resource),
            None,
            None,
        )
        .await
        .expect("create subject session");

        let id_jag_response = enterprise_token(
            State(state.clone()),
            HeaderMap::new(),
            Form(EnterpriseTokenRequest {
                grant_type: TOKEN_EXCHANGE_GRANT.to_string(),
                requested_token_type: Some(ID_JAG_TOKEN_TYPE.to_string()),
                audience: Some(state.base_url.clone()),
                resource: Some(resource.to_string()),
                scope: None,
                subject_token: Some(subject_token),
                subject_token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
                assertion: None,
                client_id: Some("client-id".to_string()),
                client_secret: None,
            }),
        )
        .await
        .expect("issue id-jag");
        let id_jag_json = response_json(id_jag_response).await;
        assert_eq!(id_jag_json["issued_token_type"], ID_JAG_TOKEN_TYPE);
        assert_eq!(id_jag_json["token_type"], "N_A");
        let id_jag = id_jag_json["access_token"].as_str().unwrap();
        let id_jag_claims = state
            .jwt_service
            .validate_id_jag(id_jag, &state.base_url)
            .expect("validate id-jag");
        assert_eq!(id_jag_claims.resource, resource);
        assert_eq!(id_jag_claims.client_id, "client-id");

        let bearer_response = enterprise_token(
            State(state.clone()),
            HeaderMap::new(),
            Form(EnterpriseTokenRequest {
                grant_type: JWT_BEARER_GRANT.to_string(),
                requested_token_type: None,
                audience: None,
                resource: None,
                scope: None,
                subject_token: None,
                subject_token_type: None,
                assertion: Some(id_jag.to_string()),
                client_id: Some("client-id".to_string()),
                client_secret: Some(client_secret.to_string()),
            }),
        )
        .await
        .expect("exchange id-jag");
        let bearer_json = response_json(bearer_response).await;
        assert_eq!(bearer_json["token_type"], "Bearer");
        assert!(bearer_json.get("scope").is_none());
        let access_token = bearer_json["access_token"].as_str().unwrap();
        let access_claims = state
            .jwt_service
            .validate_token_for_audience(access_token, resource)
            .expect("validate access token");
        assert_eq!(access_claims.sub, user.id);
        assert_eq!(access_claims.aud.as_deref(), Some(resource));
        assert_eq!(access_claims.scope.as_deref(), None);

        let session = SessionStore::find_valid_by_token_hash(
            DB::Conn(&state.db),
            &JwtService::hash_token(access_token),
        )
        .await
        .expect("lookup access session");
        assert!(session.is_some());

        let replay_error = enterprise_token(
            State(state.clone()),
            HeaderMap::new(),
            Form(EnterpriseTokenRequest {
                grant_type: JWT_BEARER_GRANT.to_string(),
                requested_token_type: None,
                audience: None,
                resource: None,
                scope: None,
                subject_token: None,
                subject_token_type: None,
                assertion: Some(id_jag.to_string()),
                client_id: Some("client-id".to_string()),
                client_secret: Some(client_secret.to_string()),
            }),
        )
        .await
        .expect_err("id-jag replay should fail");
        assert_eq!(replay_error.error, "invalid_grant");
    }

    #[tokio::test]
    async fn token_exchange_rejects_scope_escalation() {
        let state = setup_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "scope-user@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0;
        let org = OrganizationStore::create(DB::Conn(&state.db), "acme", "Acme", &user.id, None)
            .await
            .expect("create org");
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .expect("activate org");
        MembershipStore::create(DB::Conn(&state.db), &org.id, &user.id, "owner")
            .await
            .expect("create membership");

        let resource = "https://api.acme.example/mcp";
        let resource_uris = serde_json::to_string(&vec![resource]).unwrap();
        let service = ServiceStore::create_with_options(
            DB::Conn(&state.db),
            "service-id",
            &org.id,
            "mcp-server",
            "MCP Server",
            "api",
            "client-id",
            &hash_client_secret("client-secret"),
            None,
            None,
            None,
            None,
            None,
            Some(&resource_uris),
        )
        .await
        .expect("create service");
        let subject_token = state
            .jwt_service
            .create_token_with_resource(
                &user.id,
                &user.email,
                user.is_platform_owner,
                Some("acme"),
                Some("mcp-server"),
                Some(resource),
            )
            .expect("create subject token");
        SessionStore::create(
            DB::Conn(&state.db),
            &user.id,
            &JwtService::hash_token(&subject_token),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            Some("acme"),
            Some(&service.id),
            Some(resource),
            None,
            None,
        )
        .await
        .expect("create subject session");

        let error = enterprise_token(
            State(state.clone()),
            HeaderMap::new(),
            Form(EnterpriseTokenRequest {
                grant_type: TOKEN_EXCHANGE_GRANT.to_string(),
                requested_token_type: Some(ID_JAG_TOKEN_TYPE.to_string()),
                audience: Some(state.base_url.clone()),
                resource: Some(resource.to_string()),
                scope: Some("mcp.admin".to_string()),
                subject_token: Some(subject_token),
                subject_token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
                assertion: None,
                client_id: Some("client-id".to_string()),
                client_secret: None,
            }),
        )
        .await
        .expect_err("scope escalation should fail");
        assert_eq!(error.error, "invalid_scope");
    }

    #[tokio::test]
    async fn token_exchange_rejects_resource_escalation() {
        let state = setup_state().await;
        let user = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "resource-user@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user")
        .0;
        let org = OrganizationStore::create(DB::Conn(&state.db), "acme", "Acme", &user.id, None)
            .await
            .expect("create org");
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .expect("activate org");
        MembershipStore::create(DB::Conn(&state.db), &org.id, &user.id, "owner")
            .await
            .expect("create membership");

        let resource_a = "https://api.acme.example/mcp";
        let resource_b = "https://api.acme.example/files";
        let resource_uris = serde_json::to_string(&vec![resource_a, resource_b]).unwrap();
        let service = ServiceStore::create_with_options(
            DB::Conn(&state.db),
            "service-id",
            &org.id,
            "mcp-server",
            "MCP Server",
            "api",
            "client-id",
            &hash_client_secret("client-secret"),
            None,
            None,
            None,
            None,
            None,
            Some(&resource_uris),
        )
        .await
        .expect("create service");
        let subject_token = state
            .jwt_service
            .create_token_with_resource(
                &user.id,
                &user.email,
                user.is_platform_owner,
                Some("acme"),
                Some("mcp-server"),
                Some(resource_a),
            )
            .expect("create subject token");
        SessionStore::create(
            DB::Conn(&state.db),
            &user.id,
            &JwtService::hash_token(&subject_token),
            (Utc::now() + chrono::Duration::hours(1)).naive_utc(),
            None,
            None,
            Some("acme"),
            Some(&service.id),
            Some(resource_a),
            None,
            None,
        )
        .await
        .expect("create subject session");

        let error = enterprise_token(
            State(state.clone()),
            HeaderMap::new(),
            Form(EnterpriseTokenRequest {
                grant_type: TOKEN_EXCHANGE_GRANT.to_string(),
                requested_token_type: Some(ID_JAG_TOKEN_TYPE.to_string()),
                audience: Some(state.base_url.clone()),
                resource: Some(resource_b.to_string()),
                scope: None,
                subject_token: Some(subject_token),
                subject_token_type: Some(ACCESS_TOKEN_TYPE.to_string()),
                assertion: None,
                client_id: Some("client-id".to_string()),
                client_secret: None,
            }),
        )
        .await
        .expect_err("resource escalation should fail");
        assert_eq!(error.error, "invalid_grant");
    }

    #[tokio::test]
    async fn id_jag_exchange_requires_client_secret() {
        let state = setup_state().await;
        let resource = "https://api.acme.example/mcp";
        let resource_uris = serde_json::to_string(&vec![resource]).unwrap();
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&state.db),
            "owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let org = OrganizationStore::create(DB::Conn(&state.db), "acme", "Acme", &owner.id, None)
            .await
            .expect("create org");
        OrganizationStore::update_status(DB::Conn(&state.db), &org.id, "active")
            .await
            .expect("activate org");
        ServiceStore::create_with_options(
            DB::Conn(&state.db),
            "service-id",
            &org.id,
            "mcp-server",
            "MCP Server",
            "api",
            "client-id",
            &hash_client_secret("client-secret"),
            None,
            None,
            None,
            None,
            None,
            Some(&resource_uris),
        )
        .await
        .expect("create service");
        let assertion = state
            .jwt_service
            .create_id_jag(
                "user-id",
                Some("mcp-user@example.com"),
                &state.base_url,
                resource,
                "client-id",
                None,
            )
            .expect("create id-jag");

        let error = enterprise_token(
            State(state),
            HeaderMap::new(),
            Form(EnterpriseTokenRequest {
                grant_type: JWT_BEARER_GRANT.to_string(),
                requested_token_type: None,
                audience: None,
                resource: None,
                scope: None,
                subject_token: None,
                subject_token_type: None,
                assertion: Some(assertion),
                client_id: Some("client-id".to_string()),
                client_secret: None,
            }),
        )
        .await
        .expect_err("missing client secret should fail");
        assert_eq!(error.error, "invalid_client");
    }
}
