use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{CAP_INTEGRATIONS_MANAGE, PermissionService};
use crate::state::AppState;
use crate::store::{
    DB, organizations::OrganizationStore, upstream_providers::UpstreamProviderStore,
};
use axum::{
    Json,
    extract::{Path, State},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

async fn require_integration_manager(state: &AppState, org_id: &str, user_id: &str) -> Result<()> {
    if PermissionService::check(
        DB::Conn(&state.db),
        org_id,
        user_id,
        CAP_INTEGRATIONS_MANAGE,
    )
    .await?
    {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to manage integrations".to_string(),
    ))
}

#[derive(Debug, Deserialize)]
pub struct CreateUpstreamProviderRequest {
    pub connection_id: String,
    pub name: String,
    pub provider_type: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub issuer: Option<String>,
    pub authorization_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub discovery_url: Option<String>,
    pub scopes: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UpstreamProviderResponse {
    pub id: String,
    pub connection_id: String,
    pub name: String,
    pub provider_type: String,
    pub client_id: String,
    pub issuer: Option<String>,
    pub authorization_url: Option<String>,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<crate::db::models::UpstreamProvider> for UpstreamProviderResponse {
    fn from(m: crate::db::models::UpstreamProvider) -> Self {
        Self {
            id: m.id,
            connection_id: m.connection_id,
            name: m.name,
            provider_type: m.provider_type,
            client_id: m.client_id,
            issuer: m.issuer,
            authorization_url: m.authorization_url,
            enabled: m.enabled,
            created_at: m.created_at,
        }
    }
}

pub async fn create_upstream_provider(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(payload): Json<CreateUpstreamProviderRequest>,
) -> Result<Json<UpstreamProviderResponse>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &organization.id, &auth_user.user.id).await?;

    validate_upstream_provider_payload(&payload).await?;

    let encryption = state.encryption.as_ref().ok_or_else(|| {
        AppError::InternalServerError("Encryption service unavailable".to_string())
    })?;

    let client_secret_encrypted = if let Some(secret) = payload.client_secret {
        encryption
            .encrypt(&secret)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?
    } else {
        Vec::new()
    };

    let id = Uuid::new_v4().to_string();
    let metadata_str = payload.metadata.map(|m| m.to_string());

    let provider = UpstreamProviderStore::create(
        DB::Conn(&state.db),
        &id,
        &organization.id,
        &payload.connection_id,
        &payload.name,
        &payload.provider_type,
        &payload.client_id,
        client_secret_encrypted,
        encryption.key_id(),
        payload.authorization_url.as_deref(),
        payload.token_url.as_deref(),
        payload.userinfo_url.as_deref(),
        payload.discovery_url.as_deref(),
        payload.scopes.as_deref(),
        payload.issuer.as_deref(),
        metadata_str.as_deref(),
    )
    .await?;

    if let Some(enabled) = payload.enabled {
        UpstreamProviderStore::update(DB::Conn(&state.db), &provider.id, None, Some(enabled))
            .await?;
    }

    Ok(Json(
        crate::db::models::UpstreamProvider::from(provider).into(),
    ))
}

pub async fn list_upstream_providers(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<UpstreamProviderResponse>>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &organization.id, &auth_user.user.id).await?;

    let providers =
        UpstreamProviderStore::find_by_org(DB::Conn(&state.db), &organization.id).await?;

    let response = providers
        .into_iter()
        .map(|p| crate::db::models::UpstreamProvider::from(p).into())
        .collect();
    Ok(Json(response))
}

pub async fn delete_upstream_provider(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, provider_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &organization.id, &auth_user.user.id).await?;

    // Find provider to verify it belongs to this org
    let provider = UpstreamProviderStore::find_by_id(DB::Conn(&state.db), &provider_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Provider not found".to_string()))?;

    if provider.org_id != organization.id {
        return Err(AppError::Forbidden(
            "Provider does not belong to this organization".to_string(),
        ));
    }

    UpstreamProviderStore::delete(DB::Conn(&state.db), &provider_id).await?;

    Ok(Json(serde_json::json!({ "success": true })))
}

async fn validate_upstream_provider_payload(payload: &CreateUpstreamProviderRequest) -> Result<()> {
    match payload.provider_type.as_str() {
        "oidc" | "oauth2" => {
            let has_discovery = payload.discovery_url.is_some();

            if let Some(url) = payload.authorization_url.as_deref() {
                validate_provider_url(Some(url), "authorization_url").await?;
            }
            if let Some(url) = payload.token_url.as_deref() {
                validate_provider_url(Some(url), "token_url").await?;
            }
            if let Some(url) = payload.userinfo_url.as_deref() {
                validate_provider_url(Some(url), "userinfo_url").await?;
            }

            if !has_discovery
                && (payload.authorization_url.is_none()
                    || payload.token_url.is_none()
                    || payload.userinfo_url.is_none())
            {
                return Err(AppError::BadRequest(
                    "OAuth providers must include discovery_url or explicit authorization_url, token_url, and userinfo_url".to_string(),
                ));
            }
        }
        "saml" => {
            validate_provider_url(payload.authorization_url.as_deref(), "authorization_url")
                .await?;
        }
        _ => {
            return Err(AppError::BadRequest(
                "Invalid provider_type. Must be 'oidc', 'oauth2', or 'saml'".to_string(),
            ));
        }
    }

    if let Some(url) = payload.discovery_url.as_deref() {
        validate_provider_url(Some(url), "discovery_url").await?;
    }

    Ok(())
}

async fn validate_provider_url(url: Option<&str>, field: &str) -> Result<()> {
    let url = url.ok_or_else(|| AppError::BadRequest(format!("Missing {}", field)))?;
    let parsed = reqwest::Url::parse(url)
        .map_err(|_| AppError::BadRequest(format!("Invalid {} URL", field)))?;

    if parsed.scheme() != "https" {
        return Err(AppError::BadRequest(format!("{} must use https", field)));
    }

    crate::services::safe_http::SafeHttpClient::new()?
        .validate_external_url(url)
        .await
}
