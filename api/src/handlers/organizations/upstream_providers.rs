use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_INTEGRATIONS_MANAGE};
use crate::state::AppState;
use crate::store::{
    organizations::OrganizationStore, upstream_providers::UpstreamProviderStore, DB,
};
use axum::{
    extract::{Path, State},
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

async fn require_integration_manager(state: &AppState, org_id: &str, user_id: &str) -> Result<()> {
    crate::handlers::organizations::ensure_organization_active(&state.db, org_id).await?;
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

    let id = Uuid::new_v4().to_string();
    let client_secret_encrypted = if let Some(secret) = payload.client_secret {
        encryption
            .encrypt_with_context(
                &secret,
                crate::encryption::EncryptionContext::new(
                    "upstream_providers",
                    &id,
                    "client_secret_encrypted",
                ),
            )
            .map_err(|e| AppError::InternalServerError(e.to_string()))?
    } else {
        Vec::new()
    };

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

    if !UpstreamProviderStore::delete_in_org(DB::Conn(&state.db), &organization.id, &provider_id)
        .await?
    {
        return Err(AppError::NotFound("Provider not found".to_string()));
    }

    Ok(Json(serde_json::json!({ "success": true })))
}

async fn validate_upstream_provider_payload(payload: &CreateUpstreamProviderRequest) -> Result<()> {
    validate_upstream_client_secret(&payload.provider_type, payload.client_secret.as_deref())?;
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

fn validate_upstream_client_secret(provider_type: &str, client_secret: Option<&str>) -> Result<()> {
    if matches!(provider_type, "oidc" | "oauth2")
        && client_secret.is_none_or(|secret| secret.trim().is_empty())
    {
        return Err(AppError::BadRequest(
            "OIDC and OAuth2 upstream providers require a non-empty client_secret; public upstream clients are not supported"
                .to_string(),
        ));
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

#[cfg(test)]
mod secret_validation_tests {
    use super::*;

    #[test]
    fn only_saml_upstream_providers_may_omit_client_secret() {
        for provider_type in ["oidc", "oauth2"] {
            assert!(matches!(
                validate_upstream_client_secret(provider_type, None),
                Err(AppError::BadRequest(_))
            ));
            assert!(matches!(
                validate_upstream_client_secret(provider_type, Some("  ")),
                Err(AppError::BadRequest(_))
            ));
            validate_upstream_client_secret(provider_type, Some("confidential-secret"))
                .expect("confidential upstream client secret");
        }
        validate_upstream_client_secret("saml", None)
            .expect("SAML uses the documented empty secret sentinel");
    }
}
