use crate::auth::sso::Provider;
use crate::error::{AppError, Result};
use crate::handlers::auth::{
    get_authorization_url_for_client, is_supported_upstream_oauth_type,
    resolve_upstream_oidc_config,
};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::state::AppState;
use crate::store::{
    DB, connected_accounts::ConnectedAccountStore, identities::IdentityStore,
    oauth_states::OAuthStateStore,
    organization_oauth_credentials::OrganizationOAuthCredentialsStore,
    organizations::OrganizationStore, provider_token_requests::ProviderTokenRequestStore,
    service_provider_grants::ServiceProviderGrantStore, services::ServiceStore,
    upstream_providers::UpstreamProviderStore,
};
use crate::utils::scopes::{parse_optional_scopes, parse_required_scopes};
use axum::{
    Json,
    extract::{Path, Query, State},
    response::Redirect,
};
use chrono::{DateTime, Utc};
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl, basic::BasicClient};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::Url;

#[derive(Debug, Serialize)]
pub struct ProviderDefinition {
    pub provider: String,
    pub display_name: String,
    pub provider_type: String,
    pub scopes: Vec<String>,
    pub connect_supported: bool,
}

#[derive(Debug, Serialize)]
pub struct LinkedAccountGrantResponse {
    pub id: String,
    pub service_id: String,
    pub scopes: Vec<String>,
    pub granted_at: String,
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LinkedAccountResponse {
    pub id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub status: String,
    pub grants: Vec<LinkedAccountGrantResponse>,
}

#[derive(Debug, Serialize)]
pub struct LinkedAccountsResponse {
    pub accounts: Vec<LinkedAccountResponse>,
    pub available_providers: Vec<ProviderDefinition>,
}

#[derive(Debug, Deserialize)]
pub struct GrantLinkedAccountRequest {
    pub service_id: Option<String>,
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ProviderTokenRequestResponse {
    pub state: String,
    pub provider: String,
    pub requested_scopes: Vec<String>,
    pub service_id: String,
    pub service_name: String,
    pub expires_at: String,
    pub accounts: Vec<LinkedAccountResponse>,
}

#[derive(Debug, Deserialize)]
pub struct CompleteProviderTokenRequest {
    pub connected_account_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CompleteProviderTokenResponse {
    pub redirect_url: String,
}

fn parse_scopes(scopes_json: &Option<String>) -> Vec<String> {
    parse_optional_scopes(scopes_json)
}

fn parse_scopes_required(scopes_json: &str) -> Vec<String> {
    parse_required_scopes(scopes_json)
}

fn has_all_scopes(available: &[String], requested: &[String]) -> bool {
    requested.iter().all(|scope| {
        available
            .iter()
            .any(|available_scope| available_scope == scope)
    })
}

fn missing_scopes(available: &[String], requested: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|scope| {
            !available
                .iter()
                .any(|available_scope| available_scope == *scope)
        })
        .cloned()
        .collect()
}

fn build_link_redirect_uri(base_redirect: &str, provider: &str) -> Result<String> {
    let mut redirect_url = Url::parse(base_redirect)
        .map_err(|_| AppError::BadRequest("Invalid redirect_uri".to_string()))?;

    redirect_url
        .query_pairs_mut()
        .append_pair("status", "success")
        .append_pair("provider", provider)
        .append_pair("action", "link");

    Ok(redirect_url.to_string())
}

fn choose_service_redirect_uri(
    service: &crate::entities::services::Model,
    requested_redirect_uri: Option<&str>,
) -> Result<String> {
    let redirect_uris = service
        .redirect_uris
        .as_ref()
        .and_then(|uris| serde_json::from_str::<Vec<String>>(uris).ok())
        .unwrap_or_default();

    if let Some(redirect_uri) = requested_redirect_uri {
        if redirect_uris.is_empty() {
            return Err(AppError::BadRequest(
                "No redirect URIs are registered for this service".to_string(),
            ));
        }

        if !redirect_uris
            .iter()
            .any(|allowed_uri| allowed_uri == redirect_uri)
        {
            return Err(AppError::BadRequest(format!(
                "redirect_uri '{}' is not registered for this service",
                redirect_uri
            )));
        }
        return Ok(redirect_uri.to_string());
    }

    redirect_uris.first().cloned().ok_or_else(|| {
        AppError::InternalServerError("Service has no redirect_uris configured".to_string())
    })
}

async fn current_service_from_claims(
    state: &AppState,
    auth_user: &AuthUser,
) -> Result<Option<crate::entities::services::Model>> {
    let Some(org_slug) = auth_user.claims.org.as_deref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let Some(service_slug) = auth_user
        .claims
        .service
        .as_deref()
        .filter(|s| !s.is_empty())
    else {
        return Ok(None);
    };
    if org_slug == "platform" && service_slug == "admin-cli" {
        return Ok(None);
    }

    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, service_slug).await
}

async fn resolve_grant_service(
    state: &AppState,
    auth_user: &AuthUser,
    service_id: Option<&str>,
) -> Result<crate::entities::services::Model> {
    if let Some(current_service) = current_service_from_claims(state, auth_user).await? {
        return Ok(current_service);
    }

    let service_id =
        service_id.ok_or_else(|| AppError::BadRequest("service_id is required".to_string()))?;
    ServiceStore::find_by_id(DB::Conn(&state.db), service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))
}

async fn ensure_user_belongs_to_service(
    state: &AppState,
    user_id: &str,
    service_id: &str,
) -> Result<()> {
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    let has_authenticated = IdentityStore::user_has_authenticated_with_service(
        DB::Conn(&state.db),
        user_id,
        service_id,
    )
    .await?;
    if !has_authenticated {
        return Err(AppError::Forbidden(
            "User has not authenticated with this service".to_string(),
        ));
    }

    let user = crate::store::users::UserStore::find_by_id(DB::Conn(&state.db), user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;
    if user.org_id.as_deref() != Some(service.org_id.as_str()) {
        return Err(AppError::Forbidden(
            "User has not authenticated with this service".to_string(),
        ));
    }

    Ok(())
}

fn built_in_service_scopes(
    service: &crate::entities::services::Model,
    provider: &str,
) -> Option<Vec<String>> {
    match provider {
        "github" => Some(parse_scopes(&service.github_scopes)),
        "google" => Some(parse_scopes(&service.google_scopes)),
        "microsoft" => Some(parse_scopes(&service.microsoft_scopes)),
        _ => None,
    }
}

async fn service_allowed_scopes(
    state: &AppState,
    service: &crate::entities::services::Model,
    provider: &str,
) -> Result<Vec<String>> {
    if let Some(scopes) = built_in_service_scopes(service, provider) {
        return Ok(scopes);
    }

    let upstream = UpstreamProviderStore::find_by_connection_id(
        DB::Conn(&state.db),
        &service.org_id,
        provider,
    )
    .await?;
    if let Some(upstream) = upstream.filter(|provider| provider.enabled) {
        return Ok(parse_scopes(&upstream.scopes));
    }

    Err(AppError::BadRequest(
        "Provider is not configured for this service".to_string(),
    ))
}

fn default_provider_scopes(provider: &str) -> Vec<String> {
    match provider {
        "github" => vec!["user:email".to_string()],
        "microsoft" => vec![
            "openid".to_string(),
            "profile".to_string(),
            "email".to_string(),
            "offline_access".to_string(),
            "User.Read".to_string(),
        ],
        "google" => vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        _ => vec![],
    }
}

fn built_in_provider_from_key(provider: &str) -> Option<Provider> {
    match provider.to_ascii_lowercase().as_str() {
        "github" => Some(Provider::Github),
        "google" => Some(Provider::Google),
        "microsoft" => Some(Provider::Microsoft),
        _ => None,
    }
}

async fn build_upstream_oauth_client(
    state: &AppState,
    provider: &crate::entities::upstream_providers::Model,
) -> Result<BasicClient> {
    if !provider.enabled {
        return Err(AppError::BadRequest(
            "Upstream provider is disabled".to_string(),
        ));
    }
    if !is_supported_upstream_oauth_type(&provider.provider_type) {
        return Err(AppError::BadRequest(format!(
            "Provider type '{}' cannot be linked as an OAuth connected account",
            provider.provider_type
        )));
    }

    let oidc_config = resolve_upstream_oidc_config(provider).await?;
    let encryption = state
        .encryption
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("Encryption unavailable".to_string()))?;
    let secret = encryption
        .decrypt(&provider.client_secret_encrypted)
        .map_err(|e| AppError::InternalServerError(format!("Failed to decrypt secret: {}", e)))?;

    Ok(BasicClient::new(
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(secret)),
        AuthUrl::new(oidc_config.authorization_url).map_err(|e| AppError::OAuth(e.to_string()))?,
        Some(TokenUrl::new(oidc_config.token_url).map_err(|e| AppError::OAuth(e.to_string()))?),
    )
    .set_redirect_uri(
        RedirectUrl::new(format!("{}/auth/oidc/callback", state.base_url))
            .map_err(|e| AppError::OAuth(e.to_string()))?,
    ))
}

async fn provider_registry(
    state: &AppState,
    service: Option<&crate::entities::services::Model>,
) -> Result<Vec<ProviderDefinition>> {
    let mut providers = vec![
        ProviderDefinition {
            provider: "github".to_string(),
            display_name: "GitHub".to_string(),
            provider_type: "oauth2".to_string(),
            scopes: service
                .and_then(|service| built_in_service_scopes(service, "github"))
                .filter(|scopes| !scopes.is_empty())
                .unwrap_or_else(|| default_provider_scopes("github")),
            connect_supported: true,
        },
        ProviderDefinition {
            provider: "google".to_string(),
            display_name: "Google".to_string(),
            provider_type: "oauth2".to_string(),
            scopes: service
                .and_then(|service| built_in_service_scopes(service, "google"))
                .filter(|scopes| !scopes.is_empty())
                .unwrap_or_else(|| default_provider_scopes("google")),
            connect_supported: true,
        },
        ProviderDefinition {
            provider: "microsoft".to_string(),
            display_name: "Microsoft".to_string(),
            provider_type: "oauth2".to_string(),
            scopes: service
                .and_then(|service| built_in_service_scopes(service, "microsoft"))
                .filter(|scopes| !scopes.is_empty())
                .unwrap_or_else(|| default_provider_scopes("microsoft")),
            connect_supported: true,
        },
    ];

    if let Some(service) = service {
        for upstream in UpstreamProviderStore::find_by_org(DB::Conn(&state.db), &service.org_id)
            .await?
            .into_iter()
            .filter(|provider| provider.enabled)
        {
            providers.push(ProviderDefinition {
                provider: upstream.connection_id,
                display_name: upstream.name,
                connect_supported: is_supported_upstream_oauth_type(&upstream.provider_type),
                provider_type: upstream.provider_type,
                scopes: parse_scopes(&upstream.scopes),
            });
        }
    }

    Ok(providers)
}

async fn account_response(
    state: &AppState,
    account: crate::entities::connected_accounts::Model,
    service_id: Option<&str>,
) -> Result<LinkedAccountResponse> {
    let grants = if let Some(service_id) = service_id {
        ServiceProviderGrantStore::find_active(
            DB::Conn(&state.db),
            &account.user_id,
            service_id,
            &account.id,
        )
        .await?
        .into_iter()
        .collect::<Vec<_>>()
    } else {
        vec![]
    };

    Ok(LinkedAccountResponse {
        id: account.id,
        provider: account.provider,
        provider_user_id: account.provider_user_id,
        email: account.email,
        display_name: account.display_name,
        scopes: parse_scopes(&account.scopes),
        expires_at: account
            .expires_at
            .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
        status: account.status,
        grants: grants
            .into_iter()
            .map(|grant| LinkedAccountGrantResponse {
                id: grant.id,
                service_id: grant.service_id,
                scopes: parse_scopes_required(&grant.scopes),
                granted_at: DateTime::<Utc>::from_naive_utc_and_offset(grant.granted_at, Utc)
                    .to_rfc3339(),
                last_used_at: grant
                    .last_used_at
                    .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
            })
            .collect(),
    })
}

pub async fn list_linked_accounts(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<LinkedAccountsResponse>> {
    let service = current_service_from_claims(&state, &auth_user).await?;
    let service_id = service.as_ref().map(|service| service.id.as_str());
    let accounts =
        ConnectedAccountStore::list_by_user(DB::Conn(&state.db), &auth_user.user.id).await?;

    let mut responses = Vec::with_capacity(accounts.len());
    for account in accounts {
        responses.push(account_response(&state, account, service_id).await?);
    }

    Ok(Json(LinkedAccountsResponse {
        accounts: responses,
        available_providers: provider_registry(&state, service.as_ref()).await?,
    }))
}

pub async fn start_linked_account(
    State(state): State<AppState>,
    Path(provider_key): Path<String>,
    Query(query): Query<crate::handlers::identities::StartLinkQuery>,
    auth_user: AuthUser,
) -> Result<Json<crate::handlers::identities::StartLinkResponse>> {
    let service = current_service_from_claims(&state, &auth_user).await?;
    let (
        authorization_url,
        csrf_token,
        pkce_verifier,
        service_id,
        org_slug,
        service_slug,
        redirect_uri,
        upstream_connection_id,
        is_admin_flow,
        scopes,
    ) = if let Some(service) = service {
        let org = OrganizationStore::find_by_id(DB::Conn(&state.db), &service.org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
        let base_redirect = choose_service_redirect_uri(&service, query.redirect_uri.as_deref())?;

        if let Some(provider) = built_in_provider_from_key(&provider_key) {
            let mut scopes = service_allowed_scopes(&state, &service, provider.as_str()).await?;
            if scopes.is_empty() {
                scopes = default_provider_scopes(provider.as_str());
            }
            let redirect_uri = build_link_redirect_uri(&base_redirect, provider.as_str())?;
            let callback_url = format!(
                "{}/auth/admin/{}/callback",
                state.base_url,
                provider.as_str()
            );
            let org_credentials = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
                DB::Conn(&state.db),
                &service.org_id,
                provider.as_str(),
            )
            .await?;
            let (authorization_url, csrf_token, pkce_verifier) = if org_credentials.is_some() {
                let encryption = state.encryption.as_ref().ok_or_else(|| {
                    AppError::InternalServerError("Encryption service unavailable".to_string())
                })?;
                let custom_client = OrganizationStore::get_oauth_client_for_org(
                    DB::Conn(&state.db),
                    &service.org_id,
                    provider,
                    encryption,
                )
                .await?;
                get_authorization_url_for_client(&custom_client, provider, scopes.clone())
            } else {
                state.oauth_client.get_authorization_url_with_pkce(
                    provider,
                    scopes.clone(),
                    Some(&callback_url),
                )?
            };

            (
                authorization_url,
                csrf_token,
                pkce_verifier,
                Some(service.id),
                Some(org.slug),
                Some(service.slug),
                redirect_uri,
                None,
                false,
                scopes,
            )
        } else {
            let upstream = UpstreamProviderStore::find_by_connection_id(
                DB::Conn(&state.db),
                &service.org_id,
                &provider_key,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;
            let mut scopes = parse_scopes(&upstream.scopes);
            if scopes.is_empty() {
                scopes = default_provider_scopes("oidc");
            }
            let client = build_upstream_oauth_client(&state, &upstream).await?;
            let (authorization_url, csrf_token, pkce_verifier) =
                get_authorization_url_for_client(&client, Provider::Oidc, scopes.clone());
            let redirect_uri = build_link_redirect_uri(&base_redirect, &provider_key)?;

            (
                authorization_url,
                csrf_token,
                pkce_verifier,
                Some(service.id),
                Some(org.slug),
                Some(service.slug),
                redirect_uri,
                Some(provider_key),
                false,
                scopes,
            )
        }
    } else {
        let provider = built_in_provider_from_key(&provider_key).ok_or_else(|| {
            AppError::BadRequest("Custom provider linking requires service context".to_string())
        })?;
        let scopes = default_provider_scopes(provider.as_str());
        let callback_url = format!(
            "{}/auth/admin/{}/callback",
            state.base_url,
            provider.as_str()
        );
        let (authorization_url, csrf_token, pkce_verifier) = state
            .oauth_client
            .get_authorization_url_with_pkce(provider, scopes.clone(), Some(&callback_url))?;
        let redirect_base = format!(
            "{}/settings/connections",
            state.web_client_url.trim_end_matches('/')
        );
        let redirect_uri = build_link_redirect_uri(&redirect_base, provider.as_str())?;

        (
            authorization_url,
            csrf_token,
            pkce_verifier,
            None,
            None,
            None,
            redirect_uri,
            None,
            true,
            scopes,
        )
    };

    let expires_at = (Utc::now() + chrono::Duration::minutes(10)).naive_utc();
    let pkce_value = if pkce_verifier.is_empty() {
        None
    } else {
        Some(pkce_verifier.as_str())
    };
    OAuthStateStore::create(
        DB::Conn(&state.db),
        csrf_token.secret(),
        pkce_value,
        service_id.as_deref(),
        Some(&redirect_uri),
        org_slug.as_deref(),
        service_slug.as_deref(),
        is_admin_flow,
        Some(&auth_user.user.id),
        None,
        None,
        upstream_connection_id.as_deref(),
        Some(&scopes),
        None,
        &expires_at,
    )
    .await?;

    Ok(Json(crate::handlers::identities::StartLinkResponse {
        authorization_url,
    }))
}

pub async fn grant_linked_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    auth_user: AuthUser,
    Json(req): Json<GrantLinkedAccountRequest>,
) -> Result<Json<LinkedAccountGrantResponse>> {
    let account = ConnectedAccountStore::find_active_by_id_for_user(
        DB::Conn(&state.db),
        &account_id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?;
    let service = resolve_grant_service(&state, &auth_user, req.service_id.as_deref()).await?;
    ensure_user_belongs_to_service(&state, &auth_user.user.id, &service.id).await?;

    let allowed_scopes = service_allowed_scopes(&state, &service, &account.provider).await?;
    let requested_scopes = if req.scopes.is_empty() {
        allowed_scopes.clone()
    } else {
        req.scopes
    };
    let missing_from_service = missing_scopes(&allowed_scopes, &requested_scopes);
    if !missing_from_service.is_empty() {
        return Err(AppError::Forbidden(format!(
            "Requested scopes are not allowed for this service: {}",
            missing_from_service.join(", ")
        )));
    }

    let account_scopes = parse_scopes(&account.scopes);
    let missing_from_account = missing_scopes(&account_scopes, &requested_scopes);
    if !missing_from_account.is_empty() {
        return Err(AppError::BadRequest(format!(
            "Connected account is missing scopes and must be reauthorized: {}",
            missing_from_account.join(", ")
        )));
    }

    let grant = ServiceProviderGrantStore::upsert(
        DB::Conn(&state.db),
        &auth_user.user.id,
        &service.id,
        &account.id,
        &account.provider,
        &requested_scopes,
    )
    .await?;
    let event = OrgAuditBuilder::new(
        &service.org_id,
        Some(&auth_user.user.id),
        "provider_grant.created",
    )
    .target("connected_account", &account.id)
    .details_json(Some(json!({
        "grant_id": &grant.id,
        "service_id": &service.id,
        "provider": &account.provider,
        "scopes": &requested_scopes,
    })))
    .build();
    state.audit_actor.log_org(event).await;

    Ok(Json(LinkedAccountGrantResponse {
        id: grant.id,
        service_id: grant.service_id,
        scopes: parse_scopes_required(&grant.scopes),
        granted_at: DateTime::<Utc>::from_naive_utc_and_offset(grant.granted_at, Utc).to_rfc3339(),
        last_used_at: None,
    }))
}

pub async fn revoke_linked_account_grant(
    State(state): State<AppState>,
    Path((account_id, service_id)): Path<(String, String)>,
    auth_user: AuthUser,
) -> Result<axum::http::StatusCode> {
    ConnectedAccountStore::find_active_by_id_for_user(
        DB::Conn(&state.db),
        &account_id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &service_id).await?;
    ServiceProviderGrantStore::revoke(
        DB::Conn(&state.db),
        &auth_user.user.id,
        &service_id,
        &account_id,
    )
    .await?;
    if let Some(service) = service {
        let event = OrgAuditBuilder::new(
            &service.org_id,
            Some(&auth_user.user.id),
            "provider_grant.revoked",
        )
        .target("connected_account", &account_id)
        .details_json(Some(json!({
            "service_id": service_id,
        })))
        .build();
        state.audit_actor.log_org(event).await;
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn revoke_linked_account(
    State(state): State<AppState>,
    Path(account_id): Path<String>,
    auth_user: AuthUser,
) -> Result<axum::http::StatusCode> {
    ConnectedAccountStore::revoke(DB::Conn(&state.db), &account_id, &auth_user.user.id).await?;
    Ok(axum::http::StatusCode::NO_CONTENT)
}

pub async fn get_provider_token_request(
    State(state): State<AppState>,
    Path(request_state): Path<String>,
    auth_user: AuthUser,
) -> Result<Json<ProviderTokenRequestResponse>> {
    let request = ProviderTokenRequestStore::find_active_for_user(
        DB::Conn(&state.db),
        &request_state,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &request.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    let accounts = ConnectedAccountStore::list_by_user_and_provider(
        DB::Conn(&state.db),
        &auth_user.user.id,
        &request.provider,
    )
    .await?;
    let mut account_responses = Vec::with_capacity(accounts.len());
    for account in accounts {
        account_responses.push(account_response(&state, account, Some(&service.id)).await?);
    }

    Ok(Json(ProviderTokenRequestResponse {
        state: request.state,
        provider: request.provider,
        requested_scopes: parse_scopes_required(&request.requested_scopes),
        service_id: service.id,
        service_name: service.name,
        expires_at: DateTime::<Utc>::from_naive_utc_and_offset(request.expires_at, Utc)
            .to_rfc3339(),
        accounts: account_responses,
    }))
}

pub async fn complete_provider_token_request(
    State(state): State<AppState>,
    Path(request_state): Path<String>,
    auth_user: AuthUser,
    Json(req): Json<CompleteProviderTokenRequest>,
) -> Result<Json<CompleteProviderTokenResponse>> {
    let request = ProviderTokenRequestStore::find_active_for_user(
        DB::Conn(&state.db),
        &request_state,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &request.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    ensure_user_belongs_to_service(&state, &auth_user.user.id, &request.service_id).await?;
    let requested_scopes = parse_scopes_required(&request.requested_scopes);

    let candidate_accounts = if let Some(account_id) = req.connected_account_id.as_deref() {
        vec![
            ConnectedAccountStore::find_active_by_id_for_user(
                DB::Conn(&state.db),
                account_id,
                &auth_user.user.id,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?,
        ]
    } else {
        ConnectedAccountStore::list_by_user_and_provider(
            DB::Conn(&state.db),
            &auth_user.user.id,
            &request.provider,
        )
        .await?
    };

    let account = candidate_accounts
        .into_iter()
        .find(|account| {
            account.provider == request.provider
                && has_all_scopes(&parse_scopes(&account.scopes), &requested_scopes)
        })
        .ok_or_else(|| {
            AppError::BadRequest(
                "No connected account satisfies the requested provider scopes".to_string(),
            )
        })?;

    ServiceProviderGrantStore::upsert(
        DB::Conn(&state.db),
        &auth_user.user.id,
        &request.service_id,
        &account.id,
        &request.provider,
        &requested_scopes,
    )
    .await?;
    let event = OrgAuditBuilder::new(
        &service.org_id,
        Some(&auth_user.user.id),
        "provider_grant.created",
    )
    .target("connected_account", &account.id)
    .details_json(Some(json!({
        "service_id": &request.service_id,
        "provider": &request.provider,
        "scopes": &requested_scopes,
        "provider_token_request": &request.state,
    })))
    .build();
    state.audit_actor.log_org(event).await;
    ProviderTokenRequestStore::complete(DB::Conn(&state.db), &request.state, &auth_user.user.id)
        .await?;

    let mut redirect = Url::parse(&request.redirect_uri)
        .map_err(|_| AppError::BadRequest("Invalid stored redirect_uri".to_string()))?;
    {
        let mut pairs = redirect.query_pairs_mut();
        pairs
            .append_pair("provider_grant", "success")
            .append_pair("provider", &request.provider);
        if let Some(client_state) = request.client_state.as_deref() {
            pairs.append_pair("state", client_state);
        }
    }

    Ok(Json(CompleteProviderTokenResponse {
        redirect_url: redirect.to_string(),
    }))
}

async fn create_provider_token_request_oauth_state(
    state: &AppState,
    request: &crate::entities::provider_token_requests::Model,
    linking_user_id: &str,
) -> Result<String> {
    let service = ServiceStore::find_by_id(DB::Conn(&state.db), &request.service_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;
    let org = OrganizationStore::find_by_id(DB::Conn(&state.db), &service.org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let requested_scopes = parse_scopes_required(&request.requested_scopes);
    let allowed_scopes = service_allowed_scopes(&state, &service, &request.provider).await?;
    if !has_all_scopes(&allowed_scopes, &requested_scopes) {
        return Err(AppError::Forbidden(
            "Requested scopes are not allowed for this service".to_string(),
        ));
    }

    let mut return_url = Url::parse(&format!(
        "{}/settings/connections",
        state.web_client_url.trim_end_matches('/')
    ))
    .map_err(|_| AppError::InternalServerError("Invalid dashboard URL".to_string()))?;
    return_url
        .query_pairs_mut()
        .append_pair("provider_token_request", &request.state);

    let (authorization_url, csrf_token, pkce_verifier, upstream_connection_id) =
        if let Some(provider) = built_in_provider_from_key(&request.provider) {
            let callback_url = format!(
                "{}/auth/admin/{}/callback",
                state.base_url,
                provider.as_str()
            );
            let org_credentials = OrganizationOAuthCredentialsStore::find_by_org_and_provider(
                DB::Conn(&state.db),
                &service.org_id,
                provider.as_str(),
            )
            .await?;
            let (authorization_url, csrf_token, pkce_verifier) = if org_credentials.is_some() {
                let encryption = state.encryption.as_ref().ok_or_else(|| {
                    AppError::InternalServerError("Encryption service unavailable".to_string())
                })?;
                let custom_client = OrganizationStore::get_oauth_client_for_org(
                    DB::Conn(&state.db),
                    &service.org_id,
                    provider,
                    encryption,
                )
                .await?;
                get_authorization_url_for_client(&custom_client, provider, requested_scopes.clone())
            } else {
                state.oauth_client.get_authorization_url_with_pkce(
                    provider,
                    requested_scopes.clone(),
                    Some(&callback_url),
                )?
            };
            (authorization_url, csrf_token, pkce_verifier, None)
        } else {
            let upstream = UpstreamProviderStore::find_by_connection_id(
                DB::Conn(&state.db),
                &service.org_id,
                &request.provider,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;
            let client = build_upstream_oauth_client(&state, &upstream).await?;
            let (authorization_url, csrf_token, pkce_verifier) =
                get_authorization_url_for_client(&client, Provider::Oidc, requested_scopes.clone());
            (
                authorization_url,
                csrf_token,
                pkce_verifier,
                Some(request.provider.clone()),
            )
        };

    let expires_at = (Utc::now() + chrono::Duration::minutes(10)).naive_utc();
    let pkce_value = if pkce_verifier.is_empty() {
        None
    } else {
        Some(pkce_verifier.as_str())
    };
    OAuthStateStore::create(
        DB::Conn(&state.db),
        csrf_token.secret(),
        pkce_value,
        Some(&service.id),
        Some(return_url.as_str()),
        Some(&org.slug),
        Some(&service.slug),
        false,
        Some(linking_user_id),
        None,
        None,
        upstream_connection_id.as_deref(),
        Some(&requested_scopes),
        Some(&request.state),
        &expires_at,
    )
    .await?;

    Ok(authorization_url)
}

pub async fn start_provider_token_request_reauth(
    State(state): State<AppState>,
    Path(request_state): Path<String>,
) -> Result<Redirect> {
    let request = ProviderTokenRequestStore::find_active(DB::Conn(&state.db), &request_state)
        .await?
        .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;

    // The provider-token request state is a short-lived bearer capability created
    // only after service API-key, service/user boundary, and scope checks pass.
    ensure_user_belongs_to_service(&state, &request.user_id, &request.service_id).await?;

    let authorization_url =
        create_provider_token_request_oauth_state(&state, &request, &request.user_id).await?;

    Ok(Redirect::to(&authorization_url))
}

pub async fn start_provider_token_request_link(
    State(state): State<AppState>,
    Path(request_state): Path<String>,
    auth_user: AuthUser,
) -> Result<Json<crate::handlers::identities::StartLinkResponse>> {
    let request = ProviderTokenRequestStore::find_active_for_user(
        DB::Conn(&state.db),
        &request_state,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;
    ensure_user_belongs_to_service(&state, &auth_user.user.id, &request.service_id).await?;

    let authorization_url =
        create_provider_token_request_oauth_state(&state, &request, &auth_user.user.id).await?;

    Ok(Json(crate::handlers::identities::StartLinkResponse {
        authorization_url,
    }))
}
