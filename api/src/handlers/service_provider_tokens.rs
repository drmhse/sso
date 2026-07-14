use crate::auth::{sso::Provider, token_refresher};
use crate::entities::connected_accounts;
use crate::error::{AppError, Result};
use crate::middleware::ServicePrincipal;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::state::AppState;
use crate::store::{
    connected_accounts::ConnectedAccountStore, identities::IdentityStore,
    organization_oauth_credentials::OrganizationOAuthCredentialsStore,
    provider_token_requests::ProviderTokenRequestStore,
    service_provider_grants::ServiceProviderGrantStore, upstream_providers::UpstreamProviderStore,
    DB,
};
use crate::utils::scopes::{parse_optional_scopes, parse_required_scopes};
use axum::{extract::State, Json};
use chrono::{DateTime, Duration, Utc};
use sea_orm::TransactionTrait;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct ServiceProviderTokenRequest {
    pub user_id: String,
    pub provider: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProviderTokenAccount {
    pub id: String,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ServiceProviderTokenResponse {
    Ok {
        access_token: String,
        expires_at: Option<String>,
        scopes: Vec<String>,
        provider: String,
        account: ProviderTokenAccount,
    },
    ActionRequired {
        code: String,
        reauth_url: String,
        missing_scopes: Vec<String>,
        provider: String,
    },
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

fn extra_scopes(available: &[String], boundary: &[String]) -> Vec<String> {
    available
        .iter()
        .filter(|scope| !boundary.iter().any(|allowed_scope| allowed_scope == *scope))
        .cloned()
        .collect()
}

fn service_scope_config(
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
    if let Some(scopes) = service_scope_config(service, provider) {
        return Ok(scopes);
    }

    if let Some(upstream) =
        UpstreamProviderStore::find_by_connection_id(DB::Conn(&state.db), &service.org_id, provider)
            .await?
            .filter(|provider| provider.enabled)
    {
        return Ok(parse_scopes(&upstream.scopes));
    }

    Err(AppError::Forbidden(format!(
        "Service does not have {} scopes configured",
        provider
    )))
}

fn check_provider_token_permission(principal: &ServicePrincipal, provider: &str) -> Result<()> {
    let wildcard = "read:provider_tokens".to_string();
    let provider_specific = format!("read:provider_tokens:{}", provider);
    if principal.permissions.contains(&wildcard)
        || principal.permissions.contains(&provider_specific)
    {
        return Ok(());
    }
    Err(AppError::Forbidden(
        "Missing required permission: read:provider_tokens".to_string(),
    ))
}

fn normalize_provider_key(provider: &str) -> String {
    match provider.to_ascii_lowercase().as_str() {
        "github" => "github".to_string(),
        "google" => "google".to_string(),
        "microsoft" => "microsoft".to_string(),
        _ => provider.to_string(),
    }
}

fn validate_redirect_uri(
    redirect_uri: &str,
    service: &crate::entities::services::Model,
) -> Result<()> {
    let allowed_uris_json = service.redirect_uris.as_ref().ok_or_else(|| {
        AppError::BadRequest("No redirect URIs are registered for this service".to_string())
    })?;

    let allowed_uris: Vec<String> = serde_json::from_str(allowed_uris_json)
        .map_err(|e| AppError::InternalServerError(format!("Invalid redirect_uris JSON: {}", e)))?;

    if allowed_uris.is_empty() {
        return Err(AppError::BadRequest(
            "No redirect URIs are registered for this service".to_string(),
        ));
    }

    if !allowed_uris.iter().any(|allowed| allowed == redirect_uri) {
        return Err(AppError::BadRequest(format!(
            "redirect_uri '{}' is not registered for this service",
            redirect_uri
        )));
    }
    Ok(())
}

fn choose_redirect_uri(
    requested_redirect_uri: Option<&str>,
    service: &crate::entities::services::Model,
) -> Result<String> {
    if let Some(redirect_uri) = requested_redirect_uri {
        validate_redirect_uri(redirect_uri, service)?;
        return Ok(redirect_uri.to_string());
    }
    let allowed_uris = service
        .redirect_uris
        .as_ref()
        .and_then(|json| serde_json::from_str::<Vec<String>>(json).ok())
        .unwrap_or_default();
    allowed_uris
        .first()
        .cloned()
        .ok_or_else(|| AppError::BadRequest("redirect_uri is required".to_string()))
}

async fn action_required(
    state: &AppState,
    service: &crate::entities::services::Model,
    req: &ServiceProviderTokenRequest,
    account_id: Option<&str>,
    code: &str,
    missing_scopes: Vec<String>,
) -> Result<ServiceProviderTokenResponse> {
    let redirect_uri = choose_redirect_uri(req.redirect_uri.as_deref(), service)?;
    let token_request = ProviderTokenRequestStore::create(
        DB::Conn(&state.db),
        &req.user_id,
        &service.id,
        &req.provider,
        account_id,
        &req.scopes,
        &redirect_uri,
        req.state.as_deref(),
    )
    .await?;
    let reauth_url = Url::parse(&format!(
        "{}/connect/provider-token/{}",
        state.base_url.trim_end_matches('/'),
        token_request.state
    ))
    .map_err(|_| AppError::InternalServerError("Invalid provider-token reauth URL".to_string()))?;

    Ok(ServiceProviderTokenResponse::ActionRequired {
        code: code.to_string(),
        reauth_url: reauth_url.to_string(),
        missing_scopes,
        provider: req.provider.clone(),
    })
}

fn decrypt_token(
    encryption: Option<&crate::encryption::EncryptionService>,
    account_id: &str,
    encrypted_field: &'static str,
    plaintext: &Option<String>,
    encrypted: &Option<Vec<u8>>,
) -> Result<Option<String>> {
    if let Some(encryption) = encryption {
        if plaintext.is_some() {
            return Err(AppError::InternalServerError(
                "Connected-account token requires migration; run rewrap-secrets --apply"
                    .to_string(),
            ));
        }
        if let Some(encrypted_token) = encrypted {
            return encryption
                .decrypt_with_context(
                    encrypted_token,
                    crate::encryption::EncryptionContext::new(
                        "connected_accounts",
                        account_id,
                        encrypted_field,
                    ),
                )
                .map(Some)
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to decrypt token: {}", e))
                });
        }
        return Ok(None);
    }

    Ok(plaintext.clone())
}

async fn refresh_connected_account(
    state: &AppState,
    service: &crate::entities::services::Model,
    account: &connected_accounts::Model,
) -> Result<connected_accounts::Model> {
    let provider = Provider::from_str(&account.provider)?;
    let refresh_token = decrypt_token(
        state.encryption.as_deref(),
        &account.id,
        "refresh_token_encrypted",
        &account.refresh_token,
        &account.refresh_token_encrypted,
    )?
    .ok_or_else(|| AppError::OAuth("No refresh token available".to_string()))?;

    let (client_id, client_secret) = if let Some(creds) =
        OrganizationOAuthCredentialsStore::find_by_org_and_provider(
            DB::Conn(&state.db),
            &service.org_id,
            &account.provider,
        )
        .await?
    {
        let encryption = state.encryption.as_ref().ok_or_else(|| {
            AppError::OAuth("Encryption service unavailable for provider credentials".to_string())
        })?;
        let secret = encryption
            .decrypt_with_context(
                &creds.client_secret_encrypted,
                crate::encryption::EncryptionContext::new(
                    "organization_oauth_credentials",
                    &creds.id,
                    "client_secret_encrypted",
                ),
            )
            .map_err(|e| AppError::OAuth(format!("Failed to decrypt provider secret: {}", e)))?;
        (creds.client_id, secret)
    } else {
        match provider {
            Provider::Google => (
                state
                    .config
                    .platform_google_client_id
                    .clone()
                    .ok_or_else(|| {
                        AppError::OAuth("Google OAuth provider is not configured".to_string())
                    })?,
                state
                    .config
                    .platform_google_client_secret
                    .clone()
                    .ok_or_else(|| {
                        AppError::OAuth("Google OAuth provider is not configured".to_string())
                    })?,
            ),
            Provider::Microsoft => (
                state
                    .config
                    .platform_microsoft_client_id
                    .clone()
                    .ok_or_else(|| {
                        AppError::OAuth("Microsoft OAuth provider is not configured".to_string())
                    })?,
                state
                    .config
                    .platform_microsoft_client_secret
                    .clone()
                    .ok_or_else(|| {
                        AppError::OAuth("Microsoft OAuth provider is not configured".to_string())
                    })?,
            ),
            Provider::Github => {
                return Err(AppError::OAuth(
                    "GitHub token refresh is not supported".to_string(),
                ));
            }
            Provider::Oidc | Provider::Password => {
                return Err(AppError::OAuth(
                    "Token refresh is not supported for this provider".to_string(),
                ));
            }
        }
    };

    let refreshed = match provider {
        Provider::Microsoft => {
            token_refresher::refresh_microsoft_token(&refresh_token, &client_id, &client_secret)
                .await
                .map_err(|e| AppError::OAuth(format!("Token refresh failed: {}", e)))?
        }
        Provider::Google => token_refresher::refresh_google_token(
            &refresh_token,
            &client_id,
            &client_secret,
            state.config.platform_google_token_url.as_deref(),
        )
        .await
        .map_err(|e| AppError::OAuth(format!("Token refresh failed: {}", e)))?,
        Provider::Github | Provider::Oidc | Provider::Password => {
            return Err(AppError::OAuth(
                "Token refresh is not supported for this provider".to_string(),
            ));
        }
    };

    let transaction = state.db.begin().await?;
    let refreshed_account = ConnectedAccountStore::update_tokens(
        DB::Tx(&transaction),
        &account.id,
        &refreshed.access_token,
        refreshed
            .refresh_token
            .as_deref()
            .or(Some(refresh_token.as_str())),
        refreshed.expires_at,
        state.encryption.as_ref(),
    )
    .await?;
    let event = OrgAuditBuilder::new(&service.org_id, None, "provider_token.refreshed")
        .target("connected_account", &account.id)
        .details_json(Some(json!({
            "service_id": &service.id,
            "user_id": &account.user_id,
            "provider": &account.provider,
        })))
        .build();
    state
        .audit_actor
        .log_org_with_db(DB::Tx(&transaction), event)
        .await?;
    transaction.commit().await?;

    Ok(refreshed_account)
}

pub async fn request_service_provider_token(
    State(state): State<AppState>,
    principal: ServicePrincipal,
    Json(mut req): Json<ServiceProviderTokenRequest>,
) -> Result<Json<ServiceProviderTokenResponse>> {
    req.provider = normalize_provider_key(&req.provider);
    check_provider_token_permission(&principal, &req.provider)?;

    let service = principal.service.clone();
    let has_authenticated = IdentityStore::user_has_authenticated_with_org_service(
        DB::Conn(&state.db),
        &req.user_id,
        &service.org_id,
        &service.id,
    )
    .await?;
    if !has_authenticated {
        return Err(AppError::NotFound(
            "User not found or has not authenticated with this service".to_string(),
        ));
    }

    let allowed_scopes = service_allowed_scopes(&state, &service, &req.provider).await?;
    if allowed_scopes.is_empty() {
        return Err(AppError::Forbidden(format!(
            "Service does not have {} scopes configured",
            req.provider
        )));
    }
    if req.scopes.is_empty() {
        req.scopes = allowed_scopes.clone();
    }
    let missing_from_service = missing_scopes(&allowed_scopes, &req.scopes);
    if !missing_from_service.is_empty() {
        return Err(AppError::Forbidden(format!(
            "Requested scopes are not allowed for this service: {}",
            missing_from_service.join(", ")
        )));
    }

    let accounts = ConnectedAccountStore::list_by_user_and_provider(
        DB::Conn(&state.db),
        &req.user_id,
        &req.provider,
    )
    .await?;
    if accounts.is_empty() {
        let response = action_required(
            &state,
            &service,
            &req,
            None,
            "PROVIDER_LINK_REQUIRED",
            req.scopes.clone(),
        )
        .await?;
        return Ok(Json(response));
    }
    let account_ids = accounts
        .iter()
        .map(|account| account.id.clone())
        .collect::<Vec<_>>();
    let grants_by_account = ServiceProviderGrantStore::list_active_by_accounts(
        DB::Conn(&state.db),
        &req.user_id,
        &service.id,
        &account_ids,
    )
    .await?
    .into_iter()
    .map(|grant| (grant.connected_account_id.clone(), grant))
    .collect::<HashMap<_, _>>();

    for account in accounts {
        let account_scopes = parse_scopes(&account.scopes);
        if !has_all_scopes(&account_scopes, &req.scopes) {
            continue;
        }

        let Some(grant) = grants_by_account.get(&account.id).cloned() else {
            let response = action_required(
                &state,
                &service,
                &req,
                Some(&account.id),
                "PROVIDER_GRANT_REQUIRED",
                vec![],
            )
            .await?;
            return Ok(Json(response));
        };

        let grant_scopes = parse_scopes_required(&grant.scopes);
        let missing_from_grant = missing_scopes(&grant_scopes, &req.scopes);
        if !missing_from_grant.is_empty() {
            let response = action_required(
                &state,
                &service,
                &req,
                Some(&account.id),
                "PROVIDER_SCOPE_CONSENT_REQUIRED",
                missing_from_grant,
            )
            .await?;
            return Ok(Json(response));
        }

        let token_exceeds_grant = !extra_scopes(&account_scopes, &grant_scopes).is_empty();
        let token_exceeds_service = !extra_scopes(&account_scopes, &allowed_scopes).is_empty();
        if token_exceeds_grant || token_exceeds_service {
            let response = action_required(
                &state,
                &service,
                &req,
                Some(&account.id),
                "PROVIDER_REAUTH_REQUIRED",
                vec![],
            )
            .await?;
            return Ok(Json(response));
        }

        let usable_account = if let Some(expires_at_naive) = account.expires_at {
            let expires_at = DateTime::<Utc>::from_naive_utc_and_offset(expires_at_naive, Utc);
            if expires_at < Utc::now() + Duration::minutes(5) {
                match refresh_connected_account(&state, &service, &account).await {
                    Ok(refreshed) => refreshed,
                    Err(_) => {
                        let response = action_required(
                            &state,
                            &service,
                            &req,
                            Some(&account.id),
                            "PROVIDER_REAUTH_REQUIRED",
                            vec![],
                        )
                        .await?;
                        return Ok(Json(response));
                    }
                }
            } else {
                account
            }
        } else {
            account
        };

        let access_token = decrypt_token(
            state.encryption.as_deref(),
            &usable_account.id,
            "access_token_encrypted",
            &usable_account.access_token,
            &usable_account.access_token_encrypted,
        )?
        .ok_or_else(|| {
            AppError::InternalServerError("Connected account has no token".to_string())
        })?;
        let transaction = state.db.begin().await?;
        ServiceProviderGrantStore::mark_used(DB::Tx(&transaction), &grant.id).await?;
        let event = OrgAuditBuilder::new(&service.org_id, None, "provider_token.issued")
            .target("connected_account", &usable_account.id)
            .details_json(Some(json!({
                "service_id": &service.id,
                "user_id": &req.user_id,
                "provider": &usable_account.provider,
                "scopes": &req.scopes,
                "grant_id": &grant.id,
            })))
            .build();
        state
            .audit_actor
            .log_org_with_db(DB::Tx(&transaction), event)
            .await?;
        transaction.commit().await?;

        return Ok(Json(ServiceProviderTokenResponse::Ok {
            access_token,
            expires_at: usable_account
                .expires_at
                .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc).to_rfc3339()),
            scopes: grant_scopes,
            provider: usable_account.provider.clone(),
            account: ProviderTokenAccount {
                id: usable_account.id,
                provider_user_id: usable_account.provider_user_id,
                email: usable_account.email,
                display_name: usable_account.display_name,
            },
        }));
    }

    let response = action_required(
        &state,
        &service,
        &req,
        None,
        "PROVIDER_SCOPE_CONSENT_REQUIRED",
        req.scopes.clone(),
    )
    .await?;
    Ok(Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encryption() -> crate::encryption::EncryptionService {
        crate::encryption::EncryptionService::from_keyring_values("active", &"11".repeat(32), None)
            .unwrap()
    }

    #[test]
    fn configured_encryption_rejects_account_plaintext_and_reads_exact_v2_field() {
        let encryption = encryption();
        let plaintext = Some("account-plaintext-canary".to_string());
        let error = decrypt_token(
            Some(&encryption),
            "account-a",
            "refresh_token_encrypted",
            &plaintext,
            &None,
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("requires migration"));
        assert!(!message.contains("account-plaintext-canary"));

        assert_eq!(
            decrypt_token(
                None,
                "account-a",
                "refresh_token_encrypted",
                &plaintext,
                &None,
            )
            .unwrap(),
            plaintext
        );

        let ciphertext = encryption
            .encrypt_with_context(
                "account-v2-canary",
                crate::encryption::EncryptionContext::new(
                    "connected_accounts",
                    "account-a",
                    "refresh_token_encrypted",
                ),
            )
            .unwrap();
        assert_eq!(
            decrypt_token(
                Some(&encryption),
                "account-a",
                "refresh_token_encrypted",
                &None,
                &Some(ciphertext),
            )
            .unwrap()
            .as_deref(),
            Some("account-v2-canary")
        );
    }

    #[test]
    fn parse_scopes_accepts_json_comma_and_space_formats() {
        assert_eq!(
            parse_scopes(&Some(r#"["openid","email","profile"]"#.to_string())),
            vec!["openid", "email", "profile"]
        );
        assert_eq!(
            parse_scopes(&Some("openid, email profile".to_string())),
            vec!["openid", "email", "profile"]
        );
    }

    #[test]
    fn provider_normalization_preserves_custom_connection_ids() {
        assert_eq!(normalize_provider_key("Microsoft"), "microsoft");
        assert_eq!(normalize_provider_key("okta-Prod"), "okta-Prod");
    }
}
