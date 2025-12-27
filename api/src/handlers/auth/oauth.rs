use crate::auth::jwt::JwtService;
use crate::auth::sso::{oauth_http_client, Provider};
use crate::constants::{JWT_EXPIRE_HOURS, OAUTH_STATE_EXPIRE_MINUTES};
use crate::db::models::{DeviceCode, Service, User};
use crate::error::{AppError, Result};
use crate::middleware::RequestInfo;
use crate::state::AppState;
use crate::store::{
    device_codes::DeviceCodeStore, identities::IdentityStore,
    memberships::MembershipStore, oauth_states::OAuthStateStore, organizations::OrganizationStore,
    services::ServiceStore, sessions::SessionStore, upstream_providers::UpstreamProviderStore, DB,
};
use axum::{
    extract::{Extension, Path, Query, State},
    response::{Html, IntoResponse, Json, Redirect, Response},
};
use chrono::Utc;
use oauth2::url;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, TokenUrl,
};
use sea_orm::DatabaseConnection;
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

// SSO Authorization Request
#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    pub org: String,
    pub service: String,
    pub redirect_uri: Option<String>,
    pub user_code: Option<String>,
    pub saml_state: Option<String>,
    pub connection_id: Option<String>,
}

// Admin Auth Request
#[derive(Debug, Deserialize)]
pub struct AdminAuthRequest {
    pub org_slug: Option<String>,
    pub user_code: Option<String>,
}

// SSO Callback Query Parameters
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: Option<String>,
    pub format: Option<String>, // If set to "json", return JSON instead of redirect
}

/// SSO: Initiate OAuth flow
pub async fn auth_provider(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    Query(params): Query<AuthRequest>,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;

    // Get service to fetch configured scopes and validate redirect_uri
    // Get organization first, then service
    let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), &params.org)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let service_entity =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &organization.id, &params.service)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    // Convert entity to db model
    let service = crate::db::models::Service {
        id: service_entity.id,
        org_id: service_entity.org_id,
        slug: service_entity.slug,
        name: service_entity.name,
        service_type: service_entity.service_type,
        client_id: service_entity.client_id,
        client_secret_hash: service_entity.client_secret_hash,
        github_scopes: service_entity.github_scopes,
        microsoft_scopes: service_entity.microsoft_scopes,
        google_scopes: service_entity.google_scopes,
        redirect_uris: service_entity.redirect_uris,
        device_activation_uri: service_entity.device_activation_uri,
        saml_enabled: service_entity.saml_enabled,
        saml_entity_id: service_entity.saml_entity_id,
        saml_acs_url: service_entity.saml_acs_url,
        saml_slo_url: service_entity.saml_slo_url,
        saml_name_id_format: service_entity.saml_name_id_format,
        saml_attribute_mapping: service_entity.saml_attribute_mapping,
        saml_sign_assertions: service_entity.saml_sign_assertions,
        saml_sign_response: service_entity.saml_sign_response,
        created_at: chrono::DateTime::from_naive_utc_and_offset(service_entity.created_at, Utc),
    };

    // Validate redirect_uri against allowed URIs
    if let Some(redirect_uri) = &params.redirect_uri {
        validate_redirect_uri(redirect_uri, &service)?;
    }

    let scopes = get_provider_scopes(&service, provider);

    // Check if organization has custom OAuth credentials for this provider
    let org_id = &organization.id;
    let provider_str = provider.as_str();

    // Determine authorization URL and state based on whether it's an upstream connection or regular OAuth
    let (auth_url, csrf_token, pkce_verifier, upstream_conn_id) =
        if let Some(conn_id) = &params.connection_id {
            // Upstream Enterprise SSO (HRD) flow
            let provider_model = UpstreamProviderStore::find_by_connection_id(
                DB::Conn(&state.db),
                &organization.id,
                conn_id,
            )
            .await?
            .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;

            if provider_model.provider_type != "oidc" {
                return Err(AppError::BadRequest(
                    "Only OIDC upstream providers are supported currently".to_string(),
                ));
            }

            let encryption = state.encryption.as_ref().ok_or_else(|| {
                AppError::InternalServerError("Encryption unavailable".to_string())
            })?;
            let secret = encryption
                .decrypt(&provider_model.client_secret_encrypted)
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to decrypt secret: {}", e))
                })?;

            // Create OIDC client for this upstream provider
            let client = BasicClient::new(
                ClientId::new(provider_model.client_id.clone()),
                Some(ClientSecret::new(secret)),
                AuthUrl::new(provider_model.authorization_url.clone().ok_or_else(|| {
                    AppError::BadRequest("Missing authorization_url".to_string())
                })?)
                .map_err(|e| AppError::OAuth(e.to_string()))?,
                provider_model
                    .token_url
                    .clone()
                    .map(|u| TokenUrl::new(u).ok())
                    .flatten(),
            )
            .set_redirect_uri(
                RedirectUrl::new(format!("{}/auth/callback/oidc", state.base_url))
                    .map_err(|e| AppError::OAuth(e.to_string()))?,
            );

            let upstream_scopes: Vec<String> = provider_model
                .scopes
                .as_ref()
                .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                .unwrap_or_else(|| {
                    vec![
                        "openid".to_string(),
                        "email".to_string(),
                        "profile".to_string(),
                    ]
                });

            let (url, csrf, verifier) =
                get_authorization_url_for_client(&client, Provider::Oidc, upstream_scopes);
            (url, csrf, verifier, Some(conn_id.clone()))
        } else {
            // Regular OAuth flow (Platform or BYOO)
            let org_credentials =
                OrganizationStore::get_oauth_credentials(DB::Conn(&state.db), org_id, provider_str)
                    .await?;

            let (url, csrf, verifier) = if let Some(_creds) = org_credentials {
                // Use organization's custom OAuth credentials (BYOO)
                let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
                    AppError::InternalServerError(format!("Encryption unavailable: {}", e))
                })?;

                let custom_client =
                    crate::store::organizations::OrganizationStore::get_oauth_client_for_org(
                        DB::Conn(&state.db),
                        org_id,
                        provider,
                        &encryption,
                    )
                    .await?;
                get_authorization_url_for_client(&custom_client, provider, scopes)
            } else {
                // Fall back to platform's default OAuth credentials
                state
                    .oauth_client
                    .get_authorization_url_with_pkce(provider, scopes)?
            };
            (url, csrf, verifier, None)
        };

    // Store OAuth state
    let expires_at = Utc::now() + chrono::Duration::minutes(OAUTH_STATE_EXPIRE_MINUTES);
    let pkce_value = if provider == Provider::Microsoft && !pkce_verifier.is_empty() {
        Some(pkce_verifier.as_str())
    } else {
        None
    };

    OAuthStateStore::create(
        DB::Conn(&state.db),
        csrf_token.secret(),
        pkce_value,
        Some(&service.id),
        params.redirect_uri.as_deref(),
        Some(&params.org),
        Some(&params.service),
        false, // is_admin_flow
        None,  // user_id_for_linking
        params.user_code.as_deref(),
        params.saml_state.as_deref(),
        upstream_conn_id.as_deref(),
        &expires_at.naive_utc(),
    )
    .await?;

    Ok(Redirect::to(&auth_url).into_response())
}

pub fn get_provider_scopes(
    service: &crate::db::models::Service,
    provider: Provider,
) -> Vec<String> {
    let scopes_json = match provider {
        Provider::Github => &service.github_scopes,
        Provider::Microsoft => &service.microsoft_scopes,
        Provider::Google => &service.google_scopes,
        Provider::Oidc => &None,
    };

    scopes_json
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| default_scopes_for_provider(provider))
}

fn default_scopes_for_provider(provider: Provider) -> Vec<String> {
    match provider {
        Provider::Github => vec!["user:email".to_string()],
        Provider::Microsoft => vec![
            "User.Read".to_string(),
            "email".to_string(),
            "openid".to_string(),
            "profile".to_string(),
        ],
        Provider::Google => vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
        Provider::Oidc => vec![
            "openid".to_string(),
            "email".to_string(),
            "profile".to_string(),
        ],
    }
}

/// SSO: Handle OAuth callback
pub async fn auth_callback(
    State(state): State<AppState>,
    Extension(request_info): Extension<RequestInfo>,
    Path(provider_str): Path<String>,
    Query(callback): Query<CallbackQuery>,
) -> Result<Response> {
    // Wrap the main logic to catch errors and handle them appropriately
    match auth_callback_impl(state, request_info, provider_str, callback).await {
        Ok(response) => Ok(response),
        Err(e) => {
            // Log the error
            tracing::error!("OAuth callback error: {}", e);

            // Return a simple HTML error page
            let error_message = match &e {
                AppError::OAuth(msg) => msg.clone(),
                AppError::BadRequest(msg) => msg.clone(),
                AppError::Unauthorized(msg) => msg.clone(),
                _ => "Authentication failed".to_string(),
            };

            // Simple HTML escaping for error message
            let escaped_error = error_message
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&quot;")
                .replace('\'', "&#x27;");

            let html = format!(
                r#"
                <!DOCTYPE html>
                <html>
                <head><title>Authentication Failed</title></head>
                <body>
                    <h1>Authentication Failed</h1>
                    <p>Error: {}</p>
                    <p>Please try again or contact support.</p>
                </body>
                </html>
                "#,
                escaped_error
            );

            Ok((axum::http::StatusCode::BAD_REQUEST, Html(html)).into_response())
        }
    }
}

/// Internal implementation of OAuth callback that can return errors
async fn auth_callback_impl(
    state: AppState,
    request_info: RequestInfo,
    provider_str: String,
    callback: CallbackQuery,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;

    // Load config (needed for user info fetching later)
    let config = crate::config::Config::from_env()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    // Get OAuth state (includes PKCE verifier, redirect_uri, org/service context)
    let oauth_state: Option<crate::db::models::OAuthState> =
        if let Some(ref state_param) = callback.state {
            OAuthStateStore::find_by_state(DB::Conn(&state.db), state_param)
                .await?
                .map(Into::into)
        } else {
            None
        };

    // Clean up OAuth state immediately to prevent replay attacks
    // We extract all needed info first, then delete the state before token exchange
    if let Some(ref state_param) = callback.state {
        let _ = OAuthStateStore::delete(DB::Conn(&state.db), state_param).await;
    }

    // Validate that we have a valid OAuth state (required for SSO flows)
    // If state was provided but not found (expired or invalid), reject the request
    if callback.state.is_some() && oauth_state.is_none() {
        return Err(AppError::BadRequest(
            "Invalid or expired state parameter".to_string(),
        ));
    }

    // Exchange code with PKCE verifier to get full token details
    // Check if we should use organization's BYOO credentials
    let pkce_verifier = oauth_state
        .as_ref()
        .and_then(|s| s.pkce_verifier.as_deref());

    // Determine issuing context (org_id and service_id) for proper identity isolation
    let (token_details, issuing_org_id, issuing_service_id) =
        if let Some(ref oauth_ctx) = oauth_state {
            if let Some(ref conn_id) = oauth_ctx.upstream_connection_id {
                // Upstream Enterprise SSO flow
                let organization = OrganizationStore::find_by_slug(
                    DB::Conn(&state.db),
                    oauth_ctx.org_slug.as_ref().ok_or_else(|| {
                        AppError::InternalServerError("Missing org_slug in OAuth state".to_string())
                    })?,
                )
                .await?
                .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let provider_model = UpstreamProviderStore::find_by_connection_id(
                    DB::Conn(&state.db),
                    &organization.id,
                    conn_id,
                )
                .await?
                .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;

                let encryption = state.encryption.as_ref().ok_or_else(|| {
                    AppError::InternalServerError("Encryption unavailable".to_string())
                })?;
                let secret = encryption
                    .decrypt(&provider_model.client_secret_encrypted)
                    .map_err(|e| {
                        AppError::InternalServerError(format!("Failed to decrypt secret: {}", e))
                    })?;

                let client = BasicClient::new(
                    ClientId::new(provider_model.client_id.clone()),
                    Some(ClientSecret::new(secret)),
                    AuthUrl::new(provider_model.authorization_url.clone().ok_or_else(|| {
                        AppError::InternalServerError(
                            "Missing authorization_url for upstream provider".to_string(),
                        )
                    })?)
                    .map_err(|e| AppError::OAuth(e.to_string()))?,
                    provider_model
                        .token_url
                        .clone()
                        .map(|u| TokenUrl::new(u).ok())
                        .flatten(),
                )
                .set_redirect_uri(
                    RedirectUrl::new(format!("{}/auth/callback/oidc", state.base_url))
                        .map_err(|e| AppError::OAuth(e.to_string()))?,
                );

                let details =
                    exchange_custom_code(&client, Provider::Oidc, &callback.code, pkce_verifier)
                        .await?;

                (details, Some(organization.id), oauth_ctx.service_id.clone())
            } else if let Some(ref service_id) = oauth_ctx.service_id {
                // Service flow - get org_id from service and use service credentials
                let service: crate::db::models::Service =
                    ServiceStore::find_by_id(DB::Conn(&state.db), service_id)
                        .await?
                        .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?
                        .into();

                let org_id = service.org_id.clone();

                // Check for BYOO credentials for this organization
                let provider_str = provider.as_str();

                let org_credentials = OrganizationStore::get_oauth_credentials(
                    DB::Conn(&state.db),
                    &org_id,
                    provider_str,
                )
                .await?;

                let details = if let Some(_creds) = org_credentials {
                    // Use organization's custom OAuth credentials for token exchange
                    let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
                        AppError::InternalServerError(format!("Encryption unavailable: {}", e))
                    })?;

                    let custom_client =
                        crate::store::organizations::OrganizationStore::get_oauth_client_for_org(
                            DB::Conn(&state.db),
                            &org_id,
                            provider,
                            &encryption,
                        )
                        .await?;

                    exchange_custom_code(&custom_client, provider, &callback.code, pkce_verifier)
                        .await?
                } else {
                    // Fall back to platform credentials for this service
                    state
                        .oauth_client
                        .exchange_code_with_details(provider, &callback.code, pkce_verifier)
                        .await?
                };

                (details, Some(org_id), Some(service_id.clone()))
            } else if let Some(ref org_slug) = oauth_ctx.org_slug {
                // Legacy org-based flow (no service_id) - use org credentials but no service isolation
                let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let org_id = org.id.clone();
                let provider_str = provider.as_str();

                let org_credentials = OrganizationStore::get_oauth_credentials(
                    DB::Conn(&state.db),
                    &org_id,
                    provider_str,
                )
                .await?;

                let details = if let Some(_creds) = org_credentials {
                    // Use organization's custom OAuth credentials for token exchange
                    let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
                        AppError::InternalServerError(format!("Encryption unavailable: {}", e))
                    })?;

                    let custom_client =
                        crate::store::organizations::OrganizationStore::get_oauth_client_for_org(
                            DB::Conn(&state.db),
                            &org_id,
                            provider,
                            &encryption,
                        )
                        .await?;

                    exchange_custom_code(&custom_client, provider, &callback.code, pkce_verifier)
                        .await?
                } else {
                    // Fall back to platform credentials
                    state
                        .oauth_client
                        .exchange_code_with_details(provider, &callback.code, pkce_verifier)
                        .await?
                };

                (details, Some(org_id), None)
            } else {
                // No service or org context - platform credentials
                let details = state
                    .oauth_client
                    .exchange_code_with_details(provider, &callback.code, pkce_verifier)
                    .await?;
                (details, None, None)
            }
        } else {
            // No oauth state - platform credentials
            let details = state
                .oauth_client
                .exchange_code_with_details(provider, &callback.code, pkce_verifier)
                .await?;
            (details, None, None)
        };

    // Get user info
    let user_info = if provider == Provider::Oidc {
        // Handle OIDC user info fetching (requires fetching provider model again)
        let oauth_ctx = oauth_state.as_ref().ok_or_else(|| {
            AppError::BadRequest("Missing OAuth state for OIDC provider".to_string())
        })?;

        let conn_id = oauth_ctx.upstream_connection_id.as_ref().ok_or_else(|| {
            AppError::BadRequest("Missing upstream connection ID for OIDC provider".to_string())
        })?;

        let org_slug = oauth_ctx.org_slug.as_ref().ok_or_else(|| {
            AppError::InternalServerError("Missing org_slug in OAuth state".to_string())
        })?;

        let organization = OrganizationStore::find_by_slug(DB::Conn(&state.db), org_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let provider_model = UpstreamProviderStore::find_by_connection_id(
            DB::Conn(&state.db),
            &organization.id,
            conn_id,
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;

        // Fetch user info using provider's userinfo_url
        let userinfo_url = provider_model.userinfo_url.ok_or_else(|| {
            AppError::InternalServerError("Upstream provider missing userinfo_url".to_string())
        })?;

        // Use reqwest to fetch user info
        let client = reqwest::Client::new();
        let resp = client
            .get(&userinfo_url)
            .bearer_auth(&token_details.access_token)
            .send()
            .await
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to fetch user info: {}", e))
            })?;

        if !resp.status().is_success() {
            return Err(AppError::InternalServerError(format!(
                "User info request failed with status: {}",
                resp.status()
            )));
        }

        #[derive(serde::Deserialize)]
        struct OidcUserInfo {
            sub: String,
            email: Option<String>,
            name: Option<String>,
        }

        let info: OidcUserInfo = resp.json().await.map_err(|e| {
            AppError::InternalServerError(format!("Failed to parse user info: {}", e))
        })?;

        crate::auth::sso::UserInfo {
            provider_user_id: info.sub,
            email: info.email.ok_or_else(|| {
                AppError::BadRequest("Email not provided by OIDC provider".to_string())
            })?,
            name: info.name,
        }
    } else {
        // Standard providers
        get_provider_user_info(provider, &token_details.access_token, &config).await?
    };

    // Check if this is a linking flow (user_id_for_linking is set)
    if let Some(ref oauth_ctx) = oauth_state {
        if let Some(ref linking_user_id) = oauth_ctx.user_id_for_linking {
            // This is a linking flow - link the new provider to the existing user

            // Security check: Ensure the provider account is not already linked to a different user
            let existing_identity: Option<crate::db::models::Identity> =
                IdentityStore::find_any_by_provider_and_provider_user_id(
                    DB::Conn(&state.db),
                    provider.as_str(),
                    &user_info.provider_user_id,
                )
                .await?
                .map(Into::into);

            if let Some(existing) = existing_identity {
                if existing.user_id != *linking_user_id {
                    return Err(AppError::BadRequest(
                        "This social account is already linked to a different user".to_string(),
                    ));
                }
                // Already linked to the same user, just update tokens
            }

            // Create or update identity for the linking user
            IdentityStore::upsert_with_details(
                DB::Conn(&state.db),
                state.encryption.as_ref(),
                linking_user_id,
                provider.as_str(),
                &user_info.provider_user_id,
                &token_details.access_token,
                token_details.refresh_token.as_deref(),
                token_details.expires_at,
                &token_details.scopes,
                issuing_org_id.as_deref(),
                issuing_service_id.as_deref(),
            )
            .await?;

            // Redirect to frontend callback URL
            // redirect_uri already contains query params: ?status=success&provider=X&action=link
            let redirect_url = oauth_ctx.redirect_uri.as_ref().ok_or_else(|| {
                AppError::InternalServerError(
                    "No redirect_uri in oauth state for linking flow".to_string(),
                )
            })?;
            return Ok(Redirect::to(redirect_url).into_response());
        }
    }

    // Normal login flow - find or create user
    let (user_model, was_created) =
        crate::store::users::UserStore::find_or_create(DB::Conn(&state.db), &user_info.email)
            .await?;
    let user: User = user_model.into();

    // Run risk engine evaluation for existing users (skip for new users)
    let risk_assessment = if !was_created {
        use crate::services::risk_engine::RiskContext;
        let risk_ctx = RiskContext {
            user_id: &user.id,
            org_id: issuing_org_id.as_deref(),
            ip_address: &request_info.ip_address,
            user_agent: &request_info.user_agent,
            device_cookie: None, // No device cookie available during OAuth callback
        };

        let assessment = state
            .risk_engine
            .evaluate(DB::Conn(&state.db), risk_ctx)
            .await?;

        // Log risk assessment
        tracing::info!(
            user_id = %user.id,
            email = %user.email,
            provider = %provider.as_str(),
            risk_score = assessment.score,
            risk_action = ?assessment.action,
            risk_factors = ?assessment.factors,
            "OAuth login risk assessment"
        );

        Some(assessment)
    } else {
        None
    };

    // Publish signup event if user was just created
    if was_created {
        use crate::services::events::{Event, EventType};
        use serde_json::json;

        let mut event_builder = Event::builder(EventType::UserSignupSuccess)
            .actor_user_id(&user.id)
            .actor_email(&user_info.email);

        if let Some(org_id) = &issuing_org_id {
            event_builder = event_builder.org_id(org_id);
        }

        if let Some(service_id) = &issuing_service_id {
            event_builder = event_builder.detail("service_id", json!(service_id));
        }

        event_builder = event_builder.detail("provider", json!(provider.as_str()));

        let event = event_builder.build();

        // Fire and forget
        let dispatcher = state.event_dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatcher.publish(event).await {
                tracing::error!("Failed to publish signup event: {}", e);
            }
        });
    }

    // Update identity with full token details
    IdentityStore::upsert_with_details(
        DB::Conn(&state.db),
        state.encryption.as_ref(),
        &user.id,
        provider.as_str(),
        &user_info.provider_user_id,
        &token_details.access_token,
        token_details.refresh_token.as_deref(),
        token_details.expires_at,
        &token_details.scopes,
        issuing_org_id.as_deref(),
        issuing_service_id.as_deref(),
    )
    .await?;

    // Check if this is a SAML flow - complete SAML response if so
    if let Some(ref oauth_ctx) = oauth_state {
        if let Some(ref saml_state_id) = oauth_ctx.saml_state_id {
            // This is a SAML authentication flow - complete SAML response
            return crate::handlers::saml::complete_saml_authentication(
                &state,
                saml_state_id,
                &user,
            )
            .await;
        }
    }

    // Handle device flow completion
    if let Some(ref oauth_ctx) = oauth_state {
        if oauth_ctx.redirect_uri.is_none()
            && (oauth_ctx.org_slug.is_some() || oauth_ctx.service_slug.is_some())
        {
            // This is a device flow callback - find and update the device code
            if let (Some(org_slug), Some(service_slug)) =
                (&oauth_ctx.org_slug, &oauth_ctx.service_slug)
            {
                // Find device code using the user_code if provided, otherwise fall back to most recent
                let device_code: Option<DeviceCode> =
                    if let Some(ref user_code) = oauth_ctx.device_user_code {
                        DeviceCodeStore::find_pending_by_user_code(DB::Conn(&state.db), user_code)
                            .await?
                            .map(Into::into)
                    } else {
                        DeviceCodeStore::find_latest_pending_by_org_service(
                            DB::Conn(&state.db),
                            org_slug,
                            service_slug,
                        )
                        .await?
                        .map(Into::into)
                    };

                if let Some(dc) = device_code {
                    // Check if user has MFA enabled
                    let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

                    if !mfa_enabled {
                        // No MFA - authorize the device code immediately
                        DeviceCodeStore::authorize(DB::Conn(&state.db), &dc.id, &user.id).await?;
                    } else {
                        // MFA enabled - store user_id but don't authorize yet
                        // The device will remain pending until MFA is completed
                        DeviceCodeStore::set_user_id(DB::Conn(&state.db), &dc.id, &user.id).await?;

                        // Redirect to MFA challenge with device flow context
                        // Create pre-auth token with device context
                        let preauth_token = state.jwt_service.create_mfa_preauth_token(
                            &user.id,
                            &user.email,
                            user.is_platform_owner,
                            Some(org_slug),
                            Some(service_slug),
                            oauth_ctx.saml_state_id.as_deref(),
                        )?;

                        // Get the device activation URI for redirect
                        let service = ServiceStore::find_by_org_slug_and_service_slug(
                            DB::Conn(&state.db),
                            org_slug,
                            service_slug,
                        )
                        .await?
                        .map(crate::db::models::Service::from);

                        let base_activation_uri = service
                            .and_then(|s| s.device_activation_uri)
                            .ok_or_else(|| {
                                AppError::InternalServerError(
                                    "Device activation URI not configured for this service"
                                        .to_string(),
                                )
                            })?;

                        let mut mfa_url = url::Url::parse(&base_activation_uri).map_err(|_| {
                            AppError::InternalServerError(
                                "Invalid device activation URI configured".to_string(),
                            )
                        })?;

                        // Redirect to MFA challenge page with pre-auth token and device code info
                        mfa_url.set_path("/activate/mfa-challenge");
                        mfa_url
                            .query_pairs_mut()
                            .append_pair("preauth_token", &preauth_token)
                            .append_pair("device_code_id", &dc.id)
                            .append_pair("user_code", &dc.user_code);

                        return Ok(Redirect::to(mfa_url.as_str()).into_response());
                    }
                }

                // This is a device flow completion - redirect to service's success page
                // Get service to find device activation URI
                let service = ServiceStore::find_by_org_slug_and_service_slug(
                    DB::Conn(&state.db),
                    org_slug,
                    service_slug,
                )
                .await?
                .map(crate::db::models::Service::from);

                // Use the service's configured device activation URI
                let base_activation_uri = service
                    .and_then(|s| s.device_activation_uri)
                    .ok_or_else(|| {
                        AppError::InternalServerError(
                            "Device activation URI not configured for this service".to_string(),
                        )
                    })?;

                // Create success redirect URL with token
                let mut success_url = url::Url::parse(&base_activation_uri).map_err(|_| {
                    AppError::InternalServerError(
                        "Invalid device activation URI configured".to_string(),
                    )
                })?;

                // Set path to success page and include status and token
                success_url.set_path("/activate/success");
                success_url
                    .query_pairs_mut()
                    .append_pair("status", "success")
                    .append_pair("device_flow", "true");

                return Ok(Redirect::to(success_url.as_str()).into_response());
            }
        }
    }

    // If redirect_uri provided, issue JWT and redirect
    if let Some(ref oauth_ctx) = oauth_state {
        if let Some(ref redirect_uri) = oauth_ctx.redirect_uri {
            // Get service info for JWT
            let service_slug = if let (Some(org), Some(svc)) =
                (&oauth_ctx.org_slug, &oauth_ctx.service_slug)
            {
                // Get service
                let service =
                    ServiceStore::find_by_org_slug_and_service_slug(DB::Conn(&state.db), org, svc)
                        .await?
                        .map(crate::db::models::Service::from);

                if let Some(service) = service {
                    // Validate redirect_uri again before redirecting
                    validate_redirect_uri(redirect_uri, &service)?;
                    Some(svc.clone())
                } else {
                    None
                }
            } else {
                None
            };

            // Check if user has MFA enabled
            let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

            // Handle risk engine actions for existing users
            if let Some(risk_assessment) = risk_assessment {
                use crate::services::risk_engine::RiskAction;
                match risk_assessment.action {
                    RiskAction::ChallengeMFA => {
                        // Risk engine demands MFA challenge
                        let preauth_token = state.jwt_service.create_mfa_preauth_token(
                            &user.id,
                            &user.email,
                            user.is_platform_owner,
                            oauth_ctx.org_slug.as_deref(),
                            service_slug.as_deref(),
                            oauth_ctx.saml_state_id.as_deref(),
                        )?;

                        // Redirect with pre-auth token and mfa_required flag
                        let redirect_url = format!(
                            "{}?preauth_token={}&mfa_required=true",
                            redirect_uri, preauth_token
                        );
                        return Ok(Redirect::to(&redirect_url).into_response());
                    }
                    RiskAction::Block => {
                        tracing::warn!(
                            user_id = %user.id,
                            email = %user.email,
                            provider = %provider.as_str(),
                            risk_score = risk_assessment.score,
                            factors = ?risk_assessment.factors,
                            "OAuth login blocked by risk engine"
                        );

                        // Return error page instead of redirect
                        let html = format!(
                            r#"
                            <!DOCTYPE html>
                            <html>
                            <head><title>Login Blocked</title></head>
                            <body>
                                <h1>Login Suspended</h1>
                                <p>For security reasons, we've temporarily suspended this login attempt.</p>
                                <p>Please contact support if this continues to occur.</p>
                            </body>
                            </html>
                            "#
                        );
                        return Ok((axum::http::StatusCode::FORBIDDEN, Html(html)).into_response());
                    }
                    RiskAction::Allow | RiskAction::LogOnly => {
                        // Continue with normal flow
                    }
                }
            }

            if mfa_enabled {
                // User has MFA enabled - create pre-auth token instead of full session
                let preauth_token = state.jwt_service.create_mfa_preauth_token(
                    &user.id,
                    &user.email,
                    user.is_platform_owner,
                    oauth_ctx.org_slug.as_deref(),
                    service_slug.as_deref(),
                    oauth_ctx.saml_state_id.as_deref(),
                )?;

                // Redirect with pre-auth token and mfa_required flag
                let redirect_url = format!(
                    "{}?preauth_token={}&mfa_required=true",
                    redirect_uri, preauth_token
                );
                return Ok(Redirect::to(&redirect_url).into_response());
            }

            // MFA not enabled - proceed with normal token issuance

            // Check MAU limit for organization logins (billing enforcement)
            if let Some(ref org_id) = issuing_org_id {
                crate::services::tier_enforcement::TierService::check_mau_limit(
                    DB::Conn(&state.db),
                    org_id,
                )
                .await?;
            }

            // Create JWT
            let jwt = state.jwt_service.create_token(
                &user.id,
                &user.email,
                user.is_platform_owner,
                oauth_ctx.org_slug.as_deref(),
                service_slug.as_deref(),
            )?;

            // Generate refresh token
            let refresh_token = uuid::Uuid::new_v4().to_string();

            // Store session with refresh token
            let token_hash = JwtService::hash_token(&jwt);
            let now = Utc::now();
            let expires_at = now + chrono::Duration::hours(config.jwt_expiration_hours);
            let refresh_expires_at = now + chrono::Duration::days(30);

            SessionStore::create(
                DB::Conn(&state.db),
                &user.id,
                &token_hash,
                expires_at.naive_utc(),
                Some(&refresh_token),
                Some(refresh_expires_at.naive_utc()),
                oauth_ctx.org_slug.as_deref(),
                oauth_ctx.service_id.as_deref(),
                None, // user_agent
                None, // ip_address
            )
            .await?;

            // Record login event if service_id is available
            if let Some(ref service_id) = oauth_ctx.service_id {
                record_login_event(&state.audit_actor, &user.id, service_id, provider).await;
            }

            // Publish login success event for webhooks
            publish_login_event(
                &state.event_dispatcher,
                &user.id,
                &user.email,
                oauth_ctx.org_slug.as_deref(),
                oauth_ctx.service_id.as_deref(),
                Some(provider.as_str()),
            )
            .await;

            // Check if JSON response is requested (to avoid header overflow in API flows)
            if callback.format.as_ref().map_or(false, |f| f == "json") {
                // Return JSON response instead of redirect for API flows
                use serde_json::json;
                let response_body = json!({
                    "access_token": jwt,
                    "refresh_token": refresh_token,
                    "token_type": "Bearer"
                });
                return Ok(Json(response_body).into_response());
            }

            // Redirect with both tokens as query parameters
            let redirect_url = format!(
                "{}?access_token={}&refresh_token={}",
                redirect_uri, jwt, refresh_token
            );
            return Ok(Redirect::to(&redirect_url).into_response());
        }
    }

    // No redirect_uri - show HTML success page
    let html = format!(
        r#"
        <!DOCTYPE html>
        <html>
        <head><title>Authentication Successful</title></head>
        <body>
            <h1>Authentication Successful</h1>
            <p>User: {}</p>
            <p>Provider: {}</p>
        </body>
        </html>
        "#,
        user_info.email,
        provider.as_str()
    );

    Ok(Html(html).into_response())
}

/// Admin Auth: Initiate OAuth flow for platform/org admin login
pub async fn auth_admin_provider(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    Query(params): Query<AdminAuthRequest>,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;

    // Build admin OAuth client dynamically using PLATFORM_* credentials
    let config = crate::config::Config::from_env()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let admin_oauth_client = create_admin_oauth_client(&config, provider)?;

    // Use default admin scopes based on provider
    let scopes = default_scopes_for_provider(provider);

    // Generate authorization URL with PKCE (for Microsoft)
    let (auth_url, csrf_token, pkce_verifier) =
        get_admin_authorization_url(&admin_oauth_client, provider, scopes);

    // Store OAuth state with is_admin_flow = true
    let expires_at = Utc::now() + chrono::Duration::minutes(OAUTH_STATE_EXPIRE_MINUTES);
    let pkce_value = if provider == Provider::Microsoft && !pkce_verifier.is_empty() {
        Some(pkce_verifier)
    } else {
        None
    };

    let is_admin_flow = true;
    OAuthStateStore::create(
        DB::Conn(&state.db),
        csrf_token.secret(),
        pkce_value.as_deref(),
        None, // service_id
        None, // redirect_uri
        params.org_slug.as_deref(),
        None, // service_slug
        is_admin_flow,
        None, // user_id_for_linking
        params.user_code.as_deref(),
        None, // saml_state_id
        None, // upstream_connection_id
        &expires_at.naive_utc(),
    )
    .await?;

    Ok(Redirect::to(&auth_url).into_response())
}

/// Admin Auth: Handle OAuth callback for admin login
pub async fn auth_admin_callback(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    Query(callback): Query<CallbackQuery>,
) -> Result<Response> {
    // Load config early so we can use it for error redirects
    let config = crate::config::Config::from_env()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    // Wrap the main logic to catch errors and redirect to frontend with error info
    match auth_admin_callback_impl(state, provider_str, callback).await {
        Ok(response) => Ok(response),
        Err(e) => {
            // Log the error
            tracing::error!("OAuth callback error: {}", e);

            // Redirect to frontend with error information
            let error_message = match &e {
                AppError::OAuth(msg) => msg.clone(),
                AppError::BadRequest(msg) => msg.clone(),
                AppError::Unauthorized(msg) => msg.clone(),
                _ => "Authentication failed".to_string(),
            };

            let redirect_base = format!("{}/callback", config.platform_dashboard_base_url);
            let mut redirect_url = url::Url::parse(&redirect_base).map_err(|_| {
                AppError::InternalServerError("Invalid platform admin redirect URI".to_string())
            })?;

            redirect_url
                .query_pairs_mut()
                .append_pair("error", "oauth_error")
                .append_pair("error_description", &error_message);

            Ok(Redirect::to(redirect_url.as_str()).into_response())
        }
    }
}

/// Internal implementation of admin callback that can return errors
async fn auth_admin_callback_impl(
    state: AppState,
    provider_str: String,
    callback: CallbackQuery,
) -> Result<Response> {
    let provider = Provider::from_str(&provider_str)?;

    // Get OAuth state and verify it's an admin flow
    let oauth_state = if let Some(ref state_param) = callback.state {
        OAuthStateStore::find_by_state(DB::Conn(&state.db), state_param)
            .await?
            .map(crate::db::models::OAuthState::from)
    } else {
        None
    };

    let oauth_state =
        oauth_state.ok_or_else(|| AppError::BadRequest("Invalid state parameter".to_string()))?;

    if !oauth_state.is_admin_flow {
        return Err(AppError::BadRequest("Not an admin flow".to_string()));
    }

    // Clean up OAuth state immediately to prevent replay attacks
    // Do this before token exchange so even if exchange fails, state cannot be reused
    if let Some(ref state_param) = callback.state {
        let _ = OAuthStateStore::delete(DB::Conn(&state.db), state_param).await;
    }

    // Build admin OAuth client with PLATFORM_* credentials
    let config = crate::config::Config::from_env()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    let admin_oauth_client = create_admin_oauth_client(&config, provider)?;

    // Exchange code with PKCE verifier
    let pkce_verifier = oauth_state.pkce_verifier.as_deref();
    let token_details =
        exchange_admin_code(&admin_oauth_client, provider, &callback.code, pkce_verifier).await?;

    // Get user info from provider (standalone, not using OAuth client)
    let user_info = get_provider_user_info(provider, &token_details.access_token, &config).await?;

    // Find or create user with platform owner detection for admin OAuth
    let (user_model, was_created) = crate::store::users::UserStore::find_or_create_admin_oauth(
        DB::Conn(&state.db),
        &user_info.email,
        config.platform_owner_email.as_deref(),
    )
    .await?;
    let user: User = user_model.into();

    // Publish signup event if user was just created (admin OAuth flow)
    if was_created {
        use crate::services::events::{Event, EventType};
        use serde_json::json;

        let mut event_builder = Event::builder(EventType::UserSignupSuccess)
            .actor_user_id(&user.id)
            .actor_email(&user_info.email);

        if let Some(org_slug) = &oauth_state.org_slug {
            event_builder = event_builder.org_id(org_slug);
        }

        event_builder = event_builder.detail("provider", json!(provider.as_str()));
        event_builder = event_builder.detail("flow_type", json!("admin"));

        let event = event_builder.build();

        // Fire and forget
        let dispatcher = state.event_dispatcher.clone();
        tokio::spawn(async move {
            if let Err(e) = dispatcher.publish(event).await {
                tracing::error!("Failed to publish signup event: {}", e);
            }
        });
    }

    // Update identity (admin flow always uses platform credentials, so issuing_org_id and issuing_service_id are None)
    IdentityStore::upsert_with_details(
        DB::Conn(&state.db),
        state.encryption.as_ref(),
        &user.id,
        provider.as_str(),
        &user_info.provider_user_id,
        &token_details.access_token,
        token_details.refresh_token.as_deref(),
        token_details.expires_at,
        &token_details.scopes,
        None,
        None,
    )
    .await?;

    // Check if this is a device flow completion - prioritize this over normal web login
    if let Some(ref user_code) = oauth_state.device_user_code {
        // Find the specific device code by user_code
        let device_code =
            DeviceCodeStore::find_pending_by_user_code(DB::Conn(&state.db), user_code).await?;

        if let Some(dc) = device_code {
            // Check if user has MFA enabled
            let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

            if !mfa_enabled {
                // No MFA - authorize the device code immediately
                DeviceCodeStore::authorize(DB::Conn(&state.db), &dc.id, &user.id).await?;
            } else {
                // MFA enabled - store user_id but don't authorize yet
                DeviceCodeStore::set_user_id(DB::Conn(&state.db), &dc.id, &user.id).await?;

                // Redirect to MFA challenge with device flow context
                let preauth_token = state.jwt_service.create_mfa_preauth_token(
                    &user.id,
                    &user.email,
                    user.is_platform_owner,
                    oauth_state.org_slug.as_deref(),
                    None,
                    None,
                )?;

                // Determine redirect URL based on org/service for MFA challenge
                let mfa_redirect_url = if dc.org_slug == "platform"
                    && dc.service_slug == "admin-cli"
                {
                    // Platform admin CLI - redirect to platform admin frontend MFA challenge
                    format!(
                        "{}/callback?mfa_challenge=true&preauth_token={}&device_code_id={}&user_code={}",
                        config.platform_dashboard_base_url, preauth_token, dc.id, dc.user_code
                    )
                } else {
                    // Service-level device flow - redirect to service's MFA challenge page
                    let service = ServiceStore::find_by_org_slug_and_service_slug(
                        DB::Conn(&state.db),
                        &dc.org_slug,
                        &dc.service_slug,
                    )
                    .await?
                    .map(crate::db::models::Service::from);

                    let base_activation_uri = service
                        .and_then(|s| s.device_activation_uri)
                        .ok_or_else(|| {
                            AppError::InternalServerError(
                                "Device activation URI not configured for this service".to_string(),
                            )
                        })?;

                    let mut mfa_url = url::Url::parse(&base_activation_uri).map_err(|_| {
                        AppError::InternalServerError(
                            "Invalid device activation URI configured".to_string(),
                        )
                    })?;

                    mfa_url.set_path("/activate/mfa-challenge");
                    mfa_url
                        .query_pairs_mut()
                        .append_pair("preauth_token", &preauth_token)
                        .append_pair("device_code_id", &dc.id)
                        .append_pair("user_code", &dc.user_code);

                    mfa_url.to_string()
                };

                return Ok(Redirect::to(&mfa_redirect_url).into_response());
            }

            // Device code is now authorized (or pending MFA) - determine success redirect URL
            let redirect_url = if dc.org_slug == "platform" && dc.service_slug == "admin-cli" {
                // Platform admin CLI device flow - redirect to platform admin frontend
                format!(
                    "{}/callback?device_flow_status=success",
                    config.platform_dashboard_base_url
                )
            } else {
                // Service-level device flow - get service's device activation URI
                let service: Option<Service> = ServiceStore::find_by_org_slug_and_service_slug(
                    DB::Conn(&state.db),
                    &dc.org_slug,
                    &dc.service_slug,
                )
                .await?
                .map(|s| s.into());

                let base_activation_uri: String = service
                    .and_then(|s| s.device_activation_uri)
                    .ok_or_else(|| {
                        AppError::InternalServerError(
                            "Device activation URI not configured for this service".to_string(),
                        )
                    })?;

                let mut success_url = url::Url::parse(&base_activation_uri).map_err(|_| {
                    AppError::InternalServerError(
                        "Invalid device activation URI configured".to_string(),
                    )
                })?;

                success_url.set_path("/activate/success");
                success_url
                    .query_pairs_mut()
                    .append_pair("status", "success")
                    .append_pair("device_flow", "true");

                success_url.to_string()
            };

            return Ok(Redirect::to(&redirect_url).into_response());
        }
    }

    // If not a device flow, proceed with normal web login decision logic
    // Check if user has MFA enabled
    let mfa_enabled = is_mfa_enabled(&state.db, &user.id).await?;

    // Load config for redirect URL
    let config = crate::config::Config::from_env()
        .map_err(|e| AppError::InternalServerError(e.to_string()))?;

    if mfa_enabled {
        // User has MFA enabled - create pre-auth token instead of full session
        let preauth_token = state.jwt_service.create_mfa_preauth_token(
            &user.id,
            &user.email,
            user.is_platform_owner,
            oauth_state.org_slug.as_deref(),
            None, // service_slug is always None for admin flows
            None, // saml_state is not used in admin flows
        )?;

        // Redirect with pre-auth token and mfa_required flag
        let redirect_url = format!(
            "{}/callback?preauth_token={}&mfa_required=true",
            config.platform_dashboard_base_url, preauth_token
        );
        return Ok(Redirect::to(&redirect_url).into_response());
    }

    // MFA not enabled - proceed with normal token issuance
    let jwt = if user.is_platform_owner {
        // Create Platform JWT (no org or service claims)
        state
            .jwt_service
            .create_token(&user.id, &user.email, true, None, None)?
    } else if let Some(org_slug) = &oauth_state.org_slug {
        // Check if user is a member of the requested organization
        let membership =
            MembershipStore::find_by_org_slug_and_user(DB::Conn(&state.db), org_slug, &user.id)
                .await?;

        if membership.is_some() {
            // Create Org Management JWT (org claim present, service claim null)
            state
                .jwt_service
                .create_token(&user.id, &user.email, false, Some(org_slug), None)?
        } else {
            // User is not a member - issue basic JWT so they can access signup page
            state
                .jwt_service
                .create_token(&user.id, &user.email, false, None, None)?
        }
    } else {
        // Generic Admin Login (No org_slug provided):
        // Check if the user belongs to any organizations.
        let first_org_slug =
            MembershipStore::get_first_org_slug(DB::Conn(&state.db), &user.id).await?;

        if let Some(ref org_slug) = first_org_slug {
            // User is a member of at least one org. Issue a token for the first one.
            state
                .jwt_service
                .create_token(&user.id, &user.email, false, Some(org_slug), None)?
        } else {
            // User is not a member of any org: Issue a basic JWT to prompt for creation.
            state
                .jwt_service
                .create_token(&user.id, &user.email, false, None, None)?
        }
    };

    // Generate refresh token
    let refresh_token = Uuid::new_v4().to_string();

    // Store session with refresh token
    let token_hash = JwtService::hash_token(&jwt);
    let now = Utc::now();
    let expires_at = now + chrono::Duration::hours(config.jwt_expiration_hours);
    let refresh_expires_at = now + chrono::Duration::days(30);

    SessionStore::create(
        DB::Conn(&state.db),
        &user.id,
        &token_hash,
        expires_at.naive_utc(),
        Some(&refresh_token),
        Some(refresh_expires_at.naive_utc()),
        oauth_state.org_slug.as_deref(),
        None,
        None,
        None,
    )
    .await?;

    // Publish login success event for webhooks (admin login via platform OAuth)
    publish_login_event(
        &state.event_dispatcher,
        &user.id,
        &user.email,
        oauth_state.org_slug.as_deref(),
        None,
        Some(provider.as_str()),
    )
    .await;

    // Check if JSON response is requested (to avoid header overflow in API flows)
    if callback.format.as_ref().map_or(false, |f| f == "json") {
        // Return JSON response instead of redirect for API flows
        use serde_json::json;
        let response_body = json!({
            "access_token": jwt,
            "refresh_token": refresh_token,
            "token_type": "Bearer"
        });
        return Ok(Json(response_body).into_response());
    }

    // Redirect to platform admin frontend with both tokens
    let redirect_url = format!(
        "{}/callback?access_token={}&refresh_token={}",
        config.platform_dashboard_base_url, jwt, refresh_token
    );
    Ok(Redirect::to(&redirect_url).into_response())
}

// Helper functions for admin OAuth

/// Unified OAuth client builder to reduce code duplication.
/// Creates an OAuth2 BasicClient for any provider with the given credentials and callback URI.
fn build_oauth_client(
    provider: Provider,
    client_id: String,
    client_secret: String,
    callback_uri: String,
    config: &crate::config::Config,
) -> Result<oauth2::basic::BasicClient> {
    use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

    let (auth_url, token_url) = match provider {
        Provider::Github => (
            config
                .platform_github_auth_url
                .clone()
                .unwrap_or_else(|| "https://github.com/login/oauth/authorize".to_string()),
            config
                .platform_github_token_url
                .clone()
                .unwrap_or_else(|| "https://github.com/login/oauth/access_token".to_string()),
        ),
        Provider::Google => (
            config
                .platform_google_auth_url
                .clone()
                .unwrap_or_else(|| "https://accounts.google.com/o/oauth2/v2/auth".to_string()),
            config
                .platform_google_token_url
                .clone()
                .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string()),
        ),
        Provider::Microsoft => (
            config
                .platform_microsoft_auth_url
                .clone()
                .unwrap_or_else(|| {
                    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string()
                }),
            config
                .platform_microsoft_token_url
                .clone()
                .unwrap_or_else(|| {
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string()
                }),
        ),
        Provider::Oidc => {
            return Err(AppError::InternalServerError(
                "OIDC not supported in build_oauth_client".to_string(),
            ))
        }
    };

    Ok(BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url.to_string()).map_err(|e| AppError::OAuth(e.to_string()))?,
        Some(TokenUrl::new(token_url.to_string()).map_err(|e| AppError::OAuth(e.to_string()))?),
    )
    .set_redirect_uri(RedirectUrl::new(callback_uri).map_err(|e| AppError::OAuth(e.to_string()))?))
}

fn create_admin_oauth_client(
    config: &crate::config::Config,
    provider: Provider,
) -> Result<oauth2::basic::BasicClient> {
    let (client_id, client_secret) = match provider {
        Provider::Github => {
            let client_id = config.platform_github_client_id.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    format!("GitHub OAuth provider is not configured. Please set PLATFORM_GITHUB_CLIENT_ID and PLATFORM_GITHUB_CLIENT_SECRET environment variables.")
                ))?;
            let client_secret = config.platform_github_client_secret.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    format!("GitHub OAuth provider is not configured. Please set PLATFORM_GITHUB_CLIENT_ID and PLATFORM_GITHUB_CLIENT_SECRET environment variables.")
                ))?;
            (client_id.clone(), client_secret.clone())
        }
        Provider::Google => {
            let client_id = config.platform_google_client_id.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    format!("Google OAuth provider is not configured. Please set PLATFORM_GOOGLE_CLIENT_ID and PLATFORM_GOOGLE_CLIENT_SECRET environment variables.")
                ))?;
            let client_secret = config.platform_google_client_secret.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    format!("Google OAuth provider is not configured. Please set PLATFORM_GOOGLE_CLIENT_ID and PLATFORM_GOOGLE_CLIENT_SECRET environment variables.")
                ))?;
            (client_id.clone(), client_secret.clone())
        }
        Provider::Microsoft => {
            let client_id = config.platform_microsoft_client_id.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    format!("Microsoft OAuth provider is not configured. Please set PLATFORM_MICROSOFT_CLIENT_ID and PLATFORM_MICROSOFT_CLIENT_SECRET environment variables.")
                ))?;
            let client_secret = config.platform_microsoft_client_secret.as_ref()
                .ok_or_else(|| AppError::BadRequest(
                    format!("Microsoft OAuth provider is not configured. Please set PLATFORM_MICROSOFT_CLIENT_ID and PLATFORM_MICROSOFT_CLIENT_SECRET environment variables.")
                ))?;
            (client_id.clone(), client_secret.clone())
        }
        Provider::Oidc => {
            return Err(AppError::BadRequest(
                "OIDC provider not supported for admin login".to_string(),
            ))
        }
    };

    let callback_uri = format!(
        "{}/auth/admin/{}/callback",
        config.base_url,
        provider.as_str()
    );

    build_oauth_client(provider, client_id, client_secret, callback_uri, config)
}

fn get_admin_authorization_url(
    client: &oauth2::basic::BasicClient,
    provider: Provider,
    scopes: Vec<String>,
) -> (String, CsrfToken, String) {
    use oauth2::Scope;

    let scopes_oauth: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();

    // Generate PKCE challenge (only for Microsoft)
    let (pkce_challenge, pkce_verifier) = if provider == Provider::Microsoft {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        (Some(challenge), Some(verifier))
    } else {
        (None, None)
    };

    let mut auth_request = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes_oauth);

    if let Some(challenge) = pkce_challenge {
        auth_request = auth_request.set_pkce_challenge(challenge);
    }

    let (auth_url, csrf_token) = auth_request.url();

    let verifier_secret = pkce_verifier
        .map(|v| v.secret().clone())
        .unwrap_or_default();

    (auth_url.to_string(), csrf_token, verifier_secret)
}

async fn exchange_admin_code(
    client: &oauth2::basic::BasicClient,
    _provider: Provider,
    code: &str,
    pkce_verifier: Option<&str>,
) -> Result<crate::auth::sso::TokenDetails> {
    use oauth2::{AuthorizationCode, TokenResponse};

    let mut token_request = client.exchange_code(AuthorizationCode::new(code.to_string()));

    if let Some(verifier) = pkce_verifier {
        token_request =
            token_request.set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
    }

    let token = token_request
        .request_async(oauth_http_client)
        .await
        .map_err(|e| AppError::OAuth(format!("Token exchange failed: {}", e)))?;

    let expires_at = token
        .expires_in()
        .map(|duration| Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64));

    let scopes = token
        .scopes()
        .map(|scopes| scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    Ok(crate::auth::sso::TokenDetails {
        access_token: token.access_token().secret().clone(),
        refresh_token: token.refresh_token().map(|rt| rt.secret().clone()),
        expires_at,
        scopes,
    })
}

async fn exchange_custom_code(
    client: &oauth2::basic::BasicClient,
    _provider: Provider,
    code: &str,
    pkce_verifier: Option<&str>,
) -> Result<crate::auth::sso::TokenDetails> {
    use oauth2::{AuthorizationCode, TokenResponse};

    let mut token_request = client.exchange_code(AuthorizationCode::new(code.to_string()));

    if let Some(verifier) = pkce_verifier {
        token_request =
            token_request.set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
    }

    let token = token_request
        .request_async(oauth_http_client)
        .await
        .map_err(|e| AppError::OAuth(format!("Token exchange failed: {}", e)))?;

    let expires_at = token
        .expires_in()
        .map(|duration| Utc::now() + chrono::Duration::seconds(duration.as_secs() as i64));

    let scopes = token
        .scopes()
        .map(|scopes| scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    Ok(crate::auth::sso::TokenDetails {
        access_token: token.access_token().secret().clone(),
        refresh_token: token.refresh_token().map(|rt| rt.secret().clone()),
        expires_at,
        scopes,
    })
}

// Helper functions for BYOO (Bring Your Own OAuth)

fn validate_redirect_uri(redirect_uri: &str, service: &crate::db::models::Service) -> Result<()> {
    if let Some(ref allowed_uris_json) = service.redirect_uris {
        let allowed_uris: Vec<String> = serde_json::from_str(allowed_uris_json).map_err(|e| {
            AppError::InternalServerError(format!("Invalid redirect_uris JSON: {}", e))
        })?;

        if !allowed_uris.contains(&redirect_uri.to_string()) {
            return Err(AppError::BadRequest(format!(
                "redirect_uri '{}' is not registered for this service",
                redirect_uri
            )));
        }
    }
    // If no redirect_uris configured, allow any (backward compatibility)
    Ok(())
}

pub fn get_authorization_url_for_client(
    client: &oauth2::basic::BasicClient,
    provider: Provider,
    scopes: Vec<String>,
) -> (String, CsrfToken, String) {
    use oauth2::Scope;

    let scopes_oauth: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();

    // Generate PKCE challenge (only for Microsoft)
    let (pkce_challenge, pkce_verifier) = if provider == Provider::Microsoft {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        (Some(challenge), Some(verifier))
    } else {
        (None, None)
    };

    let mut auth_request = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes_oauth);

    if let Some(challenge) = pkce_challenge {
        auth_request = auth_request.set_pkce_challenge(challenge);
    }

    let (auth_url, csrf_token) = auth_request.url();

    let verifier_secret = pkce_verifier
        .map(|v| v.secret().clone())
        .unwrap_or_default();

    (auth_url.to_string(), csrf_token, verifier_secret)
}

/// Get user info from provider (standalone, not using OAuth client for BYOO isolation)
async fn get_provider_user_info(
    provider: Provider,
    access_token: &str,
    config: &crate::config::Config,
) -> Result<crate::auth::sso::UserInfo> {
    use serde::Deserialize;

    match provider {
        Provider::Github => {
            #[derive(Deserialize)]
            struct GithubUser {
                id: u64,
                email: Option<String>,
                name: Option<String>,
            }

            #[derive(Deserialize)]
            struct GithubEmail {
                email: String,
                primary: bool,
                verified: bool,
            }

            let client = reqwest::Client::new();

            let user: GithubUser = client
                .get(&config.get_github_user_api_url())
                .header("Authorization", format!("Bearer {}", access_token))
                .header("User-Agent", "SSO-Service")
                .send()
                .await
                .map_err(|e| AppError::OAuth(format!("Failed to fetch user: {}", e)))?
                .json()
                .await
                .map_err(|e| AppError::OAuth(format!("Failed to parse user: {}", e)))?;

            let email = if let Some(email) = user.email {
                email
            } else {
                let emails: Vec<GithubEmail> = client
                    .get(&config.get_github_user_emails_api_url())
                    .header("Authorization", format!("Bearer {}", access_token))
                    .header("User-Agent", "SSO-Service")
                    .send()
                    .await
                    .map_err(|e| AppError::OAuth(format!("Failed to fetch emails: {}", e)))?
                    .json()
                    .await
                    .map_err(|e| AppError::OAuth(format!("Failed to parse emails: {}", e)))?;

                emails
                    .into_iter()
                    .find(|e| e.primary && e.verified)
                    .map(|e| e.email)
                    .ok_or_else(|| AppError::OAuth("No verified email found".to_string()))?
            };

            Ok(crate::auth::sso::UserInfo {
                provider_user_id: user.id.to_string(),
                email,
                name: user.name,
            })
        }
        Provider::Google => {
            #[derive(Deserialize)]
            struct GoogleUser {
                id: String,
                email: String,
                name: Option<String>,
            }

            let client = reqwest::Client::new();
            let user: GoogleUser = client
                .get(&config.get_google_user_api_url())
                .header("Authorization", format!("Bearer {}", access_token))
                .send()
                .await
                .map_err(|e| AppError::OAuth(format!("Failed to fetch user: {}", e)))?
                .json()
                .await
                .map_err(|e| AppError::OAuth(format!("Failed to parse user: {}", e)))?;

            Ok(crate::auth::sso::UserInfo {
                provider_user_id: user.id,
                email: user.email,
                name: user.name,
            })
        }
        Provider::Microsoft => {
            #[derive(Deserialize)]
            struct MicrosoftUser {
                id: String,
                #[serde(rename = "userPrincipalName")]
                email: String,
                #[serde(rename = "displayName")]
                name: Option<String>,
            }

            let client = reqwest::Client::new();
            let user: MicrosoftUser = client
                .get(&config.get_microsoft_user_api_url())
                .header("Authorization", format!("Bearer {}", access_token))
                .send()
                .await
                .map_err(|e| AppError::OAuth(format!("Failed to fetch user: {}", e)))?
                .json()
                .await
                .map_err(|e| AppError::OAuth(format!("Failed to parse user: {}", e)))?;

            Ok(crate::auth::sso::UserInfo {
                provider_user_id: user.id,
                email: user.email,
                name: user.name,
            })
        }
        Provider::Oidc => {
            return Err(AppError::BadRequest(
                "OIDC not supported in generic get_provider_user_info".to_string(),
            ))
        }
    }
}

/// Record login event for analytics (via buffered audit actor)
async fn record_login_event(
    audit_actor: &crate::services::audit_actor::AuditHandle,
    user_id: &str,
    service_id: &str,
    provider: Provider,
) {
    use crate::entities::login_events;
    use sea_orm::Set;
    use uuid::Uuid;

    let event_model = login_events::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        user_id: Set(user_id.to_string()),
        service_id: Set(Some(service_id.to_string())),
        provider: Set(provider.as_str().to_string()),
        ..Default::default()
    };

    // Non-blocking: queues to actor, doesn't wait for DB
    audit_actor.log_login(event_model).await;
}

/// Helper function to publish login success event
pub async fn publish_login_event(
    event_dispatcher: &Arc<crate::services::events::EventDispatcher>,
    user_id: &str,
    user_email: &str,
    org_id: Option<&str>,
    service_id: Option<&str>,
    provider: Option<&str>,
) {
    use crate::services::events::{Event, EventType};
    use serde_json::json;

    let mut event_builder = Event::builder(EventType::UserLoginSuccess)
        .actor_user_id(user_id)
        .actor_email(user_email);

    if let Some(org) = org_id {
        event_builder = event_builder.org_id(org);
    }

    if let Some(svc) = service_id {
        event_builder = event_builder.detail("service_id", json!(svc));
    }

    if let Some(prov) = provider {
        event_builder = event_builder.detail("provider", json!(prov));
    }

    let event = event_builder.build();

    // Fire and forget
    let dispatcher = event_dispatcher.clone();
    tokio::spawn(async move {
        if let Err(e) = dispatcher.publish(event).await {
            tracing::error!("Failed to publish login event: {}", e);
        }
    });
}

/// Check if a user has MFA enabled
async fn is_mfa_enabled(pool: &DatabaseConnection, user_id: &str) -> Result<bool> {
    crate::store::totp::TotpStore::is_enabled(DB::Conn(pool), user_id).await
}
