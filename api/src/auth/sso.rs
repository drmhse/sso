use crate::config::Config;
use crate::error::{AppError, Result};
use crate::services::safe_http::SafeHttpClient;
use chrono::{DateTime, Utc};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Provider {
    Github,
    Google,
    Microsoft,
    Oidc,
    Password,
}

impl Provider {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "github" => Ok(Provider::Github),
            "google" => Ok(Provider::Google),
            "microsoft" => Ok(Provider::Microsoft),
            "oidc" => Ok(Provider::Oidc),
            "password" => Ok(Provider::Password),
            _ => Err(AppError::BadRequest("Invalid provider".to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Github => "github",
            Provider::Google => "google",
            Provider::Microsoft => "microsoft",
            Provider::Oidc => "oidc",
            Provider::Password => "password",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
}

#[derive(Debug)]
pub struct TokenDetails {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub scopes: Vec<String>,
}

pub struct OAuthClient {
    github_client: Option<BasicClient>,
    google_client: Option<BasicClient>,
    microsoft_client: Option<BasicClient>,
}

fn platform_redirect_uri(
    config: &Config,
    provider: Provider,
    configured_redirect_uri: Option<&String>,
) -> String {
    configured_redirect_uri.cloned().unwrap_or_else(|| {
        format!(
            "{}/auth/admin/{}/callback",
            config.base_url,
            provider.as_str()
        )
    })
}

impl OAuthClient {
    pub fn new(config: &Config) -> Result<Self> {
        // Only create GitHub client if credentials are configured
        let github_client = match (
            &config.platform_github_client_id,
            &config.platform_github_client_secret,
        ) {
            (Some(client_id), Some(client_secret)) => {
                let github_auth_url = config
                    .platform_github_auth_url
                    .clone()
                    .unwrap_or_else(|| "https://github.com/login/oauth/authorize".to_string());
                let github_token_url = config
                    .platform_github_token_url
                    .clone()
                    .unwrap_or_else(|| "https://github.com/login/oauth/access_token".to_string());
                let redirect_uri = platform_redirect_uri(
                    config,
                    Provider::Github,
                    config.platform_github_redirect_uri.as_ref(),
                );

                Some(
                    BasicClient::new(
                        ClientId::new(client_id.clone()),
                        Some(ClientSecret::new(client_secret.clone())),
                        AuthUrl::new(github_auth_url)
                            .map_err(|e| AppError::OAuth(e.to_string()))?,
                        Some(
                            TokenUrl::new(github_token_url)
                                .map_err(|e| AppError::OAuth(e.to_string()))?,
                        ),
                    )
                    .set_redirect_uri(
                        RedirectUrl::new(redirect_uri)
                            .map_err(|e| AppError::OAuth(e.to_string()))?,
                    ),
                )
            }
            _ => None,
        };

        // Only create Google client if credentials are configured
        let google_client = match (
            &config.platform_google_client_id,
            &config.platform_google_client_secret,
        ) {
            (Some(client_id), Some(client_secret)) => {
                let google_auth_url = config
                    .platform_google_auth_url
                    .clone()
                    .unwrap_or_else(|| "https://accounts.google.com/o/oauth2/v2/auth".to_string());
                let google_token_url = config
                    .platform_google_token_url
                    .clone()
                    .unwrap_or_else(|| "https://oauth2.googleapis.com/token".to_string());
                let redirect_uri = platform_redirect_uri(
                    config,
                    Provider::Google,
                    config.platform_google_redirect_uri.as_ref(),
                );

                Some(
                    BasicClient::new(
                        ClientId::new(client_id.clone()),
                        Some(ClientSecret::new(client_secret.clone())),
                        AuthUrl::new(google_auth_url)
                            .map_err(|e| AppError::OAuth(e.to_string()))?,
                        Some(
                            TokenUrl::new(google_token_url)
                                .map_err(|e| AppError::OAuth(e.to_string()))?,
                        ),
                    )
                    .set_redirect_uri(
                        RedirectUrl::new(redirect_uri)
                            .map_err(|e| AppError::OAuth(e.to_string()))?,
                    ),
                )
            }
            _ => None,
        };

        // Only create Microsoft client if credentials are configured
        let microsoft_client = match (
            &config.platform_microsoft_client_id,
            &config.platform_microsoft_client_secret,
        ) {
            (Some(client_id), Some(client_secret)) => {
                let microsoft_auth_url =
                    config
                        .platform_microsoft_auth_url
                        .clone()
                        .unwrap_or_else(|| {
                            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                                .to_string()
                        });
                let microsoft_token_url = config
                    .platform_microsoft_token_url
                    .clone()
                    .unwrap_or_else(|| {
                        "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string()
                    });
                let redirect_uri = platform_redirect_uri(
                    config,
                    Provider::Microsoft,
                    config.platform_microsoft_redirect_uri.as_ref(),
                );

                Some(
                    BasicClient::new(
                        ClientId::new(client_id.clone()),
                        Some(ClientSecret::new(client_secret.clone())),
                        AuthUrl::new(microsoft_auth_url)
                            .map_err(|e| AppError::OAuth(e.to_string()))?,
                        Some(
                            TokenUrl::new(microsoft_token_url)
                                .map_err(|e| AppError::OAuth(e.to_string()))?,
                        ),
                    )
                    .set_redirect_uri(
                        RedirectUrl::new(redirect_uri)
                            .map_err(|e| AppError::OAuth(e.to_string()))?,
                    ),
                )
            }
            _ => None,
        };

        Ok(Self {
            github_client,
            google_client,
            microsoft_client,
        })
    }

    pub fn get_client(&self, provider: Provider) -> Option<&BasicClient> {
        match provider {
            Provider::Github => self.github_client.as_ref(),
            Provider::Google => self.google_client.as_ref(),
            Provider::Microsoft => self.microsoft_client.as_ref(),
            Provider::Oidc => None,
            Provider::Password => None,
        }
    }

    #[allow(dead_code)]
    pub fn get_authorization_url(
        &self,
        provider: Provider,
        redirect_uri: Option<&str>,
    ) -> Result<(String, CsrfToken)> {
        let client = self.get_client(provider).ok_or_else(|| {
            AppError::BadRequest(format!(
                "OAuth provider '{}' is not configured",
                provider.as_str()
            ))
        })?;

        let mut auth_request = client.authorize_url(CsrfToken::new_random);

        if let Some(uri) = redirect_uri {
            auth_request = auth_request.set_redirect_uri(std::borrow::Cow::Owned(
                RedirectUrl::new(uri.to_string()).map_err(|e| AppError::OAuth(e.to_string()))?,
            ));
        }

        let (auth_url, csrf_token) = auth_request.url();
        Ok((auth_url.to_string(), csrf_token))
    }

    #[allow(dead_code)]
    pub fn get_authorization_url_with_scopes(
        &self,
        provider: Provider,
        scopes: Vec<String>,
        redirect_uri: Option<&str>,
    ) -> Result<(String, CsrfToken)> {
        let client = self.get_client(provider).ok_or_else(|| {
            AppError::BadRequest(format!(
                "OAuth provider '{}' is not configured",
                provider.as_str()
            ))
        })?;

        let scopes_oauth: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();

        let mut auth_request = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes_oauth);

        if let Some(uri) = redirect_uri {
            auth_request = auth_request.set_redirect_uri(std::borrow::Cow::Owned(
                RedirectUrl::new(uri.to_string()).map_err(|e| AppError::OAuth(e.to_string()))?,
            ));
        }

        let (auth_url, csrf_token) = auth_request.url();

        Ok((auth_url.to_string(), csrf_token))
    }

    pub fn get_authorization_url_with_pkce(
        &self,
        provider: Provider,
        scopes: Vec<String>,
        redirect_uri: Option<&str>,
    ) -> Result<(String, CsrfToken, String)> {
        let client = self.get_client(provider).ok_or_else(|| {
            AppError::BadRequest(format!(
                "OAuth provider '{}' is not configured",
                provider.as_str()
            ))
        })?;

        let scopes_oauth: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();

        // Generate PKCE challenge for all OAuth/OIDC providers.
        let (pkce_challenge, pkce_verifier) = if matches!(
            provider,
            Provider::Github | Provider::Google | Provider::Microsoft | Provider::Oidc
        ) {
            let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
            (Some(challenge), Some(verifier))
        } else {
            (None, None)
        };

        let mut auth_request = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes_oauth);

        if let Some(uri) = redirect_uri {
            auth_request = auth_request.set_redirect_uri(std::borrow::Cow::Owned(
                RedirectUrl::new(uri.to_string()).map_err(|e| AppError::OAuth(e.to_string()))?,
            ));
        }

        if let Some(challenge) = pkce_challenge {
            auth_request = auth_request.set_pkce_challenge(challenge);
        }

        let (auth_url, csrf_token) = auth_request.url();

        let verifier_secret = pkce_verifier
            .map(|v| v.secret().clone())
            .unwrap_or_default();

        Ok((auth_url.to_string(), csrf_token, verifier_secret))
    }

    #[allow(dead_code)]
    pub async fn exchange_code(&self, provider: Provider, code: &str) -> Result<String> {
        let client = self.get_client(provider).ok_or_else(|| {
            AppError::BadRequest(format!(
                "OAuth provider '{}' is not configured",
                provider.as_str()
            ))
        })?;
        let token = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(oauth_http_client)
            .await
            .map_err(|e| AppError::OAuth(format!("Token exchange failed: {}", e)))?;

        Ok(token.access_token().secret().clone())
    }

    pub async fn exchange_code_with_details(
        &self,
        provider: Provider,
        code: &str,
        pkce_verifier: Option<&str>,
    ) -> Result<TokenDetails> {
        let client = self.get_client(provider).ok_or_else(|| {
            AppError::BadRequest(format!(
                "OAuth provider '{}' is not configured",
                provider.as_str()
            ))
        })?;

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

        Ok(TokenDetails {
            access_token: token.access_token().secret().clone(),
            refresh_token: token.refresh_token().map(|rt| rt.secret().clone()),
            expires_at,
            scopes,
        })
    }
}

// Custom HTTP client wrapper for better OAuth error logging and GitHub error detection
pub async fn oauth_http_client(
    request: oauth2::HttpRequest,
) -> std::result::Result<oauth2::HttpResponse, AppError> {
    tracing::debug!("OAuth request: {:?} {}", request.method, request.url);

    let method = reqwest::Method::from_bytes(request.method.as_str().as_bytes())
        .unwrap_or(reqwest::Method::GET);
    let headers = request
        .headers
        .iter()
        .map(|(name, value)| (name.as_str().to_string(), value.as_bytes().to_vec()))
        .collect();
    let safe_client = SafeHttpClient::new()?;
    let response = safe_client
        .request_with_owned_headers(method, request.url.as_str(), request.body, headers)
        .await?;
    let status_code = oauth2::http::StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(oauth2::http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut headers = oauth2::http::HeaderMap::new();
    for (name, value) in response.headers().iter() {
        if let (Ok(name), Ok(value)) = (
            oauth2::http::HeaderName::from_bytes(name.as_str().as_bytes()),
            oauth2::http::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            headers.insert(name, value);
        }
    }
    let body = response
        .bytes()
        .await
        .map_err(|e| AppError::InternalServerError(format!("OAuth response read failed: {}", e)))?
        .to_vec();

    let mut result = Ok(oauth2::HttpResponse {
        status_code,
        headers,
        body,
    });

    // GitHub returns errors with 200 OK status but with JSON containing "error" field
    // We need to detect this and convert it to a proper error response
    if let Ok(ref response) = result {
        tracing::debug!(
            "OAuth response: status={}, body_len={}",
            response.status_code,
            response.body.len()
        );

        let body_str = String::from_utf8_lossy(&response.body);

        if response.status_code.is_success() {
            tracing::debug!("OAuth success response body: {}", body_str);

            // Check if the response body contains an error (GitHub's quirk)
            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&body_str) {
                if let Some(error) = json_value.get("error").and_then(|e| e.as_str()) {
                    let error_description = json_value
                        .get("error_description")
                        .and_then(|d| d.as_str())
                        .unwrap_or(error);

                    tracing::error!(
                        "OAuth provider returned error in success response: error={}, description={}",
                        error,
                        error_description
                    );

                    // Convert to a proper error by returning a 400 status
                    result = Ok(oauth2::HttpResponse {
                        status_code: oauth2::http::StatusCode::BAD_REQUEST,
                        headers: response.headers.clone(),
                        body: response.body.clone(),
                    });
                }
            }
        } else {
            tracing::error!(
                "OAuth error response: status={}, body={}",
                response.status_code,
                body_str
            );
        }
    } else if let Err(e) = &result {
        tracing::error!("OAuth HTTP client error: {:?}", e);
    }

    result
}
