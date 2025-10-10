use crate::config::Config;
use crate::error::{AppError, Result};
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
}

impl Provider {
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "github" => Ok(Provider::Github),
            "google" => Ok(Provider::Google),
            "microsoft" => Ok(Provider::Microsoft),
            _ => Err(AppError::BadRequest("Invalid provider".to_string())),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Provider::Github => "github",
            Provider::Google => "google",
            Provider::Microsoft => "microsoft",
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
    github_client: BasicClient,
    google_client: BasicClient,
    microsoft_client: BasicClient,
}

impl OAuthClient {
    pub fn new(config: &Config) -> Result<Self> {
        let github_client = BasicClient::new(
            ClientId::new(config.github_client_id.clone()),
            Some(ClientSecret::new(config.github_client_secret.clone())),
            AuthUrl::new("https://github.com/login/oauth/authorize".to_string())
                .map_err(|e| AppError::OAuth(e.to_string()))?,
            Some(
                TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
                    .map_err(|e| AppError::OAuth(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.github_redirect_uri.clone())
                .map_err(|e| AppError::OAuth(e.to_string()))?,
        );

        let google_client = BasicClient::new(
            ClientId::new(config.google_client_id.clone()),
            Some(ClientSecret::new(config.google_client_secret.clone())),
            AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
                .map_err(|e| AppError::OAuth(e.to_string()))?,
            Some(
                TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                    .map_err(|e| AppError::OAuth(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.google_redirect_uri.clone())
                .map_err(|e| AppError::OAuth(e.to_string()))?,
        );

        let microsoft_client = BasicClient::new(
            ClientId::new(config.microsoft_client_id.clone()),
            Some(ClientSecret::new(config.microsoft_client_secret.clone())),
            AuthUrl::new(
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".to_string(),
            )
            .map_err(|e| AppError::OAuth(e.to_string()))?,
            Some(
                TokenUrl::new(
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string(),
                )
                .map_err(|e| AppError::OAuth(e.to_string()))?,
            ),
        )
        .set_redirect_uri(
            RedirectUrl::new(config.microsoft_redirect_uri.clone())
                .map_err(|e| AppError::OAuth(e.to_string()))?,
        );

        Ok(Self {
            github_client,
            google_client,
            microsoft_client,
        })
    }

    pub fn get_client(&self, provider: Provider) -> &BasicClient {
        match provider {
            Provider::Github => &self.github_client,
            Provider::Google => &self.google_client,
            Provider::Microsoft => &self.microsoft_client,
        }
    }

    #[allow(dead_code)]
    pub fn get_authorization_url(&self, provider: Provider) -> (String, CsrfToken) {
        let client = self.get_client(provider);
        let (auth_url, csrf_token) = client.authorize_url(CsrfToken::new_random).url();
        (auth_url.to_string(), csrf_token)
    }

    #[allow(dead_code)]
    pub fn get_authorization_url_with_scopes(
        &self,
        provider: Provider,
        scopes: Vec<String>,
    ) -> (String, CsrfToken) {
        let client = self.get_client(provider);

        let scopes_oauth: Vec<Scope> = scopes.into_iter().map(Scope::new).collect();

        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(scopes_oauth)
            .url();

        (auth_url.to_string(), csrf_token)
    }

    pub fn get_authorization_url_with_pkce(
        &self,
        provider: Provider,
        scopes: Vec<String>,
    ) -> (String, CsrfToken, String) {
        let client = self.get_client(provider);

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

    #[allow(dead_code)]
    pub async fn exchange_code(&self, provider: Provider, code: &str) -> Result<String> {
        let client = self.get_client(provider);
        let token = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(oauth2::reqwest::async_http_client)
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
        let client = self.get_client(provider);

        let mut token_request = client.exchange_code(AuthorizationCode::new(code.to_string()));

        if let Some(verifier) = pkce_verifier {
            token_request =
                token_request.set_pkce_verifier(PkceCodeVerifier::new(verifier.to_string()));
        }

        let token = token_request
            .request_async(oauth2::reqwest::async_http_client)
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

    pub async fn get_user_info(&self, provider: Provider, access_token: &str) -> Result<UserInfo> {
        match provider {
            Provider::Github => self.get_github_user_info(access_token).await,
            Provider::Google => self.get_google_user_info(access_token).await,
            Provider::Microsoft => self.get_microsoft_user_info(access_token).await,
        }
    }

    async fn get_github_user_info(&self, access_token: &str) -> Result<UserInfo> {
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
            .get("https://api.github.com/user")
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
            // Fetch emails separately if not in user object
            let emails: Vec<GithubEmail> = client
                .get("https://api.github.com/user/emails")
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

        Ok(UserInfo {
            provider_user_id: user.id.to_string(),
            email,
            name: user.name,
        })
    }

    async fn get_google_user_info(&self, access_token: &str) -> Result<UserInfo> {
        #[derive(Deserialize)]
        struct GoogleUser {
            id: String,
            email: String,
            name: Option<String>,
        }

        let client = reqwest::Client::new();
        let user: GoogleUser = client
            .get("https://www.googleapis.com/oauth2/v2/userinfo")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to fetch user: {}", e)))?
            .json()
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to parse user: {}", e)))?;

        Ok(UserInfo {
            provider_user_id: user.id,
            email: user.email,
            name: user.name,
        })
    }

    async fn get_microsoft_user_info(&self, access_token: &str) -> Result<UserInfo> {
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
            .get("https://graph.microsoft.com/v1.0/me")
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to fetch user: {}", e)))?
            .json()
            .await
            .map_err(|e| AppError::OAuth(format!("Failed to parse user: {}", e)))?;

        Ok(UserInfo {
            provider_user_id: user.id,
            email: user.email,
            name: user.name,
        })
    }
}
