use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::services::safe_http::{SafeHttpClient, MAX_OAUTH_RESPONSE_BYTES};

#[derive(Debug)]
pub struct RefreshedToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

/// OAuth error response structure (common across providers)
#[derive(Deserialize, Debug)]
struct OAuthErrorResponse {
    error: String,
    error_description: Option<String>,
}

pub async fn refresh_microsoft_token(
    refresh_token: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<RefreshedToken, Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct MicrosoftTokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }

    let client = SafeHttpClient::new()?;
    let params = [
        ("client_id".to_string(), client_id.to_string()),
        ("client_secret".to_string(), client_secret.to_string()),
        ("refresh_token".to_string(), refresh_token.to_string()),
        ("grant_type".to_string(), "refresh_token".to_string()),
    ];

    let http_response = client
        .post_form(
            "https://login.microsoftonline.com/common/oauth2/v2.0/token",
            &params,
        )
        .await?;
    let (status, body) =
        SafeHttpClient::read_body_limited(http_response, MAX_OAUTH_RESPONSE_BYTES).await?;

    if !status.is_success() {
        // Try to parse as OAuth error response
        if let Ok(error_resp) = serde_json::from_slice::<OAuthErrorResponse>(&body) {
            let error_msg = match error_resp.error_description {
                Some(desc) => format!("Microsoft OAuth error: {} - {}", error_resp.error, desc),
                None => format!("Microsoft OAuth error: {}", error_resp.error),
            };
            return Err(error_msg.into());
        }
        return Err(format!("Microsoft token refresh failed with status {}", status).into());
    }

    let response: MicrosoftTokenResponse = serde_json::from_slice(&body)
        .map_err(|e| format!("Failed to parse Microsoft token response: {e}"))?;

    let expires_at = Utc::now() + Duration::seconds(response.expires_in);

    Ok(RefreshedToken {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        expires_at: Some(expires_at),
    })
}

pub async fn refresh_google_token(
    refresh_token: &str,
    client_id: &str,
    client_secret: &str,
    token_url: Option<&str>,
) -> Result<RefreshedToken, Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct GoogleTokenResponse {
        access_token: String,
        expires_in: i64,
    }

    let client = SafeHttpClient::new()?;
    let params = [
        ("client_id".to_string(), client_id.to_string()),
        ("client_secret".to_string(), client_secret.to_string()),
        ("refresh_token".to_string(), refresh_token.to_string()),
        ("grant_type".to_string(), "refresh_token".to_string()),
    ];

    let google_token_url = token_url.unwrap_or("https://oauth2.googleapis.com/token");

    let http_response = client.post_form(google_token_url, &params).await?;
    let (status, body) =
        SafeHttpClient::read_body_limited(http_response, MAX_OAUTH_RESPONSE_BYTES).await?;

    if !status.is_success() {
        // Try to parse as OAuth error response
        if let Ok(error_resp) = serde_json::from_slice::<OAuthErrorResponse>(&body) {
            let error_msg = match error_resp.error_description {
                Some(desc) => format!("Google OAuth error: {} - {}", error_resp.error, desc),
                None => format!("Google OAuth error: {}", error_resp.error),
            };
            return Err(error_msg.into());
        }
        return Err(format!("Google token refresh failed with status {}", status).into());
    }

    let response: GoogleTokenResponse = serde_json::from_slice(&body)
        .map_err(|e| format!("Failed to parse Google token response: {e}"))?;

    let expires_at = Utc::now() + Duration::seconds(response.expires_in);

    Ok(RefreshedToken {
        access_token: response.access_token,
        refresh_token: None,
        expires_at: Some(expires_at),
    })
}
