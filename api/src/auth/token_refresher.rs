use chrono::{Duration, Utc};
use serde::Deserialize;

#[derive(Debug)]
pub struct RefreshedToken {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<chrono::DateTime<Utc>>,
}

pub async fn refresh_microsoft_token(
    refresh_token: &str,
) -> Result<RefreshedToken, Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct MicrosoftTokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: i64,
    }

    let client = reqwest::Client::new();
    let params = [
        (
            "client_id",
            std::env::var("MICROSOFT_CLIENT_ID").unwrap_or_default(),
        ),
        (
            "client_secret",
            std::env::var("MICROSOFT_CLIENT_SECRET").unwrap_or_default(),
        ),
        ("refresh_token", refresh_token.to_string()),
        ("grant_type", "refresh_token".to_string()),
    ];

    let response: MicrosoftTokenResponse = client
        .post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
        .form(&params)
        .send()
        .await?
        .json()
        .await?;

    let expires_at = Utc::now() + Duration::seconds(response.expires_in);

    Ok(RefreshedToken {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        expires_at: Some(expires_at),
    })
}

pub async fn refresh_google_token(
    refresh_token: &str,
) -> Result<RefreshedToken, Box<dyn std::error::Error>> {
    #[derive(Deserialize)]
    struct GoogleTokenResponse {
        access_token: String,
        expires_in: i64,
    }

    let client = reqwest::Client::new();
    let params = [
        (
            "client_id",
            std::env::var("GOOGLE_CLIENT_ID").unwrap_or_default(),
        ),
        (
            "client_secret",
            std::env::var("GOOGLE_CLIENT_SECRET").unwrap_or_default(),
        ),
        ("refresh_token", refresh_token.to_string()),
        ("grant_type", "refresh_token".to_string()),
    ];

    let response: GoogleTokenResponse = client
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await?
        .json()
        .await?;

    let expires_at = Utc::now() + Duration::seconds(response.expires_in);

    Ok(RefreshedToken {
        access_token: response.access_token,
        refresh_token: None,
        expires_at: Some(expires_at),
    })
}
