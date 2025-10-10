use crate::auth::jwt::Claims;
use crate::auth::sso::Provider;
use crate::db::models::Identity;
use crate::error::{AppError, Result};
use crate::handlers::auth::AppState;
use axum::{
    extract::{Extension, Path, State},
    Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Debug, Serialize)]
pub struct ProviderTokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<String>,
    pub scopes: Vec<String>,
    pub provider: String,
}

pub async fn get_provider_token(
    State(state): State<AppState>,
    Path(provider_str): Path<String>,
    Extension(claims): Extension<Claims>,
) -> Result<Json<ProviderTokenResponse>> {
    let provider = Provider::from_str(&provider_str)?;

    // 1. Verify service is authorized to access this provider
    let grant_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM provider_token_grants
         WHERE service_id = (SELECT id FROM services WHERE client_id = ?)
         AND provider = ?",
    )
    .bind(&claims.service)
    .bind(provider.as_str())
    .fetch_one(&state.pool)
    .await?;

    if grant_count == 0 {
        return Err(AppError::Forbidden(format!(
            "Service not authorized to access {} tokens",
            provider.as_str()
        )));
    }

    // 2. Get user's identity for this provider
    let identity = sqlx::query_as::<_, Identity>(
        "SELECT * FROM identities WHERE user_id = ? AND provider = ?",
    )
    .bind(&claims.sub)
    .bind(provider.as_str())
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| {
        AppError::NotFound(format!(
            "User has not authenticated with {}",
            provider.as_str()
        ))
    })?;

    // 3. Check if token is expired or about to expire (< 5 minutes)
    if let Some(expires_at) = &identity.expires_at {
        let now = Utc::now();
        if *expires_at < now + Duration::minutes(5) {
            // Token expired or expiring soon - refresh it
            let refreshed_identity = refresh_provider_token_with_lock(&state, &identity).await?;
            return Ok(Json(ProviderTokenResponse {
                access_token: refreshed_identity.access_token.unwrap_or_default(),
                refresh_token: refreshed_identity.refresh_token,
                expires_at: refreshed_identity.expires_at.map(|dt| dt.to_rfc3339()),
                scopes: parse_scopes(&refreshed_identity.scopes),
                provider: provider.as_str().to_string(),
            }));
        }
    }

    // 4. Return existing token
    Ok(Json(ProviderTokenResponse {
        access_token: identity.access_token.unwrap_or_default(),
        refresh_token: identity.refresh_token.clone(),
        expires_at: identity.expires_at.map(|dt| dt.to_rfc3339()),
        scopes: parse_scopes(&identity.scopes),
        provider: provider.as_str().to_string(),
    }))
}

async fn refresh_provider_token_with_lock(
    state: &AppState,
    identity: &Identity,
) -> Result<Identity> {
    let lock_timeout = 30;

    // Try to acquire lock
    let lock_acquired = acquire_refresh_lock(&state.pool, &identity.user_id, lock_timeout).await?;

    if !lock_acquired {
        // Another process is already refreshing - wait and retry
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        // Fetch updated identity (should have new token now)
        let updated_identity =
            sqlx::query_as::<_, Identity>("SELECT * FROM identities WHERE id = ?")
                .bind(&identity.id)
                .fetch_one(&state.pool)
                .await?;

        return Ok(updated_identity);
    }

    // We have the lock - proceed with refresh
    let result = refresh_provider_token(state, identity).await;

    // Always release lock
    let _ = release_refresh_lock(&state.pool, &identity.user_id).await;

    result
}

async fn refresh_provider_token(state: &AppState, identity: &Identity) -> Result<Identity> {
    let provider = Provider::from_str(&identity.provider)?;

    let refresh_token = identity
        .refresh_token
        .as_ref()
        .ok_or_else(|| AppError::OAuth("No refresh token available".to_string()))?;

    // Call provider's token refresh endpoint
    let new_token = match provider {
        Provider::Github => {
            return Err(AppError::OAuth(
                "GitHub tokens do not support refresh".to_string(),
            ));
        }
        Provider::Microsoft => refresh_microsoft_token(refresh_token).await?,
        Provider::Google => refresh_google_token(refresh_token).await?,
    };

    // Update identity in database
    let updated_identity = sqlx::query_as::<_, Identity>(
        r#"
        UPDATE identities
        SET access_token = ?,
            refresh_token = COALESCE(?, refresh_token),
            expires_at = ?,
            last_refreshed_at = datetime('now')
        WHERE id = ?
        RETURNING *
        "#,
    )
    .bind(&new_token.access_token)
    .bind(&new_token.refresh_token)
    .bind(&new_token.expires_at)
    .bind(&identity.id)
    .fetch_one(&state.pool)
    .await?;

    Ok(updated_identity)
}

#[derive(Debug)]
struct RefreshedToken {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<chrono::DateTime<Utc>>,
}

async fn refresh_microsoft_token(refresh_token: &str) -> Result<RefreshedToken> {
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
        .await
        .map_err(|e| AppError::OAuth(format!("Token refresh failed: {}", e)))?
        .json()
        .await
        .map_err(|e| AppError::OAuth(format!("Failed to parse token response: {}", e)))?;

    let expires_at = Utc::now() + Duration::seconds(response.expires_in);

    Ok(RefreshedToken {
        access_token: response.access_token,
        refresh_token: response.refresh_token,
        expires_at: Some(expires_at),
    })
}

async fn refresh_google_token(refresh_token: &str) -> Result<RefreshedToken> {
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
        .await
        .map_err(|e| AppError::OAuth(format!("Token refresh failed: {}", e)))?
        .json()
        .await
        .map_err(|e| AppError::OAuth(format!("Failed to parse token response: {}", e)))?;

    let expires_at = Utc::now() + Duration::seconds(response.expires_in);

    Ok(RefreshedToken {
        access_token: response.access_token,
        refresh_token: None,
        expires_at: Some(expires_at),
    })
}

fn parse_scopes(scopes_json: &Option<String>) -> Vec<String> {
    scopes_json
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

async fn acquire_refresh_lock(
    pool: &SqlitePool,
    user_id: &str,
    timeout_seconds: i64,
) -> Result<bool> {
    let now = Utc::now();
    let expires_at = now + Duration::seconds(timeout_seconds);

    // Clean up expired locks first
    sqlx::query("DELETE FROM token_refresh_locks WHERE expires_at < datetime('now')")
        .execute(pool)
        .await?;

    // Try to insert lock
    let result = sqlx::query(
        "INSERT OR IGNORE INTO token_refresh_locks (user_id, acquired_at, expires_at)
         VALUES (?, ?, ?)",
    )
    .bind(user_id)
    .bind(&now)
    .bind(&expires_at)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

async fn release_refresh_lock(pool: &SqlitePool, user_id: &str) -> Result<()> {
    sqlx::query("DELETE FROM token_refresh_locks WHERE user_id = ?")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}
