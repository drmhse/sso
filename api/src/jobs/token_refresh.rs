use crate::auth::sso::Provider;
use crate::auth::token_refresher;
use crate::db::models::Identity;
use crate::encryption::EncryptionService;
use chrono::{Duration, Utc};
use sqlx::SqlitePool;

pub struct TokenRefreshJob {
    pool: SqlitePool,
    encryption: Option<EncryptionService>,
}

impl TokenRefreshJob {
    pub fn new(pool: SqlitePool, encryption: Option<EncryptionService>) -> Self {
        Self { pool, encryption }
    }

    pub async fn start(self) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));

        loop {
            interval.tick().await;

            if let Err(e) = self.refresh_expiring_tokens().await {
                tracing::error!("Token refresh job failed: {}", e);
            }
        }
    }

    async fn refresh_expiring_tokens(&self) -> Result<(), Box<dyn std::error::Error>> {
        let threshold = Utc::now() + Duration::hours(1);

        let expiring_identities = sqlx::query_as::<_, Identity>(
            r#"
            SELECT * FROM identities
            WHERE expires_at IS NOT NULL
            AND expires_at < ?
            AND (refresh_token IS NOT NULL OR refresh_token_encrypted IS NOT NULL)
            "#,
        )
        .bind(threshold)
        .fetch_all(&self.pool)
        .await?;

        tracing::info!("Found {} tokens to refresh", expiring_identities.len());

        for identity in expiring_identities {
            match self.refresh_single_token(&identity).await {
                Ok(_) => tracing::info!("Refreshed token for identity: {}", identity.id),
                Err(e) => {
                    tracing::error!("Failed to refresh token for {}: {}", identity.id, e)
                }
            }
        }

        Ok(())
    }

    async fn refresh_single_token(
        &self,
        identity: &Identity,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let provider = Provider::from_str(&identity.provider)
            .map_err(|e| format!("Invalid provider: {}", e))?;

        // 1. Determine which credentials to use
        let (client_id, client_secret) = if let Some(org_id) = &identity.issuing_org_id {
            // Case 1: BYOO Token
            let creds = sqlx::query!(
                "SELECT client_id, client_secret_encrypted FROM organization_oauth_credentials WHERE org_id = ? AND provider = ?",
                org_id,
                identity.provider
            )
            .fetch_optional(&self.pool)
            .await?
            .ok_or("BYOO credentials not found for org")?;

            let secret = self.encryption.as_ref()
                .ok_or("Encryption service unavailable for BYOO secret")?
                .decrypt(&creds.client_secret_encrypted)?;

            (creds.client_id, secret)
        } else {
            // Case 2: Platform Token (Admin or Default)
            let user = sqlx::query!("SELECT is_platform_owner FROM users WHERE id = ?", identity.user_id)
                .fetch_one(&self.pool).await?;

            let config = crate::config::Config::from_env().map_err(|e| e.to_string())?;

            if user.is_platform_owner {
                // Case 2a: Platform Admin Credentials
                match provider {
                    Provider::Google => (config.platform_google_client_id, config.platform_google_client_secret),
                    Provider::Microsoft => (config.platform_microsoft_client_id, config.platform_microsoft_client_secret),
                    Provider::Github => return Err("GitHub admin token refresh not supported".into()),
                }
            } else {
                // Case 2b: Platform Default Credentials
                match provider {
                    Provider::Google => (config.google_client_id, config.google_client_secret),
                    Provider::Microsoft => (config.microsoft_client_id, config.microsoft_client_secret),
                    Provider::Github => return Err("GitHub default token refresh not supported".into()),
                }
            }
        };

        // 2. Get the refresh token
        let refresh_token = if let Some(ref encrypted) = identity.refresh_token_encrypted {
            if let Some(ref enc) = self.encryption { enc.decrypt(encrypted)? } else { return Err("Encryption service not available".into()); }
        } else if let Some(ref token) = identity.refresh_token {
            token.clone()
        } else {
            return Err("No refresh token available".into());
        };

        // 3. Call the appropriate refresh function with the correct credentials
        let new_token = match provider {
            Provider::Microsoft => token_refresher::refresh_microsoft_token(&refresh_token, &client_id, &client_secret).await?,
            Provider::Google => token_refresher::refresh_google_token(&refresh_token, &client_id, &client_secret).await?,
            Provider::Github => return Ok(()), // GitHub refresh tokens are complex/optional, skip for now
        };

        // 4. Update the identity in the database
        if let Some(ref enc) = self.encryption {
            let access_encrypted = enc.encrypt(&new_token.access_token)?;
            let refresh_encrypted = new_token
                .refresh_token
                .as_ref()
                .map(|rt| enc.encrypt(rt))
                .transpose()?;

            sqlx::query(
                r#"
                UPDATE identities
                SET access_token_encrypted = ?,
                    refresh_token_encrypted = COALESCE(?, refresh_token_encrypted),
                    expires_at = ?,
                    last_refreshed_at = datetime('now'),
                    encryption_key_id = ?
                WHERE id = ?
                "#,
            )
            .bind(&access_encrypted)
            .bind(&refresh_encrypted)
            .bind(new_token.expires_at)
            .bind(enc.key_id())
            .bind(&identity.id)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE identities
                SET access_token = ?,
                    refresh_token = COALESCE(?, refresh_token),
                    expires_at = ?,
                    last_refreshed_at = datetime('now')
                WHERE id = ?
                "#,
            )
            .bind(&new_token.access_token)
            .bind(&new_token.refresh_token)
            .bind(new_token.expires_at)
            .bind(&identity.id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }
}
