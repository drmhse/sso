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
        .bind(&threshold)
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

        // Decrypt refresh token if encrypted
        let refresh_token = if let Some(ref encrypted) = identity.refresh_token_encrypted {
            if let Some(ref enc) = self.encryption {
                enc.decrypt(encrypted)?
            } else {
                return Err("Encryption service not available".into());
            }
        } else if let Some(ref token) = identity.refresh_token {
            token.clone()
        } else {
            return Err("No refresh token available".into());
        };

        // Call provider refresh endpoint using centralized module
        let new_token = match provider {
            Provider::Microsoft => token_refresher::refresh_microsoft_token(&refresh_token).await?,
            Provider::Google => token_refresher::refresh_google_token(&refresh_token).await?,
            Provider::Github => return Ok(()),
        };

        // Encrypt new tokens if encryption is enabled
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
            .bind(&new_token.expires_at)
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
            .bind(&new_token.expires_at)
            .bind(&identity.id)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }
}
