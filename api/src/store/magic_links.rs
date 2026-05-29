use crate::entities::{magic_link_tokens, prelude::MagicLinkTokens};
use crate::error::Result;
use crate::store::DB;
use chrono::{Duration, Utc};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use sha2::{Digest, Sha256};

pub struct MagicLinksStore;

impl MagicLinksStore {
    /// Create a new magic link token
    /// Returns the plaintext token that should be sent in the email
    pub async fn create(
        db: DB<'_>,
        email: &str,
        user_id: Option<&str>,
        context: &str,
    ) -> Result<String> {
        // Generate a secure random token (32 bytes = 64 hex chars)
        let token_bytes = rand::random::<[u8; 32]>();
        let token = hex::encode(token_bytes);

        // Hash the token for storage (SHA256)
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        // Token expires in 15 minutes
        let expires_at = (Utc::now() + Duration::minutes(15)).naive_utc();

        let magic_link = magic_link_tokens::ActiveModel {
            token_hash: Set(token_hash),
            user_id: Set(user_id.map(|id| id.to_string())),
            email: Set(email.to_string()),
            context: Set(context.to_string()),
            created_at: Set(Utc::now().naive_utc()),
            expires_at: Set(expires_at),
        };

        magic_link.insert(&db).await?;

        // Return the plaintext token to be sent in email
        Ok(token)
    }

    /// Find a magic link token by its hash
    pub async fn find_by_token(
        db: DB<'_>,
        token: &str,
    ) -> Result<Option<magic_link_tokens::Model>> {
        // Hash the provided token
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let magic_link = MagicLinkTokens::find()
            .filter(magic_link_tokens::Column::TokenHash.eq(&token_hash))
            .one(&db)
            .await?;

        Ok(magic_link)
    }

    /// Delete a magic link token (one-time use)
    pub async fn delete(db: DB<'_>, token: &str) -> Result<bool> {
        // Hash the provided token
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let token_hash = hex::encode(hasher.finalize());

        let result = MagicLinkTokens::delete_many()
            .filter(magic_link_tokens::Column::TokenHash.eq(&token_hash))
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    /// Delete a magic link token by hash directly
    pub async fn delete_by_hash(db: DB<'_>, token_hash: &str) -> Result<bool> {
        let result = MagicLinkTokens::delete_many()
            .filter(magic_link_tokens::Column::TokenHash.eq(token_hash))
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    /// Clean up expired magic link tokens (for background job)
    pub async fn cleanup_expired(db: DB<'_>) -> Result<u64> {
        let now = Utc::now().naive_utc();

        let result = MagicLinkTokens::delete_many()
            .filter(magic_link_tokens::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Find all pending magic links for an email (for debugging/admin purposes)
    pub async fn find_by_email(db: DB<'_>, email: &str) -> Result<Vec<magic_link_tokens::Model>> {
        let tokens = MagicLinkTokens::find()
            .filter(magic_link_tokens::Column::Email.eq(email))
            .all(&db)
            .await?;

        Ok(tokens)
    }
}
