use crate::entities::{prelude::ScimTokens, scim_tokens};
use crate::error::Result;
use crate::store::DB;
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub struct ScimTokenStore;

impl ScimTokenStore {
    /// Generate a new SCIM token
    /// Returns (full_token, prefix, hash)
    pub fn generate() -> (String, String, String) {
        let random_part = Uuid::new_v4().to_string().replace('-', "");
        let full_token = format!("scim_{}", random_part);
        let prefix = full_token.chars().take(8).collect::<String>();
        let hash = Self::hash_token(&full_token);

        (full_token, prefix, hash)
    }

    /// Hash a SCIM token using SHA256
    pub fn hash_token(token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Create a new SCIM token
    pub async fn create(
        db: DB<'_>,
        org_id: &str,
        name: &str,
        token_hash: &str,
        prefix: &str,
        created_by: &str,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<scim_tokens::Model> {
        let token = scim_tokens::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            org_id: Set(org_id.to_string()),
            name: Set(name.to_string()),
            token_hash: Set(token_hash.to_string()),
            prefix: Set(prefix.to_string()),
            active: Set(true),
            expires_at: Set(expires_at),
            last_used_at: Set(None),
            created_by: Set(created_by.to_string()),
            created_at: Set(Utc::now().naive_utc()),
        };

        let result = token.insert(&db).await?;
        Ok(result)
    }

    /// Find a SCIM token by hash
    pub async fn find_by_hash(db: DB<'_>, token_hash: &str) -> Result<Option<scim_tokens::Model>> {
        let token = ScimTokens::find()
            .filter(scim_tokens::Column::TokenHash.eq(token_hash))
            .one(&db)
            .await?;

        Ok(token)
    }

    /// List all SCIM tokens for an organization
    pub async fn list_by_org(db: DB<'_>, org_id: &str) -> Result<Vec<scim_tokens::Model>> {
        let tokens = ScimTokens::find()
            .filter(scim_tokens::Column::OrgId.eq(org_id))
            .all(&db)
            .await?;

        Ok(tokens)
    }

    /// Update last_used_at timestamp
    pub async fn update_last_used(db: DB<'_>, token_id: &str) -> Result<()> {
        let token = ScimTokens::find()
            .filter(scim_tokens::Column::Id.eq(token_id))
            .one(&db)
            .await?;

        if let Some(token) = token {
            let mut active: scim_tokens::ActiveModel = token.into();
            active.last_used_at = Set(Some(Utc::now().naive_utc()));
            active.update(&db).await?;
        }

        Ok(())
    }

    /// Revoke a SCIM token (set active = false)
    pub async fn revoke(db: DB<'_>, token_id: &str) -> Result<()> {
        let token = ScimTokens::find()
            .filter(scim_tokens::Column::Id.eq(token_id))
            .one(&db)
            .await?;

        if let Some(token) = token {
            let mut active: scim_tokens::ActiveModel = token.into();
            active.active = Set(false);
            active.update(&db).await?;
        }

        Ok(())
    }

    /// Delete a SCIM token permanently
    pub async fn delete(db: DB<'_>, token_id: &str) -> Result<()> {
        let token = ScimTokens::find()
            .filter(scim_tokens::Column::Id.eq(token_id))
            .one(&db)
            .await?;

        if let Some(token) = token {
            let active: scim_tokens::ActiveModel = token.into();
            active.delete(&db).await?;
        }

        Ok(())
    }

    /// Verify a SCIM token is valid (active and not expired)
    pub async fn verify(db: DB<'_>, token: &str) -> Result<Option<scim_tokens::Model>> {
        let token_hash = Self::hash_token(token);
        let scim_token = Self::find_by_hash(db, &token_hash).await?;

        if let Some(ref t) = scim_token {
            // Check if active
            if !t.active {
                return Ok(None);
            }

            // Check if expired
            if let Some(expires_at) = t.expires_at {
                let expires = chrono::DateTime::<Utc>::from_naive_utc_and_offset(expires_at, Utc);
                if expires < Utc::now() {
                    return Ok(None);
                }
            }
        }

        Ok(scim_token)
    }
}
