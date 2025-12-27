use crate::entities::email_verification_tokens;
use crate::entities::prelude::EmailVerificationTokens;
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct EmailVerificationStore;

impl EmailVerificationStore {
    /// Find an email verification token by token hash
    pub async fn find_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<email_verification_tokens::Model>> {
        let result = EmailVerificationTokens::find()
            .filter(email_verification_tokens::Column::TokenHash.eq(token_hash))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new email verification token
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        token_hash: &str,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<email_verification_tokens::Model> {
        let new_token = email_verification_tokens::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            token_hash: Set(token_hash.to_string()),
            expires_at: Set(*expires_at),
            used: Set(false),
            ..Default::default()
        };

        let token = new_token.insert(&db).await?;
        Ok(token)
    }

    /// Mark an email verification token as used
    pub async fn mark_as_used(db: DB<'_>, token_hash: &str) -> Result<()> {
        let token = Self::find_by_token_hash(db.clone(), token_hash)
            .await?
            .ok_or_else(|| AppError::NotFound("Token not found".to_string()))?;

        let mut token_active: email_verification_tokens::ActiveModel = token.into();
        token_active.used = Set(true);
        token_active.update(&db).await?;

        Ok(())
    }
}
