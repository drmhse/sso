use crate::entities::password_reset_tokens;
use crate::entities::prelude::PasswordResetTokens;
use crate::error::Result;
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct PasswordResetStore;

impl PasswordResetStore {
    /// Find a password reset token by token hash
    pub async fn find_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<password_reset_tokens::Model>> {
        let result = PasswordResetTokens::find()
            .filter(password_reset_tokens::Column::TokenHash.eq(token_hash))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new password reset token
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        token_hash: &str,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<password_reset_tokens::Model> {
        let new_token = password_reset_tokens::ActiveModel {
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

    /// Mark a password reset token as used
    pub async fn mark_as_used(db: DB<'_>, token_hash: &str) -> Result<bool> {
        let result = PasswordResetTokens::update_many()
            .filter(password_reset_tokens::Column::TokenHash.eq(token_hash))
            .filter(password_reset_tokens::Column::Used.eq(false))
            .col_expr(
                password_reset_tokens::Column::Used,
                sea_orm::sea_query::Expr::value(true),
            )
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }
}
