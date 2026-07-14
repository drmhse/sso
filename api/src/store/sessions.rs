use crate::entities::prelude::Sessions;
use crate::entities::sessions;
use crate::error::{AppError, Result};
use crate::store::DB;
use chrono::NaiveDateTime;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct SessionStore;

impl SessionStore {
    /// Find a session by ID
    pub async fn find_by_id(db: DB<'_>, session_id: &str) -> Result<Option<sessions::Model>> {
        let result = Sessions::find()
            .filter(sessions::Column::Id.eq(session_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a session by token hash
    pub async fn find_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<sessions::Model>> {
        let result = Sessions::find()
            .filter(sessions::Column::TokenHash.eq(token_hash))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a valid (non-expired) session by token hash
    pub async fn find_valid_by_token_hash(
        db: DB<'_>,
        token_hash: &str,
    ) -> Result<Option<sessions::Model>> {
        let now = chrono::Utc::now().naive_utc();

        let result = Sessions::find()
            .filter(sessions::Column::TokenHash.eq(token_hash))
            .filter(sessions::Column::ExpiresAt.gt(now))
            .one(&db)
            .await?;

        Ok(result)
    }

    /// Find a session by refresh token
    pub async fn find_by_refresh_token(
        db: DB<'_>,
        refresh_token: &str,
    ) -> Result<Option<sessions::Model>> {
        let result = Sessions::find()
            .filter(sessions::Column::RefreshToken.eq(refresh_token))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new session
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        token_hash: &str,
        expires_at: NaiveDateTime,
        refresh_token: Option<&str>,
        refresh_token_expires_at: Option<NaiveDateTime>,
        org_slug: Option<&str>,
        service_id: Option<&str>,
        resource: Option<&str>,
        user_agent: Option<&str>,
        ip_address: Option<&str>,
    ) -> Result<sessions::Model> {
        let new_session = sessions::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            token_hash: Set(token_hash.to_string()),
            expires_at: Set(expires_at),
            refresh_token: Set(refresh_token.map(|s| s.to_string())),
            refresh_token_expires_at: Set(refresh_token_expires_at),
            org_slug: Set(org_slug.map(|s| s.to_string())),
            service_id: Set(service_id.map(|s| s.to_string())),
            resource: Set(resource.map(|s| s.to_string())),
            user_agent: Set(user_agent.map(|s| s.to_string())),
            ip_address: Set(ip_address.map(|s| s.to_string())),
            ..Default::default()
        };

        let session = new_session;
        let db_clone = db.clone();

        let session = crate::error::with_deadlock_retry("create_session", 10, || {
            let session_am = session.clone();
            let db = &db_clone;
            async move { session_am.insert(db).await }
        })
        .await?;

        Ok(session)
    }

    /// Delete a session
    pub async fn delete(db: DB<'_>, session_id: &str) -> Result<()> {
        let session = Self::find_by_id(db.clone(), session_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Session not found".to_string()))?;

        let session_active: sessions::ActiveModel = session.into();
        session_active.delete(&db).await?;

        Ok(())
    }

    /// Delete session by token hash
    pub async fn delete_by_token_hash(db: DB<'_>, token_hash: &str) -> Result<()> {
        if let Some(session) = Self::find_by_token_hash(db.clone(), token_hash).await? {
            let session_active: sessions::ActiveModel = session.into();
            session_active.delete(&db).await?;
        }

        Ok(())
    }

    /// Delete all sessions for a user
    pub async fn delete_all_for_user(db: DB<'_>, user_id: &str) -> Result<u64> {
        let result = Sessions::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Delete all sessions for a user in a specific service
    pub async fn delete_user_service_sessions(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
    ) -> Result<u64> {
        let result = Sessions::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(sessions::Column::ServiceId.eq(service_id))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Delete sessions scoped to an organization slug or one of its services.
    pub async fn delete_user_org_scoped_sessions(
        db: DB<'_>,
        user_id: &str,
        org_slug: &str,
        service_ids: &[String],
    ) -> Result<u64> {
        use sea_orm::Condition;

        let mut scope = Condition::any().add(sessions::Column::OrgSlug.eq(org_slug));
        if !service_ids.is_empty() {
            scope = scope.add(sessions::Column::ServiceId.is_in(service_ids.iter().cloned()));
        }

        let result = Sessions::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(scope)
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Delete expired sessions
    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        let now = chrono::Utc::now().naive_utc();

        let result = Sessions::delete_many()
            .filter(sessions::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// List sessions for a user
    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<sessions::Model>> {
        let sessions = Sessions::find()
            .filter(sessions::Column::UserId.eq(user_id))
            .all(&db)
            .await?;

        Ok(sessions)
    }

    /// Count active (non-expired) sessions for a user
    pub async fn count_active_by_user(db: DB<'_>, user_id: &str) -> Result<u64> {
        use sea_orm::PaginatorTrait;

        let now = chrono::Utc::now().naive_utc();

        let count = Sessions::find()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(sessions::Column::ExpiresAt.gt(now))
            .count(&db)
            .await?;

        Ok(count)
    }

    /// Update session tokens for token rotation
    pub async fn update_tokens(
        db: DB<'_>,
        session_id: &str,
        current_refresh_token: &str,
        new_token_hash: &str,
        new_expires_at: NaiveDateTime,
        new_refresh_token: &str,
        new_refresh_expires_at: NaiveDateTime,
    ) -> Result<bool> {
        let result = Sessions::update_many()
            .filter(sessions::Column::Id.eq(session_id))
            .filter(sessions::Column::RefreshToken.eq(current_refresh_token))
            .col_expr(
                sessions::Column::TokenHash,
                sea_orm::sea_query::Expr::value(new_token_hash),
            )
            .col_expr(
                sessions::Column::ExpiresAt,
                sea_orm::sea_query::Expr::value(new_expires_at),
            )
            .col_expr(
                sessions::Column::RefreshToken,
                sea_orm::sea_query::Expr::value(new_refresh_token),
            )
            .col_expr(
                sessions::Column::RefreshTokenExpiresAt,
                sea_orm::sea_query::Expr::value(new_refresh_expires_at),
            )
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    /// Delete all sessions for a user except the current session (for security after password change)
    pub async fn delete_all_except_current(
        db: DB<'_>,
        user_id: &str,
        current_session_id: &str,
    ) -> Result<u64> {
        let result = Sessions::delete_many()
            .filter(sessions::Column::UserId.eq(user_id))
            .filter(sessions::Column::Id.ne(current_session_id))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}
