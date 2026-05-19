use crate::entities::prelude::ProviderTokenRequests;
use crate::entities::provider_token_requests;
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct ProviderTokenRequestStore;

impl ProviderTokenRequestStore {
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        provider: &str,
        connected_account_id: Option<&str>,
        requested_scopes: &[String],
        redirect_uri: &str,
        client_state: Option<&str>,
    ) -> Result<provider_token_requests::Model> {
        let requested_scopes_json = serde_json::to_string(requested_scopes)
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;
        let now = chrono::Utc::now();
        let active = provider_token_requests::ActiveModel {
            state: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            service_id: Set(service_id.to_string()),
            provider: Set(provider.to_string()),
            connected_account_id: Set(connected_account_id.map(str::to_string)),
            requested_scopes: Set(requested_scopes_json),
            redirect_uri: Set(redirect_uri.to_string()),
            client_state: Set(client_state.map(str::to_string)),
            status: Set("pending".to_string()),
            created_at: Set(now.naive_utc()),
            expires_at: Set((now + chrono::Duration::minutes(15)).naive_utc()),
            completed_at: Set(None),
        };
        Ok(active.insert(&db).await?)
    }

    pub async fn find_active_for_user(
        db: DB<'_>,
        state: &str,
        user_id: &str,
    ) -> Result<Option<provider_token_requests::Model>> {
        Ok(ProviderTokenRequests::find()
            .filter(provider_token_requests::Column::State.eq(state))
            .filter(provider_token_requests::Column::UserId.eq(user_id))
            .filter(provider_token_requests::Column::Status.eq("pending"))
            .filter(provider_token_requests::Column::ExpiresAt.gt(chrono::Utc::now().naive_utc()))
            .one(&db)
            .await?)
    }

    pub async fn find_active(
        db: DB<'_>,
        state: &str,
    ) -> Result<Option<provider_token_requests::Model>> {
        Ok(ProviderTokenRequests::find()
            .filter(provider_token_requests::Column::State.eq(state))
            .filter(provider_token_requests::Column::Status.eq("pending"))
            .filter(provider_token_requests::Column::ExpiresAt.gt(chrono::Utc::now().naive_utc()))
            .one(&db)
            .await?)
    }

    pub async fn complete(db: DB<'_>, state: &str, user_id: &str) -> Result<()> {
        let request = Self::find_active_for_user(db.clone(), state, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Provider token request not found".to_string()))?;
        let mut active: provider_token_requests::ActiveModel = request.into();
        active.status = Set("completed".to_string());
        active.completed_at = Set(Some(chrono::Utc::now().naive_utc()));
        active.update(&db).await?;
        Ok(())
    }
}
