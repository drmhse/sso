use crate::entities::oauth_states;
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

pub struct OAuthStateStore;

impl OAuthStateStore {
    /// Find an OAuth state by state token (excludes expired states)
    pub async fn find_by_state(db: DB<'_>, state: &str) -> Result<Option<oauth_states::Model>> {
        let now = chrono::Utc::now().naive_utc();

        let result = oauth_states::Entity::find()
            .filter(oauth_states::Column::State.eq(state))
            .filter(oauth_states::Column::ExpiresAt.gt(now))
            .one(&db)
            .await?;

        Ok(result)
    }

    /// Create a new OAuth state
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        state: &str,
        pkce_verifier: Option<&str>,
        service_id: Option<&str>,
        redirect_uri: Option<&str>,
        org_slug: Option<&str>,
        service_slug: Option<&str>,
        is_admin_flow: bool,
        user_id_for_linking: Option<&str>,
        device_user_code: Option<&str>,
        saml_state_id: Option<&str>,
        upstream_connection_id: Option<&str>,
        requested_scopes: Option<&[String]>,
        client_state: Option<&str>,
        provider_token_request_state: Option<&str>,
        resource: Option<&str>,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<oauth_states::Model> {
        let now = chrono::Utc::now().naive_utc();
        let requested_scopes_json = requested_scopes
            .map(serde_json::to_string)
            .transpose()
            .map_err(|e| AppError::InternalServerError(e.to_string()))?;

        let new_state = oauth_states::ActiveModel {
            state: Set(state.to_string()),
            pkce_verifier: Set(pkce_verifier.map(|s| s.to_string())),
            service_id: Set(service_id.map(|s| s.to_string())),
            redirect_uri: Set(redirect_uri.map(|s| s.to_string())),
            org_slug: Set(org_slug.map(|s| s.to_string())),
            service_slug: Set(service_slug.map(|s| s.to_string())),
            is_admin_flow: Set(is_admin_flow),
            user_id_for_linking: Set(user_id_for_linking.map(|s| s.to_string())),
            device_user_code: Set(device_user_code.map(|s| s.to_string())),
            saml_state_id: Set(saml_state_id.map(|s| s.to_string())),
            upstream_connection_id: Set(upstream_connection_id.map(|s| s.to_string())),
            requested_scopes: Set(requested_scopes_json),
            client_state: Set(client_state.map(|s| s.to_string())),
            provider_token_request_state: Set(provider_token_request_state.map(|s| s.to_string())),
            resource: Set(resource.map(|s| s.to_string())),
            created_at: Set(now),
            expires_at: Set(*expires_at),
        };

        let oauth_state = new_state.insert(&db).await?;
        Ok(oauth_state)
    }

    /// Delete an OAuth state
    pub async fn delete(db: DB<'_>, state: &str) -> Result<()> {
        let oauth_state = Self::find_by_state(db.clone(), state)
            .await?
            .ok_or_else(|| AppError::NotFound("OAuth state not found".to_string()))?;

        let state_active: oauth_states::ActiveModel = oauth_state.into();
        state_active.delete(&db).await?;

        Ok(())
    }

    /// Delete expired OAuth states
    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        let now = chrono::Utc::now().naive_utc();

        let result = oauth_states::Entity::delete_many()
            .filter(oauth_states::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}
