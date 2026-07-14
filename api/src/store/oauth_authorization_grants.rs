use crate::entities::oauth_authorization_grants;
use crate::entities::prelude::OauthAuthorizationGrants;
use crate::error::Result;
use crate::store::DB;
use chrono::NaiveDateTime;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct OAuthAuthorizationGrantStore;

impl OAuthAuthorizationGrantStore {
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        token_hash: &str,
        user_id: &str,
        service_id: &str,
        client_id: &str,
        resource: &str,
        scope: Option<&str>,
        expires_at: NaiveDateTime,
    ) -> Result<oauth_authorization_grants::Model> {
        let grant = oauth_authorization_grants::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            token_hash: Set(token_hash.to_string()),
            user_id: Set(user_id.to_string()),
            service_id: Set(service_id.to_string()),
            client_id: Set(client_id.to_string()),
            resource: Set(resource.to_string()),
            scope: Set(scope.map(|value| value.to_string())),
            expires_at: Set(expires_at),
            ..Default::default()
        };

        Ok(grant.insert(&db).await?)
    }

    pub async fn consume_valid_by_token_hash(db: DB<'_>, token_hash: &str) -> Result<bool> {
        let now = chrono::Utc::now().naive_utc();

        let result = OauthAuthorizationGrants::delete_many()
            .filter(oauth_authorization_grants::Column::TokenHash.eq(token_hash))
            .filter(oauth_authorization_grants::Column::ExpiresAt.gt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected == 1)
    }

    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        let now = chrono::Utc::now().naive_utc();

        let result = OauthAuthorizationGrants::delete_many()
            .filter(oauth_authorization_grants::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }
}
