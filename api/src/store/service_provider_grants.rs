use crate::entities::prelude::ServiceProviderGrants;
use crate::entities::service_provider_grants;
use crate::error::{AppError, Result};
use crate::store::DB;
use crate::utils::scopes::scopes_to_json;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use uuid::Uuid;

pub struct ServiceProviderGrantStore;

impl ServiceProviderGrantStore {
    pub async fn list_by_user_and_service(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
    ) -> Result<Vec<service_provider_grants::Model>> {
        Ok(ServiceProviderGrants::find()
            .filter(service_provider_grants::Column::UserId.eq(user_id))
            .filter(service_provider_grants::Column::ServiceId.eq(service_id))
            .filter(service_provider_grants::Column::Status.eq("active"))
            .order_by_desc(service_provider_grants::Column::GrantedAt)
            .all(&db)
            .await?)
    }

    pub async fn find_active(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        connected_account_id: &str,
    ) -> Result<Option<service_provider_grants::Model>> {
        Ok(ServiceProviderGrants::find()
            .filter(service_provider_grants::Column::UserId.eq(user_id))
            .filter(service_provider_grants::Column::ServiceId.eq(service_id))
            .filter(service_provider_grants::Column::ConnectedAccountId.eq(connected_account_id))
            .filter(service_provider_grants::Column::Status.eq("active"))
            .one(&db)
            .await?)
    }

    pub async fn find_active_for_provider(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        provider: &str,
    ) -> Result<Vec<service_provider_grants::Model>> {
        Ok(ServiceProviderGrants::find()
            .filter(service_provider_grants::Column::UserId.eq(user_id))
            .filter(service_provider_grants::Column::ServiceId.eq(service_id))
            .filter(service_provider_grants::Column::Provider.eq(provider))
            .filter(service_provider_grants::Column::Status.eq("active"))
            .order_by_desc(service_provider_grants::Column::GrantedAt)
            .all(&db)
            .await?)
    }

    pub async fn upsert(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        connected_account_id: &str,
        provider: &str,
        scopes: &[String],
    ) -> Result<service_provider_grants::Model> {
        let scopes_json =
            scopes_to_json(scopes).map_err(|e| AppError::InternalServerError(e.to_string()))?;
        let now = chrono::Utc::now().naive_utc();

        if let Some(existing) = ServiceProviderGrants::find()
            .filter(service_provider_grants::Column::UserId.eq(user_id))
            .filter(service_provider_grants::Column::ServiceId.eq(service_id))
            .filter(service_provider_grants::Column::ConnectedAccountId.eq(connected_account_id))
            .one(&db)
            .await?
        {
            let mut active: service_provider_grants::ActiveModel = existing.into();
            active.provider = Set(provider.to_string());
            active.scopes = Set(scopes_json);
            active.status = Set("active".to_string());
            active.granted_at = Set(now);
            active.revoked_at = Set(None);
            return Ok(active.update(&db).await?);
        }

        let active = service_provider_grants::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            service_id: Set(service_id.to_string()),
            connected_account_id: Set(connected_account_id.to_string()),
            provider: Set(provider.to_string()),
            scopes: Set(scopes_json),
            status: Set("active".to_string()),
            granted_at: Set(now),
            last_used_at: Set(None),
            revoked_at: Set(None),
        };

        Ok(active.insert(&db).await?)
    }

    pub async fn mark_used(db: DB<'_>, grant_id: &str) -> Result<()> {
        let grant = ServiceProviderGrants::find()
            .filter(service_provider_grants::Column::Id.eq(grant_id))
            .one(&db)
            .await?
            .ok_or_else(|| AppError::NotFound("Provider grant not found".to_string()))?;
        let mut active: service_provider_grants::ActiveModel = grant.into();
        active.last_used_at = Set(Some(chrono::Utc::now().naive_utc()));
        active.update(&db).await?;
        Ok(())
    }

    pub async fn revoke(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        connected_account_id: &str,
    ) -> Result<()> {
        let grant = Self::find_active(db.clone(), user_id, service_id, connected_account_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Provider grant not found".to_string()))?;
        let now = chrono::Utc::now().naive_utc();
        let mut active: service_provider_grants::ActiveModel = grant.into();
        active.status = Set("revoked".to_string());
        active.revoked_at = Set(Some(now));
        active.update(&db).await?;
        Ok(())
    }
}
