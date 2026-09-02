use crate::db::DB;
use crate::entities::prelude::ServiceProviderGrants;
use crate::entities::service_provider_grants;
use crate::error::{AppError, Result};
use crate::store::connected_accounts::ConnectedAccountStore;
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

    pub async fn list_active_by_accounts(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
        connected_account_ids: &[String],
    ) -> Result<Vec<service_provider_grants::Model>> {
        if connected_account_ids.is_empty() {
            return Ok(Vec::new());
        }

        Ok(ServiceProviderGrants::find()
            .filter(service_provider_grants::Column::UserId.eq(user_id))
            .filter(service_provider_grants::Column::ServiceId.eq(service_id))
            .filter(
                service_provider_grants::Column::ConnectedAccountId
                    .is_in(connected_account_ids.iter().cloned()),
            )
            .filter(service_provider_grants::Column::Status.eq("active"))
            .order_by_desc(service_provider_grants::Column::GrantedAt)
            .all(&db)
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
        let account = ConnectedAccountStore::find_active_by_id_for_user(
            db.clone(),
            connected_account_id,
            user_id,
        )
        .await?
        .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?;
        if account.provider != provider {
            return Err(AppError::BadRequest(
                "Connected account provider does not match the grant provider".to_string(),
            ));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        connected_accounts::ConnectedAccountStore, organizations::OrganizationStore,
        services::ServiceStore, users::UserStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn provider_grants_require_owned_matching_account_and_preserve_denied_state() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "grant-owner@example.test", None, false)
            .await
            .expect("create owner");
        let other = UserStore::create(DB::Conn(&db), "grant-other@example.test", None, false)
            .await
            .expect("create other user");
        let org =
            OrganizationStore::create(DB::Conn(&db), "grant-org", "Grant Org", &owner.id, None)
                .await
                .expect("create org");
        let service = ServiceStore::create(
            DB::Conn(&db),
            &org.id,
            "grant-service",
            "Grant Service",
            "web",
            "grant-client",
        )
        .await
        .expect("create service");
        let account = ConnectedAccountStore::upsert_from_oauth_details(
            DB::Conn(&db),
            None,
            &owner.id,
            "github",
            "grant-subject",
            None,
            None,
            "access-token",
            None,
            None,
            &["read:user".to_string()],
        )
        .await
        .expect("create account");
        let grant = ServiceProviderGrantStore::upsert(
            DB::Conn(&db),
            &owner.id,
            &service.id,
            &account.id,
            "github",
            &["read:user".to_string()],
        )
        .await
        .expect("create grant");

        assert!(matches!(
            ServiceProviderGrantStore::upsert(
                DB::Conn(&db),
                &other.id,
                &service.id,
                &account.id,
                "github",
                &["read:user".to_string()],
            )
            .await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            ServiceProviderGrantStore::upsert(
                DB::Conn(&db),
                &owner.id,
                &service.id,
                &account.id,
                "google",
                &["openid".to_string()],
            )
            .await,
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            ServiceProviderGrantStore::revoke(DB::Conn(&db), &other.id, &service.id, &account.id,)
                .await,
            Err(AppError::NotFound(_))
        ));

        let unchanged = ServiceProviderGrantStore::find_active(
            DB::Conn(&db),
            &owner.id,
            &service.id,
            &account.id,
        )
        .await
        .expect("load grant")
        .expect("grant preserved");
        assert_eq!(unchanged.id, grant.id);
        assert_eq!(unchanged.provider, "github");
        assert_eq!(unchanged.status, "active");
        assert!(ServiceProviderGrantStore::list_by_user_and_service(
            DB::Conn(&db),
            &other.id,
            &service.id,
        )
        .await
        .expect("list other grants")
        .is_empty());
    }
}
