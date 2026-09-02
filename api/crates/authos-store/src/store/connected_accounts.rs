use crate::db::DB;
use crate::entities::connected_accounts;
use crate::entities::prelude::ConnectedAccounts;
use crate::error::{AppError, Result};
use crate::utils::scopes::scopes_to_json;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use std::sync::Arc;
use uuid::Uuid;

pub struct ConnectedAccountStore;

impl ConnectedAccountStore {
    pub async fn find_by_id(db: DB<'_>, id: &str) -> Result<Option<connected_accounts::Model>> {
        Ok(ConnectedAccounts::find()
            .filter(connected_accounts::Column::Id.eq(id))
            .one(&db)
            .await?)
    }

    pub async fn find_active_by_id_for_user(
        db: DB<'_>,
        id: &str,
        user_id: &str,
    ) -> Result<Option<connected_accounts::Model>> {
        Ok(ConnectedAccounts::find()
            .filter(connected_accounts::Column::Id.eq(id))
            .filter(connected_accounts::Column::UserId.eq(user_id))
            .filter(connected_accounts::Column::Status.eq("active"))
            .one(&db)
            .await?)
    }

    pub async fn find_by_provider_user_id(
        db: DB<'_>,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<connected_accounts::Model>> {
        Ok(ConnectedAccounts::find()
            .filter(connected_accounts::Column::Provider.eq(provider))
            .filter(connected_accounts::Column::ProviderUserId.eq(provider_user_id))
            .one(&db)
            .await?)
    }

    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<connected_accounts::Model>> {
        Ok(ConnectedAccounts::find()
            .filter(connected_accounts::Column::UserId.eq(user_id))
            .filter(connected_accounts::Column::Status.eq("active"))
            .order_by_asc(connected_accounts::Column::Provider)
            .order_by_desc(connected_accounts::Column::UpdatedAt)
            .all(&db)
            .await?)
    }

    pub async fn list_by_user_and_provider(
        db: DB<'_>,
        user_id: &str,
        provider: &str,
    ) -> Result<Vec<connected_accounts::Model>> {
        Ok(ConnectedAccounts::find()
            .filter(connected_accounts::Column::UserId.eq(user_id))
            .filter(connected_accounts::Column::Provider.eq(provider))
            .filter(connected_accounts::Column::Status.eq("active"))
            .order_by_desc(connected_accounts::Column::UpdatedAt)
            .all(&db)
            .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_from_oauth_details(
        db: DB<'_>,
        encryption: Option<&Arc<crate::encryption::EncryptionService>>,
        user_id: &str,
        provider: &str,
        provider_user_id: &str,
        email: Option<&str>,
        display_name: Option<&str>,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        scopes: &[String],
    ) -> Result<connected_accounts::Model> {
        let scopes_json =
            scopes_to_json(scopes).map_err(|e| AppError::InternalServerError(e.to_string()))?;
        let now = chrono::Utc::now().naive_utc();
        let expires_naive = expires_at.map(|dt| dt.naive_utc());

        if let Some(existing) = ConnectedAccounts::find()
            .filter(connected_accounts::Column::UserId.eq(user_id))
            .filter(connected_accounts::Column::Provider.eq(provider))
            .filter(connected_accounts::Column::ProviderUserId.eq(provider_user_id))
            .one(&db)
            .await?
        {
            let account_id = existing.id.clone();
            let mut active: connected_accounts::ActiveModel = existing.into();
            active.email = Set(email.map(str::to_string));
            active.display_name = Set(display_name.map(str::to_string));
            active.expires_at = Set(expires_naive);
            active.scopes = Set(Some(scopes_json));
            active.last_refreshed_at = Set(Some(now));
            active.updated_at = Set(now);
            active.status = Set("active".to_string());
            active.revoked_at = Set(None);

            Self::set_tokens(
                &mut active,
                encryption,
                &account_id,
                access_token,
                refresh_token,
            )?;

            return Ok(active.update(&db).await?);
        }

        if let Some(existing) =
            Self::find_by_provider_user_id(db.clone(), provider, provider_user_id).await?
        {
            if existing.user_id != user_id {
                return Err(AppError::BadRequest(
                    "This provider account is already linked to a different user".to_string(),
                ));
            }
        }

        let account_id = Uuid::new_v4().to_string();
        let mut active = connected_accounts::ActiveModel {
            id: Set(account_id.clone()),
            user_id: Set(user_id.to_string()),
            provider: Set(provider.to_string()),
            provider_user_id: Set(provider_user_id.to_string()),
            email: Set(email.map(str::to_string)),
            display_name: Set(display_name.map(str::to_string)),
            access_token: Set(None),
            refresh_token: Set(None),
            access_token_encrypted: Set(None),
            refresh_token_encrypted: Set(None),
            encryption_key_id: Set(None),
            expires_at: Set(expires_naive),
            scopes: Set(Some(scopes_json)),
            last_refreshed_at: Set(Some(now)),
            status: Set("active".to_string()),
            linked_at: Set(now),
            updated_at: Set(now),
            revoked_at: Set(None),
        };
        Self::set_tokens(
            &mut active,
            encryption,
            &account_id,
            access_token,
            refresh_token,
        )?;

        Ok(active.insert(&db).await?)
    }

    pub async fn update_tokens(
        db: DB<'_>,
        account_id: &str,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        encryption: Option<&Arc<crate::encryption::EncryptionService>>,
    ) -> Result<connected_accounts::Model> {
        let account = Self::find_by_id(db.clone(), account_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?;
        let now = chrono::Utc::now().naive_utc();
        let mut active: connected_accounts::ActiveModel = account.into();
        active.expires_at = Set(expires_at.map(|dt| dt.naive_utc()));
        active.last_refreshed_at = Set(Some(now));
        active.updated_at = Set(now);
        Self::set_tokens(
            &mut active,
            encryption,
            account_id,
            access_token,
            refresh_token,
        )?;
        Ok(active.update(&db).await?)
    }

    pub async fn revoke(db: DB<'_>, account_id: &str, user_id: &str) -> Result<()> {
        let account = Self::find_active_by_id_for_user(db.clone(), account_id, user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Connected account not found".to_string()))?;
        let now = chrono::Utc::now().naive_utc();
        let mut active: connected_accounts::ActiveModel = account.into();
        active.status = Set("revoked".to_string());
        active.revoked_at = Set(Some(now));
        active.updated_at = Set(now);
        active.update(&db).await?;
        Ok(())
    }

    fn set_tokens(
        active: &mut connected_accounts::ActiveModel,
        encryption: Option<&Arc<crate::encryption::EncryptionService>>,
        account_id: &str,
        access_token: &str,
        refresh_token: Option<&str>,
    ) -> Result<()> {
        if let Some(enc) = encryption {
            let access_token_encrypted = enc
                .encrypt_with_context(
                    access_token,
                    crate::encryption::EncryptionContext::new(
                        "connected_accounts",
                        account_id,
                        "access_token_encrypted",
                    ),
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to encrypt access token: {}", e))
                })?;
            let refresh_token_encrypted = refresh_token
                .map(|rt| {
                    enc.encrypt_with_context(
                        rt,
                        crate::encryption::EncryptionContext::new(
                            "connected_accounts",
                            account_id,
                            "refresh_token_encrypted",
                        ),
                    )
                })
                .transpose()
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to encrypt refresh token: {}", e))
                })?;
            active.access_token = Set(None);
            active.refresh_token = Set(None);
            active.access_token_encrypted = Set(Some(access_token_encrypted));
            active.refresh_token_encrypted = Set(refresh_token_encrypted);
            active.encryption_key_id = Set(Some(enc.key_id().to_string()));
        } else {
            active.access_token = Set(Some(access_token.to_string()));
            if let Some(rt) = refresh_token {
                active.refresh_token = Set(Some(rt.to_string()));
            }
            active.access_token_encrypted = Set(None);
            active.refresh_token_encrypted = Set(None);
            active.encryption_key_id = Set(None);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::users::UserStore;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn linked_account_ownership_and_provider_subject_collision_are_enforced() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let owner = UserStore::create(DB::Conn(&db), "linked-owner@example.test", None, false)
            .await
            .expect("create owner");
        let other = UserStore::create(DB::Conn(&db), "linked-other@example.test", None, false)
            .await
            .expect("create other user");
        let account = ConnectedAccountStore::upsert_from_oauth_details(
            DB::Conn(&db),
            None,
            &owner.id,
            "github",
            "provider-subject",
            None,
            None,
            "owner-access-token",
            Some("owner-refresh-token"),
            None,
            &["read:user".to_string()],
        )
        .await
        .expect("create linked account");

        assert!(ConnectedAccountStore::find_active_by_id_for_user(
            DB::Conn(&db),
            &account.id,
            &other.id,
        )
        .await
        .expect("cross-user lookup")
        .is_none());
        assert!(matches!(
            ConnectedAccountStore::revoke(DB::Conn(&db), &account.id, &other.id).await,
            Err(AppError::NotFound(_))
        ));
        let unchanged = ConnectedAccountStore::find_by_id(DB::Conn(&db), &account.id)
            .await
            .expect("load account")
            .expect("account preserved");
        assert_eq!(unchanged.status, "active");
        assert_eq!(
            unchanged.access_token.as_deref(),
            Some("owner-access-token")
        );
        assert_eq!(
            unchanged.refresh_token.as_deref(),
            Some("owner-refresh-token")
        );
        assert!(
            ConnectedAccountStore::list_by_user(DB::Conn(&db), &other.id)
                .await
                .expect("list other user accounts")
                .is_empty()
        );

        assert!(matches!(
            ConnectedAccountStore::upsert_from_oauth_details(
                DB::Conn(&db),
                None,
                &other.id,
                "github",
                "provider-subject",
                None,
                None,
                "attacker-token",
                None,
                None,
                &["read:user".to_string()],
            )
            .await,
            Err(AppError::BadRequest(_))
        ));
        let still_unchanged = ConnectedAccountStore::find_by_id(DB::Conn(&db), &account.id)
            .await
            .expect("reload account")
            .expect("account remains");
        assert_eq!(still_unchanged.user_id, owner.id);
        assert_eq!(
            still_unchanged.access_token.as_deref(),
            Some("owner-access-token")
        );
    }
}
