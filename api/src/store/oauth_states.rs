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
        let now = chrono::Utc::now().naive_utc();

        let result = oauth_states::Entity::delete_many()
            .filter(oauth_states::Column::State.eq(state))
            .filter(oauth_states::Column::ExpiresAt.gt(now))
            .exec(&db)
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("OAuth state not found".to_string()));
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn delete_removes_unexpired_state_without_preloading() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let expires_at = (Utc::now() + Duration::minutes(5)).naive_utc();

        OAuthStateStore::create(
            DB::Conn(&db),
            "state-token",
            Some("verifier"),
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            &expires_at,
        )
        .await
        .expect("create state");

        OAuthStateStore::delete(DB::Conn(&db), "state-token")
            .await
            .expect("delete state");
        assert!(OAuthStateStore::find_by_state(DB::Conn(&db), "state-token")
            .await
            .expect("load state")
            .is_none());
    }

    #[tokio::test]
    async fn delete_reports_missing_or_expired_state() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let expires_at = (Utc::now() - Duration::minutes(5)).naive_utc();

        OAuthStateStore::create(
            DB::Conn(&db),
            "expired-state",
            None,
            None,
            None,
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            &expires_at,
        )
        .await
        .expect("create expired state");

        assert!(matches!(
            OAuthStateStore::delete(DB::Conn(&db), "missing").await,
            Err(AppError::NotFound(_))
        ));
        assert!(matches!(
            OAuthStateStore::delete(DB::Conn(&db), "expired-state").await,
            Err(AppError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_callback_consumption_has_exactly_one_winner() {
        let path =
            std::env::temp_dir().join(format!("authos-oauth-state-{}.db", uuid::Uuid::new_v4()));
        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let expires_at = (Utc::now() + Duration::minutes(5)).naive_utc();
        OAuthStateStore::create(
            DB::Conn(&db),
            "concurrent-state",
            Some("pkce-verifier"),
            None,
            Some("https://client.example.test/callback"),
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            Some("client-state"),
            None,
            None,
            &expires_at,
        )
        .await
        .expect("create state");

        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let db = db.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                OAuthStateStore::delete(DB::Conn(&db), "concurrent-state")
                    .await
                    .is_ok()
            }));
        }
        barrier.wait().await;

        let mut wins = 0;
        for task in tasks {
            wins += usize::from(task.await.expect("join callback"));
        }
        assert_eq!(wins, 1);
        assert!(
            OAuthStateStore::find_by_state(DB::Conn(&db), "concurrent-state")
                .await
                .expect("reload state")
                .is_none()
        );

        db.close().await.expect("close sqlite");
        let _ = std::fs::remove_file(path);
    }
}
