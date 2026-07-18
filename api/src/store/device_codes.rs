use crate::entities::device_codes;
use crate::entities::prelude::DeviceCodes;
use crate::error::{AppError, Result};
use crate::store::DB;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

pub struct DeviceCodeStore;

impl DeviceCodeStore {
    /// Find a device code by ID
    pub async fn find_by_id(
        db: DB<'_>,
        device_code_id: &str,
    ) -> Result<Option<device_codes::Model>> {
        let result = DeviceCodes::find()
            .filter(device_codes::Column::Id.eq(device_code_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a device code by device_code value
    pub async fn find_by_device_code(
        db: DB<'_>,
        device_code: &str,
    ) -> Result<Option<device_codes::Model>> {
        let result = DeviceCodes::find()
            .filter(device_codes::Column::DeviceCode.eq(device_code))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find a device code by user_code
    pub async fn find_by_user_code(
        db: DB<'_>,
        user_code: &str,
    ) -> Result<Option<device_codes::Model>> {
        let result = DeviceCodes::find()
            .filter(device_codes::Column::UserCode.eq(user_code))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new device code
    pub async fn create(
        db: DB<'_>,
        device_code: &str,
        user_code: &str,
        client_id: &str,
        org_slug: &str,
        service_slug: &str,
        expires_at: &chrono::NaiveDateTime,
    ) -> Result<device_codes::Model> {
        let new_device_code = device_codes::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            device_code: Set(device_code.to_string()),
            user_code: Set(user_code.to_string()),
            client_id: Set(client_id.to_string()),
            org_slug: Set(org_slug.to_string()),
            service_slug: Set(service_slug.to_string()),
            expires_at: Set(*expires_at),
            status: Set("pending".to_string()),
            ..Default::default()
        };

        let code = new_device_code.insert(&db).await?;
        Ok(code)
    }

    /// Update device code status and user_id
    pub async fn update_status(
        db: DB<'_>,
        device_code_id: &str,
        status: &str,
        user_id: Option<&str>,
    ) -> Result<device_codes::Model> {
        let device_code = Self::find_by_id(db.clone(), device_code_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Device code not found".to_string()))?;

        let mut code_active: device_codes::ActiveModel = device_code.into();
        code_active.status = Set(status.to_string());
        code_active.user_id = Set(user_id.map(|s| s.to_string()));

        let updated_code = code_active.update(&db).await?;
        Ok(updated_code)
    }

    /// Update device code with user_id (approve)
    pub async fn approve(
        db: DB<'_>,
        device_code_id: &str,
        user_id: &str,
    ) -> Result<device_codes::Model> {
        Self::update_status(db, device_code_id, "approved", Some(user_id)).await
    }

    /// Update device code status to denied
    pub async fn deny(db: DB<'_>, device_code_id: &str) -> Result<device_codes::Model> {
        Self::update_status(db, device_code_id, "denied", None).await
    }

    /// Delete a device code
    pub async fn delete(db: DB<'_>, device_code_id: &str) -> Result<()> {
        let result = DeviceCodes::delete_many()
            .filter(device_codes::Column::Id.eq(device_code_id))
            .exec(&db)
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("Device code not found".to_string()));
        }

        Ok(())
    }

    /// Delete expired device codes
    pub async fn delete_expired(db: DB<'_>) -> Result<u64> {
        let now = chrono::Utc::now().naive_utc();

        let result = DeviceCodes::delete_many()
            .filter(device_codes::Column::ExpiresAt.lt(now))
            .exec(&db)
            .await?;

        Ok(result.rows_affected)
    }

    /// Find pending device code by user_code
    pub async fn find_pending_by_user_code(
        db: DB<'_>,
        user_code: &str,
    ) -> Result<Option<device_codes::Model>> {
        let result = DeviceCodes::find()
            .filter(device_codes::Column::UserCode.eq(user_code))
            .filter(device_codes::Column::Status.eq("pending"))
            .filter(device_codes::Column::ExpiresAt.gt(chrono::Utc::now().naive_utc()))
            .filter(device_codes::Column::UserId.is_null())
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find latest pending device code by org_slug and service_slug
    /// Note: Since device_codes table doesn't have a created_at column,
    /// we return the first pending device code found
    pub async fn find_latest_pending_by_org_service(
        db: DB<'_>,
        org_slug: &str,
        service_slug: &str,
    ) -> Result<Option<device_codes::Model>> {
        let result = DeviceCodes::find()
            .filter(device_codes::Column::OrgSlug.eq(org_slug))
            .filter(device_codes::Column::ServiceSlug.eq(service_slug))
            .filter(device_codes::Column::Status.eq("pending"))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Set user_id for a device code (without changing status)
    pub async fn set_user_id(
        db: DB<'_>,
        device_code_id: &str,
        user_id: &str,
    ) -> Result<device_codes::Model> {
        let now = chrono::Utc::now().naive_utc();
        let updated = DeviceCodes::update_many()
            .filter(device_codes::Column::Id.eq(device_code_id))
            .filter(device_codes::Column::Status.eq("pending"))
            .filter(device_codes::Column::ExpiresAt.gt(now))
            .filter(device_codes::Column::UserId.is_null())
            .col_expr(
                device_codes::Column::UserId,
                sea_orm::sea_query::Expr::value(Some(user_id.to_string())),
            )
            .exec(&db)
            .await?;
        if updated.rows_affected != 1 {
            return Err(AppError::BadRequest(
                "Device authorization context is invalid or expired".to_string(),
            ));
        }
        Self::find_by_id(db, device_code_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Device code not found".to_string()))
    }

    /// Authorize a device code (set status to authorized and user_id)
    pub async fn authorize(
        db: DB<'_>,
        device_code_id: &str,
        user_id: &str,
    ) -> Result<device_codes::Model> {
        let now = chrono::Utc::now().naive_utc();
        let updated = DeviceCodes::update_many()
            .filter(device_codes::Column::Id.eq(device_code_id))
            .filter(device_codes::Column::Status.eq("pending"))
            .filter(device_codes::Column::ExpiresAt.gt(now))
            .filter(device_codes::Column::UserId.is_null())
            .col_expr(
                device_codes::Column::Status,
                sea_orm::sea_query::Expr::value("authorized"),
            )
            .col_expr(
                device_codes::Column::UserId,
                sea_orm::sea_query::Expr::value(Some(user_id.to_string())),
            )
            .exec(&db)
            .await?;
        if updated.rows_affected != 1 {
            return Err(AppError::BadRequest(
                "Device authorization context is invalid or expired".to_string(),
            ));
        }
        Self::find_by_id(db, device_code_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Device code not found".to_string()))
    }

    /// Authorize a device code by verifying it belongs to a specific user
    pub async fn authorize_for_user(
        db: DB<'_>,
        device_code_id: &str,
        user_id: &str,
    ) -> Result<u64> {
        let now = chrono::Utc::now().naive_utc();
        let num_updated = crate::error::with_deadlock_retry("authorize_device_code", 10, || {
            let db = &db;
            let device_code_id = device_code_id.to_string();
            let user_id = user_id.to_string();
            async move {
                DeviceCodes::update_many()
                    .filter(device_codes::Column::Id.eq(device_code_id))
                    .filter(device_codes::Column::UserId.eq(user_id))
                    .filter(device_codes::Column::Status.eq("pending"))
                    .filter(device_codes::Column::ExpiresAt.gt(now))
                    .col_expr(
                        device_codes::Column::Status,
                        sea_orm::sea_query::Expr::value("authorized"),
                    )
                    .exec(db)
                    .await
            }
        })
        .await?
        .rows_affected;

        Ok(num_updated)
    }

    /// Atomically consume an authorized device code so token exchange is single-use.
    pub async fn consume_authorized(
        db: DB<'_>,
        device_code_id: &str,
        client_id: &str,
        user_id: &str,
        org_slug: &str,
        service_slug: &str,
    ) -> Result<bool> {
        let now = chrono::Utc::now().naive_utc();
        let rows_affected = DeviceCodes::update_many()
            .filter(device_codes::Column::Id.eq(device_code_id))
            .filter(device_codes::Column::ClientId.eq(client_id))
            .filter(device_codes::Column::UserId.eq(user_id))
            .filter(device_codes::Column::OrgSlug.eq(org_slug))
            .filter(device_codes::Column::ServiceSlug.eq(service_slug))
            .filter(device_codes::Column::Status.eq("authorized"))
            .filter(device_codes::Column::ExpiresAt.gt(now))
            .col_expr(
                device_codes::Column::Status,
                sea_orm::sea_query::Expr::value("consumed"),
            )
            .exec(&db)
            .await?
            .rows_affected;

        Ok(rows_affected == 1)
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[tokio::test]
    async fn delete_expired_removes_only_codes_past_their_expiry() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let now = chrono::Utc::now().naive_utc();

        let expired = DeviceCodeStore::create(
            DB::Conn(&db),
            "expired-device-code",
            "EXP-0001",
            "test-client",
            "test-org",
            "test-service",
            &(now - chrono::Duration::minutes(1)),
        )
        .await
        .expect("create expired code");
        let live = DeviceCodeStore::create(
            DB::Conn(&db),
            "live-device-code",
            "LIVE-001",
            "test-client",
            "test-org",
            "test-service",
            &(now + chrono::Duration::minutes(15)),
        )
        .await
        .expect("create live code");

        assert_eq!(
            DeviceCodeStore::delete_expired(DB::Conn(&db))
                .await
                .expect("delete expired codes"),
            1
        );
        assert!(DeviceCodeStore::find_by_id(DB::Conn(&db), &expired.id)
            .await
            .expect("find expired code")
            .is_none());
        assert!(DeviceCodeStore::find_by_id(DB::Conn(&db), &live.id)
            .await
            .expect("find live code")
            .is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::users::UserStore;
    use chrono::{Duration, Utc};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;
    use std::sync::Arc;
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn delete_removes_device_code_without_preloading() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let expires_at = (Utc::now() + Duration::minutes(5)).naive_utc();

        let code = DeviceCodeStore::create(
            DB::Conn(&db),
            "device-code",
            "USER-CODE",
            "client-id",
            "org",
            "service",
            &expires_at,
        )
        .await
        .expect("create device code");

        DeviceCodeStore::delete(DB::Conn(&db), &code.id)
            .await
            .expect("delete device code");
        assert!(DeviceCodeStore::find_by_id(DB::Conn(&db), &code.id)
            .await
            .expect("load deleted device code")
            .is_none());
    }

    #[tokio::test]
    async fn delete_reports_missing_device_code() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        assert!(matches!(
            DeviceCodeStore::delete(DB::Conn(&db), "missing").await,
            Err(AppError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn concurrent_token_exchange_has_exactly_one_winner() {
        let path =
            std::env::temp_dir().join(format!("authos-device-code-{}.db", uuid::Uuid::new_v4()));
        let db = Database::connect(format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "device-user@example.test", None, false)
            .await
            .expect("create user");
        let expires_at = (Utc::now() + Duration::minutes(5)).naive_utc();
        let code = DeviceCodeStore::create(
            DB::Conn(&db),
            "concurrent-device-code",
            "CONCURRENT-CODE",
            "bound-client",
            "org",
            "service",
            &expires_at,
        )
        .await
        .expect("create device code");
        DeviceCodeStore::update_status(DB::Conn(&db), &code.id, "authorized", Some(&user.id))
            .await
            .expect("authorize device code");
        assert!(!DeviceCodeStore::consume_authorized(
            DB::Conn(&db),
            &code.id,
            "bound-client",
            "different-user",
            "org",
            "service",
        )
        .await
        .expect("reject wrong user"));
        assert!(!DeviceCodeStore::consume_authorized(
            DB::Conn(&db),
            &code.id,
            "bound-client",
            &user.id,
            "different-org",
            "service",
        )
        .await
        .expect("reject wrong organization"));
        assert!(!DeviceCodeStore::consume_authorized(
            DB::Conn(&db),
            &code.id,
            "bound-client",
            &user.id,
            "org",
            "different-service",
        )
        .await
        .expect("reject wrong service"));

        let barrier = Arc::new(Barrier::new(3));
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let db = db.clone();
            let code_id = code.id.clone();
            let user_id = user.id.clone();
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                DeviceCodeStore::consume_authorized(
                    DB::Conn(&db),
                    &code_id,
                    "bound-client",
                    &user_id,
                    "org",
                    "service",
                )
                .await
                .expect("consume device code")
            }));
        }
        barrier.wait().await;

        let mut wins = 0;
        for task in tasks {
            wins += usize::from(task.await.expect("join token exchange"));
        }
        assert_eq!(wins, 1);
        assert!(!DeviceCodeStore::consume_authorized(
            DB::Conn(&db),
            &code.id,
            "different-client",
            &user.id,
            "org",
            "service",
        )
        .await
        .expect("reject wrong client"));

        db.close().await.expect("close sqlite");
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn mfa_authorization_requires_pending_unexpired_user_bound_code() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "mfa-device@example.test", None, false)
            .await
            .expect("create user");
        let valid = DeviceCodeStore::create(
            DB::Conn(&db),
            "mfa-valid-device",
            "MFA-VALID",
            "bound-client",
            "org",
            "service",
            &(Utc::now() + Duration::minutes(5)).naive_utc(),
        )
        .await
        .expect("create valid code");
        DeviceCodeStore::set_user_id(DB::Conn(&db), &valid.id, &user.id)
            .await
            .expect("bind valid code");
        assert_eq!(
            DeviceCodeStore::authorize_for_user(DB::Conn(&db), &valid.id, &user.id)
                .await
                .expect("authorize valid code"),
            1
        );
        assert_eq!(
            DeviceCodeStore::authorize_for_user(DB::Conn(&db), &valid.id, &user.id)
                .await
                .expect("reject already authorized code"),
            0
        );

        let expired = DeviceCodeStore::create(
            DB::Conn(&db),
            "mfa-expired-device",
            "MFA-EXPRD",
            "bound-client",
            "org",
            "service",
            &(Utc::now() - Duration::seconds(1)).naive_utc(),
        )
        .await
        .expect("create expired code");
        assert!(
            DeviceCodeStore::set_user_id(DB::Conn(&db), &expired.id, &user.id)
                .await
                .is_err()
        );
        assert_eq!(
            DeviceCodeStore::authorize_for_user(DB::Conn(&db), &expired.id, &user.id)
                .await
                .expect("reject expired code"),
            0
        );
    }

    #[tokio::test]
    async fn device_principal_binding_cannot_overwrite_or_bypass_a_terminal_or_claimed_row() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let first = UserStore::create(DB::Conn(&db), "first-device@example.test", None, false)
            .await
            .expect("create first user");
        let second = UserStore::create(DB::Conn(&db), "second-device@example.test", None, false)
            .await
            .expect("create second user");

        let authorized = DeviceCodeStore::create(
            DB::Conn(&db),
            "authorized-device",
            "AUTH-RACE",
            "client",
            "org",
            "service",
            &(Utc::now() + Duration::minutes(5)).naive_utc(),
        )
        .await
        .expect("create authorized code");
        DeviceCodeStore::authorize(DB::Conn(&db), &authorized.id, &first.id)
            .await
            .expect("authorize first user");
        assert!(
            DeviceCodeStore::set_user_id(DB::Conn(&db), &authorized.id, &second.id)
                .await
                .is_err()
        );
        let persisted = DeviceCodeStore::find_by_id(DB::Conn(&db), &authorized.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.user_id.as_deref(), Some(first.id.as_str()));
        assert_eq!(persisted.status, "authorized");

        let claimed = DeviceCodeStore::create(
            DB::Conn(&db),
            "claimed-device",
            "CLAIM-RACE",
            "client",
            "org",
            "service",
            &(Utc::now() + Duration::minutes(5)).naive_utc(),
        )
        .await
        .expect("create claimed code");
        DeviceCodeStore::set_user_id(DB::Conn(&db), &claimed.id, &second.id)
            .await
            .expect("claim for second user's MFA");
        assert!(
            DeviceCodeStore::authorize(DB::Conn(&db), &claimed.id, &first.id)
                .await
                .is_err()
        );
        let persisted = DeviceCodeStore::find_by_id(DB::Conn(&db), &claimed.id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted.user_id.as_deref(), Some(second.id.as_str()));
        assert_eq!(persisted.status, "pending");
    }
}
