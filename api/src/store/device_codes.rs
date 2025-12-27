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
        let device_code = Self::find_by_id(db.clone(), device_code_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Device code not found".to_string()))?;

        let code_active: device_codes::ActiveModel = device_code.into();
        code_active.delete(&db).await?;

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
        let device_code = Self::find_by_id(db.clone(), device_code_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Device code not found".to_string()))?;

        let mut code_active: device_codes::ActiveModel = device_code.into();
        code_active.user_id = Set(Some(user_id.to_string()));

        let updated_code = code_active.update(&db).await?;
        Ok(updated_code)
    }

    /// Authorize a device code (set status to authorized and user_id)
    pub async fn authorize(
        db: DB<'_>,
        device_code_id: &str,
        user_id: &str,
    ) -> Result<device_codes::Model> {
        Self::update_status(db, device_code_id, "authorized", Some(user_id)).await
    }

    /// Authorize a device code by verifying it belongs to a specific user
    pub async fn authorize_for_user(
        db: DB<'_>,
        device_code_id: &str,
        user_id: &str,
    ) -> Result<u64> {
        let num_updated = crate::error::with_deadlock_retry("authorize_device_code", 10, || {
            let db = &db;
            let device_code_id = device_code_id.to_string();
            let user_id = user_id.to_string();
            async move {
                DeviceCodes::update_many()
                    .filter(device_codes::Column::Id.eq(device_code_id))
                    .filter(device_codes::Column::UserId.eq(user_id))
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
}
