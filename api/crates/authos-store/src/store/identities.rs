use crate::db::DB;
use crate::entities::identities;
use crate::entities::prelude::Identities;
use crate::error::{AppError, Result};
use crate::utils::scopes::scopes_to_json;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, QueryFilter, QueryOrder,
    QuerySelect, Set,
};
use uuid::Uuid;

/// Identity data for end-user management
#[derive(Debug, Clone, FromQueryResult)]
pub struct EndUserIdentityRow {
    pub user_id: String,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: String,
}

#[derive(Debug, Clone, FromQueryResult)]
pub struct ServiceUserRow {
    pub id: String,
    pub email: String,
    pub created_at: chrono::NaiveDateTime,
}

pub struct IdentityStore;

impl IdentityStore {
    /// Return whether a user has an identity issued in the exact tenant/service
    /// context. Global identities and identities issued by another service do
    /// not grant access to SAML assertions for this service.
    pub async fn exists_for_user_and_service_context(
        db: DB<'_>,
        user_id: &str,
        org_id: &str,
        service_id: &str,
    ) -> Result<bool> {
        let identity = Identities::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::IssuingOrgId.eq(org_id))
            .filter(identities::Column::IssuingServiceId.eq(service_id))
            .one(&db)
            .await?;
        Ok(identity.is_some())
    }

    /// Find an identity by ID
    pub async fn find_by_id(db: DB<'_>, identity_id: &str) -> Result<Option<identities::Model>> {
        let result = Identities::find()
            .filter(identities::Column::Id.eq(identity_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find an identity by user and provider
    pub async fn find_by_user_and_provider(
        db: DB<'_>,
        user_id: &str,
        provider: &str,
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<Option<identities::Model>> {
        let mut query = Identities::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::Provider.eq(provider));

        // Handle NULL values for issuing_org_id and issuing_service_id
        match (issuing_org_id, issuing_service_id) {
            (None, None) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.is_null())
                    .filter(identities::Column::IssuingServiceId.is_null());
            }
            (Some(org_id), Some(service_id)) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.eq(org_id))
                    .filter(identities::Column::IssuingServiceId.eq(service_id));
            }
            _ => {
                return Err(AppError::BadRequest(
                    "Both issuing_org_id and issuing_service_id must be provided or both must be None".to_string(),
                ));
            }
        }

        let result = query.one(&db).await?;
        Ok(result)
    }

    /// Find an identity by provider and provider_user_id
    pub async fn find_by_provider_and_provider_user_id(
        db: DB<'_>,
        provider: &str,
        provider_user_id: &str,
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<Option<identities::Model>> {
        let mut query = Identities::find()
            .filter(identities::Column::Provider.eq(provider))
            .filter(identities::Column::ProviderUserId.eq(provider_user_id));

        // Handle context-based uniqueness
        match (issuing_org_id, issuing_service_id) {
            (None, None) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.is_null())
                    .filter(identities::Column::IssuingServiceId.is_null());
            }
            (Some(org_id), Some(service_id)) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.eq(org_id))
                    .filter(identities::Column::IssuingServiceId.eq(service_id));
            }
            _ => {
                return Err(AppError::BadRequest(
                    "Both issuing_org_id and issuing_service_id must be provided or both must be None".to_string(),
                ));
            }
        }

        let result = query.one(&db).await?;
        Ok(result)
    }

    /// Find all identities by provider and provider_user_id across contexts.
    pub async fn list_any_by_provider_and_provider_user_id(
        db: DB<'_>,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Vec<identities::Model>> {
        let result = Identities::find()
            .filter(identities::Column::Provider.eq(provider))
            .filter(identities::Column::ProviderUserId.eq(provider_user_id))
            .order_by_desc(identities::Column::CreatedAt)
            .all(&db)
            .await?;
        Ok(result)
    }

    /// Create a new identity
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        db: DB<'_>,
        user_id: &str,
        provider: &str,
        provider_user_id: &str,
        access_token: Option<&str>,
        refresh_token: Option<&str>,
        access_token_encrypted: Option<Vec<u8>>,
        refresh_token_encrypted: Option<Vec<u8>>,
        encryption_key_id: Option<&str>,
        _expires_at: Option<&str>,
        scopes: Option<&str>,
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<identities::Model> {
        let new_identity = identities::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_string()),
            provider: Set(provider.to_string()),
            provider_user_id: Set(provider_user_id.to_string()),
            access_token: Set(access_token.map(std::string::ToString::to_string)),
            refresh_token: Set(refresh_token.map(std::string::ToString::to_string)),
            access_token_encrypted: Set(access_token_encrypted),
            refresh_token_encrypted: Set(refresh_token_encrypted),
            encryption_key_id: Set(encryption_key_id.map(std::string::ToString::to_string)),
            scopes: Set(scopes.map(std::string::ToString::to_string)),
            issuing_org_id: Set(issuing_org_id.map(std::string::ToString::to_string)),
            issuing_service_id: Set(issuing_service_id.map(std::string::ToString::to_string)),
            ..Default::default()
        };

        let identity = new_identity.insert(&db).await?;
        Ok(identity)
    }

    /// Update refreshed identity tokens (plaintext).
    /// Providers such as Google usually do not return a refresh token on refresh,
    /// so a missing refresh_token means "keep the existing one".
    pub async fn update_tokens(
        db: DB<'_>,
        identity_id: &str,
        access_token: Option<&str>,
        refresh_token: Option<&str>,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<identities::Model> {
        let identity = Self::find_by_id(db.clone(), identity_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Identity not found".to_string()))?;

        let mut identity_active: identities::ActiveModel = identity.into();
        identity_active.access_token = Set(access_token.map(std::string::ToString::to_string));
        if let Some(refresh_token) = refresh_token {
            identity_active.refresh_token = Set(Some(refresh_token.to_string()));
        }
        identity_active.expires_at = Set(expires_at);
        identity_active.last_refreshed_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_identity = identity_active.update(&db).await?;
        Ok(updated_identity)
    }

    /// Update refreshed identity tokens (encrypted).
    /// Providers such as Google usually do not return a refresh token on refresh,
    /// so a missing refresh_token_encrypted means "keep the existing one".
    pub async fn update_tokens_encrypted(
        db: DB<'_>,
        identity_id: &str,
        access_token_encrypted: Option<Vec<u8>>,
        refresh_token_encrypted: Option<Vec<u8>>,
        encryption_key_id: &str,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<identities::Model> {
        let identity = Self::find_by_id(db.clone(), identity_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Identity not found".to_string()))?;

        let mut identity_active: identities::ActiveModel = identity.into();
        identity_active.access_token = Set(None);
        identity_active.refresh_token = Set(None);
        identity_active.access_token_encrypted = Set(access_token_encrypted);
        if let Some(refresh_token_encrypted) = refresh_token_encrypted {
            identity_active.refresh_token_encrypted = Set(Some(refresh_token_encrypted));
        }
        identity_active.encryption_key_id = Set(Some(encryption_key_id.to_string()));
        identity_active.expires_at = Set(expires_at);
        identity_active.last_refreshed_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_identity = identity_active.update(&db).await?;
        Ok(updated_identity)
    }

    /// Persist refreshed encrypted tokens only if the refresh credential is
    /// still exactly the one used for the provider request. Revocation or
    /// replacement while network I/O is in flight must win.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_tokens_encrypted_if_current(
        db: DB<'_>,
        identity_id: &str,
        expected_refresh_token_encrypted: Option<&[u8]>,
        expected_refresh_token_plaintext: Option<&str>,
        access_token_encrypted: Option<Vec<u8>>,
        refresh_token_encrypted: Option<Vec<u8>>,
        encryption_key_id: &str,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<bool> {
        use sea_orm::sea_query::Expr;

        let mut update = Identities::update_many()
            .filter(identities::Column::Id.eq(identity_id))
            .col_expr(identities::Column::AccessToken, Expr::value(None::<String>))
            .col_expr(
                identities::Column::RefreshToken,
                Expr::value(None::<String>),
            )
            .col_expr(
                identities::Column::AccessTokenEncrypted,
                Expr::value(access_token_encrypted),
            )
            .col_expr(
                identities::Column::EncryptionKeyId,
                Expr::value(Some(encryption_key_id.to_string())),
            )
            .col_expr(identities::Column::ExpiresAt, Expr::value(expires_at))
            .col_expr(
                identities::Column::LastRefreshedAt,
                Expr::value(Some(chrono::Utc::now().naive_utc())),
            );
        update = match expected_refresh_token_encrypted {
            Some(expected) => {
                update.filter(identities::Column::RefreshTokenEncrypted.eq(expected.to_vec()))
            }
            None => update.filter(identities::Column::RefreshTokenEncrypted.is_null()),
        };
        update = match expected_refresh_token_plaintext {
            Some(expected) => {
                update.filter(identities::Column::RefreshToken.eq(expected.to_string()))
            }
            None => update.filter(identities::Column::RefreshToken.is_null()),
        };
        if let Some(refresh_token_encrypted) = refresh_token_encrypted {
            update = update.col_expr(
                identities::Column::RefreshTokenEncrypted,
                Expr::value(Some(refresh_token_encrypted)),
            );
        }
        Ok(update.exec(&db).await?.rows_affected == 1)
    }

    /// Development-mode equivalent of encrypted CAS refresh writeback.
    pub async fn update_tokens_if_current(
        db: DB<'_>,
        identity_id: &str,
        expected_refresh_token: Option<&str>,
        access_token: Option<&str>,
        refresh_token: Option<&str>,
        expires_at: Option<chrono::NaiveDateTime>,
    ) -> Result<bool> {
        use sea_orm::sea_query::Expr;

        let mut update = Identities::update_many()
            .filter(identities::Column::Id.eq(identity_id))
            .col_expr(
                identities::Column::AccessToken,
                Expr::value(access_token.map(str::to_string)),
            )
            .col_expr(identities::Column::ExpiresAt, Expr::value(expires_at))
            .col_expr(
                identities::Column::LastRefreshedAt,
                Expr::value(Some(chrono::Utc::now().naive_utc())),
            );
        update = match expected_refresh_token {
            Some(expected) => {
                update.filter(identities::Column::RefreshToken.eq(expected.to_string()))
            }
            None => update.filter(identities::Column::RefreshToken.is_null()),
        };
        if let Some(refresh_token) = refresh_token {
            update = update.col_expr(
                identities::Column::RefreshToken,
                Expr::value(Some(refresh_token.to_string())),
            );
        }
        Ok(update.exec(&db).await?.rows_affected == 1)
    }

    /// Delete an identity
    pub async fn delete(db: DB<'_>, identity_id: &str) -> Result<()> {
        let result = Identities::delete_many()
            .filter(identities::Column::Id.eq(identity_id))
            .exec(&db)
            .await?;

        if result.rows_affected == 0 {
            return Err(AppError::NotFound("Identity not found".to_string()));
        }

        Ok(())
    }

    /// Delete identity by user and provider
    pub async fn delete_by_user_and_provider(
        db: DB<'_>,
        user_id: &str,
        provider: &str,
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<()> {
        if let Some(identity) = Self::find_by_user_and_provider(
            db.clone(),
            user_id,
            provider,
            issuing_org_id,
            issuing_service_id,
        )
        .await?
        {
            let identity_active: identities::ActiveModel = identity.into();
            identity_active.delete(&db).await?;
        }

        Ok(())
    }

    /// Delete identity by user and service (Security Audit Item 2)
    /// Used by Service API to remove user's link to a service without affecting other services
    pub async fn delete_by_user_and_service(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
    ) -> Result<()> {
        Identities::delete_many()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::IssuingServiceId.eq(Some(service_id)))
            .exec(&db)
            .await?;

        Ok(())
    }

    /// List all identities for a user
    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<identities::Model>> {
        let identities = Identities::find()
            .filter(identities::Column::UserId.eq(user_id))
            .all(&db)
            .await?;

        Ok(identities)
    }

    /// List identities for a user with context filtering
    pub async fn list_by_user_with_context(
        db: DB<'_>,
        user_id: &str,
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<Vec<identities::Model>> {
        let mut query = Identities::find().filter(identities::Column::UserId.eq(user_id));

        // Handle context-based filtering
        match (issuing_org_id, issuing_service_id) {
            (None, None) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.is_null())
                    .filter(identities::Column::IssuingServiceId.is_null());
            }
            (Some(org_id), Some(service_id)) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.eq(org_id))
                    .filter(identities::Column::IssuingServiceId.eq(service_id));
            }
            _ => {
                return Err(AppError::BadRequest(
                    "Both issuing_org_id and issuing_service_id must be provided or both must be None".to_string(),
                ));
            }
        }

        let identities = query.all(&db).await?;
        Ok(identities)
    }

    /// Count identities for a user with context filtering
    pub async fn count_by_user_with_context(
        db: DB<'_>,
        user_id: &str,
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<u64> {
        use sea_orm::PaginatorTrait;

        let mut query = Identities::find().filter(identities::Column::UserId.eq(user_id));

        // Handle context-based filtering
        match (issuing_org_id, issuing_service_id) {
            (None, None) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.is_null())
                    .filter(identities::Column::IssuingServiceId.is_null());
            }
            (Some(org_id), Some(service_id)) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.eq(org_id))
                    .filter(identities::Column::IssuingServiceId.eq(service_id));
            }
            _ => {
                return Err(AppError::BadRequest(
                    "Both issuing_org_id and issuing_service_id must be provided or both must be None".to_string(),
                ));
            }
        }

        let count = query.count(&db).await?;
        Ok(count)
    }

    /// Get the most recent provider for a user (based on last_refreshed_at)
    pub async fn get_latest_provider(db: DB<'_>, user_id: &str) -> Result<Option<String>> {
        use sea_orm::QueryOrder;

        let identity = Identities::find()
            .filter(identities::Column::UserId.eq(user_id))
            .order_by_desc(identities::Column::LastRefreshedAt)
            .one(&db)
            .await?;

        Ok(identity.map(|i| i.provider))
    }

    /// List identities that need token refresh
    /// Finds identities with expiring tokens that have either plaintext or encrypted refresh tokens
    pub async fn list_needing_refresh(
        db: DB<'_>,
        threshold: &str,
    ) -> Result<Vec<identities::Model>> {
        use sea_orm::Condition;

        // Parse the threshold string to NaiveDateTime
        let threshold_dt = chrono::DateTime::parse_from_rfc3339(threshold)
            .map_err(|e| AppError::BadRequest(format!("Invalid threshold date: {}", e)))?
            .naive_utc();

        let identities = Identities::find()
            .filter(identities::Column::ExpiresAt.is_not_null())
            .filter(identities::Column::ExpiresAt.lt(threshold_dt))
            .filter(
                Condition::any()
                    .add(identities::Column::RefreshToken.is_not_null())
                    .add(identities::Column::RefreshTokenEncrypted.is_not_null()),
            )
            .all(&db)
            .await?;

        Ok(identities)
    }

    /// Upsert identity with full token details and encryption support
    ///
    /// This method handles creating or updating an identity with context-aware
    /// uniqueness (platform vs service context).
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_with_details(
        db: DB<'_>,
        encryption: Option<&std::sync::Arc<crate::encryption::EncryptionService>>,
        user_id: &str,
        provider: &str,
        provider_user_id: &str,
        access_token: &str,
        refresh_token: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        scopes: &[String],
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<identities::Model> {
        let scopes_json =
            scopes_to_json(scopes).map_err(|e| AppError::InternalServerError(e.to_string()))?;
        let last_refreshed = chrono::Utc::now().naive_utc();
        let expires_naive = expires_at.map(|dt| dt.naive_utc());

        let existing = Self::find_by_user_provider_context(
            db.clone(),
            user_id,
            provider,
            issuing_org_id,
            issuing_service_id,
        )
        .await?;

        let identity = if let Some(existing) = existing {
            // Update existing identity
            let identity_id = existing.id.clone();
            let mut active: identities::ActiveModel = existing.into();

            active.provider_user_id = Set(provider_user_id.to_string());
            active.expires_at = Set(expires_naive);
            active.scopes = Set(Some(scopes_json));
            active.last_refreshed_at = Set(Some(last_refreshed));

            if let Some(enc) = encryption {
                let access_token_encrypted = encrypt_identity_token(
                    enc,
                    &identity_id,
                    "access_token_encrypted",
                    access_token,
                )
                .map_err(|e| {
                    AppError::InternalServerError(format!("Failed to encrypt access token: {}", e))
                })?;
                active.access_token = Set(None);
                active.refresh_token = Set(None);
                active.access_token_encrypted = Set(Some(access_token_encrypted));
                if let Some(rt) = refresh_token {
                    let refresh_token_encrypted =
                        encrypt_identity_token(enc, &identity_id, "refresh_token_encrypted", rt)
                            .map_err(|e| {
                                AppError::InternalServerError(format!(
                                    "Failed to encrypt refresh token: {}",
                                    e
                                ))
                            })?;
                    active.refresh_token_encrypted = Set(Some(refresh_token_encrypted));
                }
                active.encryption_key_id = Set(Some(enc.key_id().to_string()));
            } else {
                active.access_token = Set(Some(access_token.to_string()));
                if let Some(rt) = refresh_token {
                    active.refresh_token = Set(Some(rt.to_string()));
                }
            }

            active.update(&db).await?
        } else {
            // Create new identity

            let id = Uuid::new_v4().to_string();
            let now = chrono::Utc::now().naive_utc();

            let new_identity = if let Some(enc) = encryption {
                let access_token_encrypted =
                    encrypt_identity_token(enc, &id, "access_token_encrypted", access_token)
                        .map_err(|e| {
                            AppError::InternalServerError(format!(
                                "Failed to encrypt access token: {}",
                                e
                            ))
                        })?;
                let refresh_token_encrypted = refresh_token
                    .map(|rt| encrypt_identity_token(enc, &id, "refresh_token_encrypted", rt))
                    .transpose()
                    .map_err(|e| {
                        AppError::InternalServerError(format!(
                            "Failed to encrypt refresh token: {}",
                            e
                        ))
                    })?;

                identities::ActiveModel {
                    id: Set(id),
                    user_id: Set(user_id.to_string()),
                    provider: Set(provider.to_string()),
                    provider_user_id: Set(provider_user_id.to_string()),
                    access_token: Set(None),
                    refresh_token: Set(None),
                    access_token_encrypted: Set(Some(access_token_encrypted)),
                    refresh_token_encrypted: Set(refresh_token_encrypted),
                    encryption_key_id: Set(Some(enc.key_id().to_string())),
                    expires_at: Set(expires_naive),
                    scopes: Set(Some(scopes_json.clone())),
                    issuing_org_id: Set(issuing_org_id.map(std::string::ToString::to_string)),
                    issuing_service_id: Set(
                        issuing_service_id.map(std::string::ToString::to_string)
                    ),
                    last_refreshed_at: Set(Some(last_refreshed)),
                    created_at: Set(now),
                }
            } else {
                identities::ActiveModel {
                    id: Set(id),
                    user_id: Set(user_id.to_string()),
                    provider: Set(provider.to_string()),
                    provider_user_id: Set(provider_user_id.to_string()),
                    access_token: Set(Some(access_token.to_string())),
                    refresh_token: Set(refresh_token.map(std::string::ToString::to_string)),
                    access_token_encrypted: Set(None),
                    refresh_token_encrypted: Set(None),
                    encryption_key_id: Set(None),
                    expires_at: Set(expires_naive),
                    scopes: Set(Some(scopes_json.clone())),
                    issuing_org_id: Set(issuing_org_id.map(std::string::ToString::to_string)),
                    issuing_service_id: Set(
                        issuing_service_id.map(std::string::ToString::to_string)
                    ),
                    last_refreshed_at: Set(Some(last_refreshed)),
                    created_at: Set(now),
                }
            };

            // Handle potential race condition where another request creates the same identity
            match new_identity.insert(&db).await {
                Ok(identity) => identity,
                Err(e) => {
                    // Check if this is a unique constraint violation
                    if e.to_string().contains("duplicate key")
                        || e.to_string().contains("unique constraint")
                    {
                        // Race condition: another request created the identity, retry lookup by provider context
                        tracing::debug!(
                            "Identity creation race condition detected, retrying lookup for provider: {}, provider_user_id: {}",
                            provider,
                            provider_user_id
                        );

                        if let Some(existing_identity) = Self::find_by_provider_user_id_context(
                            db.clone(),
                            provider,
                            provider_user_id,
                            issuing_org_id,
                            issuing_service_id,
                        )
                        .await?
                        {
                            // Check if this identity belongs to a different user (orphaned record)
                            if existing_identity.user_id != user_id {
                                tracing::warn!(
                                    "Found orphaned identity for provider {} with user_id {}, updating to correct user_id {}",
                                    provider,
                                    existing_identity.user_id,
                                    user_id
                                );

                                // Update the orphaned identity to the correct user
                                let identity_id = existing_identity.id.clone();
                                let mut identity_active: identities::ActiveModel =
                                    existing_identity.into();
                                identity_active.user_id = Set(user_id.to_string());

                                // Update tokens and other fields as well
                                if let Some(enc) = encryption {
                                    let access_token_encrypted = encrypt_identity_token(
                                        enc,
                                        &identity_id,
                                        "access_token_encrypted",
                                        access_token,
                                    )
                                    .map_err(|e| {
                                        AppError::InternalServerError(format!(
                                            "Failed to encrypt access token: {}",
                                            e
                                        ))
                                    })?;
                                    identity_active.access_token = Set(None);
                                    identity_active.refresh_token = Set(None);
                                    identity_active.access_token_encrypted =
                                        Set(Some(access_token_encrypted));
                                    if let Some(rt) = refresh_token {
                                        let refresh_token_encrypted = encrypt_identity_token(
                                            enc,
                                            &identity_id,
                                            "refresh_token_encrypted",
                                            rt,
                                        )
                                        .map_err(|e| {
                                            AppError::InternalServerError(format!(
                                                "Failed to encrypt refresh token: {}",
                                                e
                                            ))
                                        })?;
                                        identity_active.refresh_token_encrypted =
                                            Set(Some(refresh_token_encrypted));
                                    }
                                    identity_active.encryption_key_id =
                                        Set(Some(enc.key_id().to_string()));
                                } else {
                                    identity_active.access_token =
                                        Set(Some(access_token.to_string()));
                                    if let Some(rt) = refresh_token {
                                        identity_active.refresh_token = Set(Some(rt.to_string()));
                                    }
                                    identity_active.encryption_key_id = Set(None);
                                }

                                identity_active.expires_at = Set(expires_naive);
                                identity_active.scopes = Set(Some(scopes_json.clone()));
                                identity_active.last_refreshed_at = Set(Some(last_refreshed));

                                identity_active.update(&db).await?
                            } else {
                                // Identity belongs to correct user, update tokens
                                let identity_id = existing_identity.id.clone();
                                let mut identity_active: identities::ActiveModel =
                                    existing_identity.into();
                                identity_active.provider_user_id =
                                    Set(provider_user_id.to_string());
                                identity_active.expires_at = Set(expires_naive);
                                identity_active.scopes = Set(Some(scopes_json.clone()));
                                identity_active.last_refreshed_at = Set(Some(last_refreshed));

                                if let Some(enc) = encryption {
                                    let access_token_encrypted = encrypt_identity_token(
                                        enc,
                                        &identity_id,
                                        "access_token_encrypted",
                                        access_token,
                                    )
                                    .map_err(|e| {
                                        AppError::InternalServerError(format!(
                                            "Failed to encrypt access token: {}",
                                            e
                                        ))
                                    })?;
                                    identity_active.access_token = Set(None);
                                    identity_active.refresh_token = Set(None);
                                    identity_active.access_token_encrypted =
                                        Set(Some(access_token_encrypted));
                                    if let Some(rt) = refresh_token {
                                        let refresh_token_encrypted = encrypt_identity_token(
                                            enc,
                                            &identity_id,
                                            "refresh_token_encrypted",
                                            rt,
                                        )
                                        .map_err(|e| {
                                            AppError::InternalServerError(format!(
                                                "Failed to encrypt refresh token: {}",
                                                e
                                            ))
                                        })?;
                                        identity_active.refresh_token_encrypted =
                                            Set(Some(refresh_token_encrypted));
                                    }
                                    identity_active.encryption_key_id =
                                        Set(Some(enc.key_id().to_string()));
                                } else {
                                    identity_active.access_token =
                                        Set(Some(access_token.to_string()));
                                    if let Some(rt) = refresh_token {
                                        identity_active.refresh_token = Set(Some(rt.to_string()));
                                    }
                                }

                                identity_active.update(&db).await?
                            }
                        } else {
                            return Err(AppError::InternalServerError(
                                "Failed to find identity after race condition".to_string(),
                            ));
                        }
                    } else {
                        return Err(AppError::InternalServerError(format!(
                            "Failed to create identity: {}",
                            e
                        )));
                    }
                }
            }
        };

        Ok(identity)
    }

    /// Find identity by user, provider, and context (org/service)
    async fn find_by_user_provider_context(
        db: DB<'_>,
        user_id: &str,
        provider: &str,
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<Option<identities::Model>> {
        let mut query = Identities::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::Provider.eq(provider));

        match (issuing_org_id, issuing_service_id) {
            (Some(org_id), Some(service_id)) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.eq(org_id))
                    .filter(identities::Column::IssuingServiceId.eq(service_id));
            }
            _ => {
                query = query
                    .filter(identities::Column::IssuingOrgId.is_null())
                    .filter(identities::Column::IssuingServiceId.is_null());
            }
        }

        Ok(query.one(&db).await?)
    }

    /// Find identity by provider, provider_user_id, and context (org/service)
    async fn find_by_provider_user_id_context(
        db: DB<'_>,
        provider: &str,
        provider_user_id: &str,
        issuing_org_id: Option<&str>,
        issuing_service_id: Option<&str>,
    ) -> Result<Option<identities::Model>> {
        let mut query = Identities::find()
            .filter(identities::Column::Provider.eq(provider))
            .filter(identities::Column::ProviderUserId.eq(provider_user_id));

        match (issuing_org_id, issuing_service_id) {
            (Some(org_id), Some(service_id)) => {
                query = query
                    .filter(identities::Column::IssuingOrgId.eq(org_id))
                    .filter(identities::Column::IssuingServiceId.eq(service_id));
            }
            _ => {
                query = query
                    .filter(identities::Column::IssuingOrgId.is_null())
                    .filter(identities::Column::IssuingServiceId.is_null());
            }
        }

        let result = query.one(&db).await?;
        Ok(result)
    }

    /// List identities for multiple users in an organization (for end-user management)
    pub async fn list_identities_for_users_in_org(
        db: DB<'_>,
        user_ids: &[String],
        org_id: &str,
        service_id: Option<&str>,
    ) -> Result<Vec<EndUserIdentityRow>> {
        use sea_orm::QueryOrder;

        if user_ids.is_empty() {
            return Ok(Vec::new());
        }

        let mut query = Identities::find()
            .filter(identities::Column::UserId.is_in(user_ids.to_vec()))
            .filter(identities::Column::IssuingOrgId.eq(org_id));

        if let Some(svc_id) = service_id {
            query = query.filter(identities::Column::IssuingServiceId.eq(svc_id));
        }

        let identities = query
            .order_by_asc(identities::Column::CreatedAt)
            .all(&db)
            .await?;

        let results = identities
            .into_iter()
            .map(|identity| EndUserIdentityRow {
                user_id: identity.user_id,
                provider: identity.provider,
                provider_user_id: identity.provider_user_id,
                created_at: identity.created_at.to_string(),
            })
            .collect();

        Ok(results)
    }

    /// List identities for a specific user and organization
    pub async fn list_identities_for_user_in_org(
        db: DB<'_>,
        user_id: &str,
        org_id: &str,
    ) -> Result<Vec<EndUserIdentityRow>> {
        use sea_orm::QueryOrder;

        let identities = Identities::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::IssuingOrgId.eq(org_id))
            .order_by_asc(identities::Column::CreatedAt)
            .all(&db)
            .await?;

        let results = identities
            .into_iter()
            .map(|identity| EndUserIdentityRow {
                user_id: identity.user_id,
                provider: identity.provider,
                provider_user_id: identity.provider_user_id,
                created_at: identity.created_at.to_string(),
            })
            .collect();

        Ok(results)
    }

    /// Count identities for a user in an organization
    pub async fn count_by_user_and_org(db: DB<'_>, user_id: &str, org_id: &str) -> Result<u64> {
        use sea_orm::PaginatorTrait;

        let count = Identities::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::IssuingOrgId.eq(org_id))
            .count(&db)
            .await?;

        Ok(count)
    }

    /// Count distinct users who have authenticated with a service
    pub async fn count_users_by_service(db: DB<'_>, service_id: &str) -> Result<u64> {
        use sea_orm::PaginatorTrait;

        // Count distinct user_ids for the service where issuing_service_id matches
        let count = Identities::find()
            .filter(identities::Column::IssuingServiceId.eq(Some(service_id)))
            .select_only()
            .column(identities::Column::UserId)
            .distinct()
            .count(&db)
            .await?;

        Ok(count)
    }

    /// Count distinct users whose user row and identity context both belong to
    /// the service principal's organization.
    pub async fn count_users_by_org_service(
        db: DB<'_>,
        org_id: &str,
        service_id: &str,
    ) -> Result<u64> {
        use crate::entities::users;
        use sea_orm::{JoinType, PaginatorTrait, RelationTrait};

        Ok(Identities::find()
            .join(JoinType::InnerJoin, identities::Relation::Users.def())
            .filter(identities::Column::IssuingOrgId.eq(Some(org_id)))
            .filter(identities::Column::IssuingServiceId.eq(Some(service_id)))
            .filter(users::Column::OrgId.eq(Some(org_id)))
            .select_only()
            .column(identities::Column::UserId)
            .distinct()
            .count(&db)
            .await?)
    }

    /// List users who have authenticated with a service (with pagination)
    pub async fn list_users_by_service(
        db: DB<'_>,
        service_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<String>> {
        use sea_orm::{QueryOrder, QuerySelect};

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 1000);
        // Get distinct user_ids for the service where issuing_service_id matches
        // Note: For PostgreSQL DISTINCT queries, ORDER BY columns must be in SELECT list
        let user_ids = Identities::find()
            .filter(identities::Column::IssuingServiceId.eq(Some(service_id)))
            .select_only()
            .column(identities::Column::UserId)
            .column_as(identities::Column::CreatedAt, "created_at")
            .distinct()
            .order_by_desc(identities::Column::CreatedAt)
            .limit(limit)
            .offset(offset)
            .into_tuple::<(String, String)>()
            .all(&db)
            .await?
            .into_iter()
            .map(|(user_id, _created_at)| user_id)
            .collect();

        Ok(user_ids)
    }

    /// List users who have authenticated with a service, returning user details directly.
    pub async fn list_user_details_by_service(
        db: DB<'_>,
        service_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ServiceUserRow>> {
        use crate::entities::users;
        use sea_orm::{JoinType, QueryOrder, QuerySelect, RelationTrait};

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 1000);
        let users = Identities::find()
            .join(JoinType::InnerJoin, identities::Relation::Users.def())
            .filter(identities::Column::IssuingServiceId.eq(Some(service_id)))
            .select_only()
            .column_as(users::Column::Id, "id")
            .column_as(users::Column::Email, "email")
            .column_as(users::Column::CreatedAt, "created_at")
            .group_by(users::Column::Id)
            .group_by(users::Column::Email)
            .group_by(users::Column::CreatedAt)
            .order_by_desc(identities::Column::CreatedAt.max())
            .limit(limit)
            .offset(offset)
            .into_model::<ServiceUserRow>()
            .all(&db)
            .await?;

        Ok(users)
    }

    /// List service users only when both the user and the issuing identity are
    /// bound to the service principal's organization.
    pub async fn list_user_details_by_org_service(
        db: DB<'_>,
        org_id: &str,
        service_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ServiceUserRow>> {
        use crate::entities::users;
        use sea_orm::{JoinType, QueryOrder, RelationTrait};

        let (limit, offset) = crate::utils::pagination::store_u64(limit, offset, 1000);
        Ok(Identities::find()
            .join(JoinType::InnerJoin, identities::Relation::Users.def())
            .filter(identities::Column::IssuingOrgId.eq(Some(org_id)))
            .filter(identities::Column::IssuingServiceId.eq(Some(service_id)))
            .filter(users::Column::OrgId.eq(Some(org_id)))
            .select_only()
            .column_as(users::Column::Id, "id")
            .column_as(users::Column::Email, "email")
            .column_as(users::Column::CreatedAt, "created_at")
            .group_by(users::Column::Id)
            .group_by(users::Column::Email)
            .group_by(users::Column::CreatedAt)
            .order_by_desc(identities::Column::CreatedAt.max())
            .limit(limit)
            .offset(offset)
            .into_model::<ServiceUserRow>()
            .all(&db)
            .await?)
    }

    /// Check if a user has authenticated with a service
    pub async fn user_has_authenticated_with_service(
        db: DB<'_>,
        user_id: &str,
        service_id: &str,
    ) -> Result<bool> {
        let exists = Identities::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::IssuingServiceId.eq(Some(service_id)))
            .one(&db)
            .await?
            .is_some();

        Ok(exists)
    }

    /// Check a user/service link with both identity and user organization
    /// predicates. This is the only safe form for service-principal APIs.
    pub async fn user_has_authenticated_with_org_service(
        db: DB<'_>,
        user_id: &str,
        org_id: &str,
        service_id: &str,
    ) -> Result<bool> {
        use crate::entities::users;
        use sea_orm::{JoinType, RelationTrait};

        Ok(Identities::find()
            .join(JoinType::InnerJoin, identities::Relation::Users.def())
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::IssuingOrgId.eq(Some(org_id)))
            .filter(identities::Column::IssuingServiceId.eq(Some(service_id)))
            .filter(users::Column::OrgId.eq(Some(org_id)))
            .one(&db)
            .await?
            .is_some())
    }
}

fn encrypt_identity_token(
    encryption: &crate::encryption::EncryptionService,
    identity_id: &str,
    field: &'static str,
    plaintext: &str,
) -> std::result::Result<Vec<u8>, crate::encryption::EncryptionError> {
    encryption.encrypt_with_context(
        plaintext,
        crate::encryption::EncryptionContext::new("identities", identity_id, field),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        organizations::OrganizationStore, services::ServiceStore, users::UserStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, Set};

    #[tokio::test]
    async fn delete_reports_missing_identity_without_preload() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        assert!(matches!(
            IdentityStore::delete(DB::Conn(&db), "missing").await,
            Err(AppError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn service_principal_queries_reject_inconsistent_cross_tenant_identity_context() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user_a = UserStore::create(DB::Conn(&db), "identity-a@example.com", None, false)
            .await
            .expect("create user A");
        let user_b = UserStore::create(DB::Conn(&db), "identity-b@example.com", None, false)
            .await
            .expect("create user B");
        let org_a = OrganizationStore::create(
            DB::Conn(&db),
            "identity-org-a",
            "Identity Org A",
            &user_a.id,
            None,
        )
        .await
        .expect("create org A");
        let org_b = OrganizationStore::create(
            DB::Conn(&db),
            "identity-org-b",
            "Identity Org B",
            &user_b.id,
            None,
        )
        .await
        .expect("create org B");
        let mut user_a_active: crate::entities::users::ActiveModel = user_a.clone().into();
        user_a_active.org_id = Set(Some(org_a.id.clone()));
        user_a_active.update(&db).await.expect("scope user A");
        let mut user_b_active: crate::entities::users::ActiveModel = user_b.clone().into();
        user_b_active.org_id = Set(Some(org_b.id.clone()));
        user_b_active.update(&db).await.expect("scope user B");
        let service_a = ServiceStore::create(
            DB::Conn(&db),
            &org_a.id,
            "identity-service-a",
            "Identity Service A",
            "web",
            "identity-client-a",
        )
        .await
        .expect("create service A");
        IdentityStore::create(
            DB::Conn(&db),
            &user_a.id,
            "test",
            "provider-a",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org_a.id),
            Some(&service_a.id),
        )
        .await
        .expect("create valid identity");
        IdentityStore::create(
            DB::Conn(&db),
            &user_b.id,
            "test",
            "provider-b",
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(&org_b.id),
            Some(&service_a.id),
        )
        .await
        .expect("create deliberately inconsistent identity");

        assert!(IdentityStore::user_has_authenticated_with_org_service(
            DB::Conn(&db),
            &user_a.id,
            &org_a.id,
            &service_a.id
        )
        .await
        .expect("check valid identity"));
        assert!(!IdentityStore::user_has_authenticated_with_org_service(
            DB::Conn(&db),
            &user_b.id,
            &org_a.id,
            &service_a.id
        )
        .await
        .expect("reject cross-tenant identity"));
        assert_eq!(
            IdentityStore::count_users_by_org_service(DB::Conn(&db), &org_a.id, &service_a.id)
                .await
                .expect("count scoped users"),
            1
        );
        let listed = IdentityStore::list_user_details_by_org_service(
            DB::Conn(&db),
            &org_a.id,
            &service_a.id,
            10,
            0,
        )
        .await
        .expect("list scoped users");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, user_a.id);
    }
}
