use crate::entities::prelude::{Memberships, Users};
use crate::entities::{memberships, users};
use crate::error::{AppError, Result};
use crate::store::DB;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};
use chrono::{NaiveDate, NaiveDateTime};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, EntityTrait, FromQueryResult, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, Set,
};
use uuid::Uuid;

/// Options for user creation to unify different creation patterns
#[derive(Debug, Default)]
pub struct UserCreationOptions {
    /// Whether the user should be a platform owner
    pub is_platform_owner: bool,
    /// Optional password hash (for password-based users)
    pub password_hash: Option<String>,
    /// Platform owner email to check against for automatic platform owner detection
    pub platform_owner_email: Option<String>,
    /// Whether to mark email as verified immediately
    pub mark_email_verified: bool,
}

pub struct UserStore;

impl UserStore {
    /// Find a user by their ID
    pub async fn find_by_id(db: DB<'_>, user_id: &str) -> Result<Option<users::Model>> {
        let result = Users::find()
            .filter(users::Column::Id.eq(user_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find users by a list of IDs
    pub async fn find_by_ids(db: DB<'_>, user_ids: &[String]) -> Result<Vec<users::Model>> {
        let results = Users::find()
            .filter(users::Column::Id.is_in(user_ids))
            .all(&db)
            .await?;
        Ok(results)
    }

    /// Unified find or create user method with options
    /// If the user exists, return it. Otherwise, create a new user with the specified options.
    /// Returns (user, was_created) where was_created is true if the user was just created
    pub async fn find_or_create_with_options(
        db: DB<'_>,
        email: &str,
        options: UserCreationOptions,
    ) -> Result<(users::Model, bool)> {
        // Check if user already exists
        if let Some(user) = Self::find_by_email(db.clone(), email).await? {
            return Ok((user, false));
        }

        // Determine platform owner status
        let is_platform_owner = if let Some(owner_email) = options.platform_owner_email {
            owner_email.eq_ignore_ascii_case(email)
        } else {
            options.is_platform_owner
        };

        // Determine email verification timestamp
        let email_verified_at = if options.mark_email_verified {
            Some(chrono::Utc::now().naive_utc())
        } else {
            None
        };

        // Create new user
        let new_user = users::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            email: Set(email.to_string()),
            is_platform_owner: Set(is_platform_owner),
            password_hash: Set(options.password_hash),
            email_verified_at: Set(email_verified_at),
            ..Default::default()
        };

        let user = new_user.insert(&db).await?;
        Ok((user, true))
    }

    /// Find a user by their email address
    pub async fn find_by_email(db: DB<'_>, email: &str) -> Result<Option<users::Model>> {
        let result = Users::find()
            .filter(users::Column::Email.eq(email))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find or create a user by email address
    /// If the user exists, return it. Otherwise, create a new user.
    /// Returns (user, was_created) where was_created is true if the user was just created
    pub async fn find_or_create(db: DB<'_>, email: &str) -> Result<(users::Model, bool)> {
        let options = UserCreationOptions::default();
        Self::find_or_create_with_options(db, email, options).await
    }

    /// Find or create a user for admin OAuth flow with platform owner detection
    /// If the user exists, return it. Otherwise, create a new user with platform owner check.
    /// Returns (user, was_created) where was_created is true if the user was just created
    pub async fn find_or_create_admin_oauth(
        db: DB<'_>,
        email: &str,
        platform_owner_email: Option<&str>,
    ) -> Result<(users::Model, bool)> {
        let options = UserCreationOptions {
            platform_owner_email: platform_owner_email.map(|s| s.to_string()),
            ..Default::default()
        };
        Self::find_or_create_with_options(db, email, options).await
    }

    /// Create a new user with email and optional password hash
    pub async fn create(
        db: DB<'_>,
        email: &str,
        password_hash: Option<String>,
        is_platform_owner: bool,
    ) -> Result<users::Model> {
        let options = UserCreationOptions {
            is_platform_owner,
            password_hash,
            ..Default::default()
        };

        let (user, _was_created) = Self::find_or_create_with_options(db, email, options).await?;
        Ok(user)
    }

    /// Update a user's password hash
    pub async fn update_password(
        db: DB<'_>,
        user_id: &str,
        password_hash: String,
    ) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("User not found".to_string()))?;

        let mut user_active: users::ActiveModel = user.into();
        user_active.password_hash = Set(Some(password_hash));
        user_active.updated_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Set or unset platform owner status for a user
    pub async fn set_platform_owner(
        db: DB<'_>,
        user_id: &str,
        is_platform_owner: bool,
    ) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| crate::error::AppError::NotFound("User not found".to_string()))?;

        let mut user_active: users::ActiveModel = user.into();
        user_active.is_platform_owner = Set(is_platform_owner);
        user_active.updated_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Update user password hash
    pub async fn update_password_hash(
        db: DB<'_>,
        user_id: &str,
        password_hash: &str,
    ) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let mut user_active: users::ActiveModel = user.into();
        user_active.password_hash = Set(Some(password_hash.to_string()));
        user_active.updated_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Mark email as verified
    pub async fn verify_email(db: DB<'_>, user_id: &str) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let now = chrono::Utc::now().naive_utc();
        let mut user_active: users::ActiveModel = user.into();
        user_active.email_verified_at = Set(Some(now));
        user_active.updated_at = Set(Some(now));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Check if an email is already taken by another user (excluding current user)
    pub async fn is_email_taken(db: DB<'_>, email: &str, exclude_user_id: &str) -> Result<bool> {
        let count = Users::find()
            .filter(users::Column::Email.eq(email))
            .filter(users::Column::Id.ne(exclude_user_id))
            .count(&db)
            .await?;

        Ok(count > 0)
    }

    /// Update user's email address
    pub async fn update_email(db: DB<'_>, user_id: &str, new_email: &str) -> Result<users::Model> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let mut user_active: users::ActiveModel = user.into();
        user_active.email = Set(new_email.to_string());
        user_active.updated_at = Set(Some(chrono::Utc::now().naive_utc()));

        let updated_user = user_active.update(&db).await?;
        Ok(updated_user)
    }

    /// Count platform owners
    pub async fn count_platform_owners(db: DB<'_>) -> Result<u64> {
        let count = Users::find()
            .filter(users::Column::IsPlatformOwner.eq(true))
            .count(&db)
            .await?;
        Ok(count)
    }

    /// Search users with filters and ordering
    pub async fn search_users(
        db: DB<'_>,
        email_search: Option<&str>,
        role_filter: Option<&str>,
        order_by: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<users::Model>> {
        let mut query = Users::find();

        // Apply email search filter (case-insensitive LIKE)
        if let Some(email) = email_search {
            let search_pattern = format!("%{}%", email);
            query = query.filter(users::Column::Email.like(&search_pattern));
        }

        // Apply role filter
        if let Some(role) = role_filter {
            match role {
                "platform_owner" => {
                    query = query.filter(users::Column::IsPlatformOwner.eq(true));
                }
                "regular" => {
                    query = query.filter(users::Column::IsPlatformOwner.eq(false));
                }
                _ => {}
            }
        }

        // Apply ordering
        match order_by {
            "email_asc" => {
                query = query.order_by_asc(users::Column::Email);
            }
            "email_desc" => {
                query = query.order_by_desc(users::Column::Email);
            }
            "created_desc" => {
                query = query.order_by_desc(users::Column::CreatedAt);
            }
            "created_asc" => {
                query = query.order_by_asc(users::Column::CreatedAt);
            }
            _ => {
                // Default ordering
                query = query.order_by_desc(users::Column::CreatedAt);
            }
        }

        // Apply pagination
        let users = query
            .limit(limit as u64)
            .offset(offset as u64)
            .all(&db)
            .await?;

        Ok(users)
    }

    /// Advanced search with relevance-based ordering for platform admin search
    pub async fn search_with_relevance(
        db: DB<'_>,
        search_query: &str,
        limit: u64,
    ) -> Result<Vec<UserSearchResult>> {
        let search_term = format!("%{}%", search_query.trim());
        let q_trimmed = search_query.trim();

        // Build the relevance ordering using raw SQL CASE expression
        // Build the relevance ordering using SeaORM CaseStatement
        let relevance_expr: sea_orm::sea_query::SimpleExpr =
            sea_orm::sea_query::CaseStatement::new()
                .case(users::Column::Email.eq(q_trimmed), 1)
                .case(users::Column::Email.like(&search_term), 2)
                .case(users::Column::Id.eq(q_trimmed), 3)
                .finally(4)
                .into();

        let results = Users::find()
            .select_only()
            .column(users::Column::Id)
            .column(users::Column::Email)
            .column(users::Column::IsPlatformOwner)
            .column(users::Column::CreatedAt)
            .filter(
                Condition::any()
                    .add(users::Column::Email.like(&search_term))
                    .add(users::Column::Id.eq(q_trimmed)),
            )
            .order_by_asc(relevance_expr)
            .order_by_desc(users::Column::CreatedAt)
            .limit(limit)
            .into_model::<UserSearchResult>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// Get user growth trends by date range
    pub async fn get_growth_trends(
        db: DB<'_>,
        start_date: NaiveDateTime,
        end_date: NaiveDateTime,
        include_platform_owners: bool,
    ) -> Result<Vec<UserGrowthTrendData>> {
        use sea_orm::sea_query::{Alias, Func, SimpleExpr};
        let date_expr: SimpleExpr =
            Func::cast_as(Expr::col(users::Column::CreatedAt), Alias::new("DATE")).into();

        let mut query = Users::find()
            .filter(users::Column::CreatedAt.gte(start_date))
            .filter(users::Column::CreatedAt.lte(end_date));

        if !include_platform_owners {
            query = query.filter(users::Column::IsPlatformOwner.eq(false));
        }

        let results = query
            .select_only()
            .column_as(date_expr.clone(), "date")
            .column_as(Expr::col(users::Column::Id).count(), "count")
            .group_by(date_expr)
            .order_by_asc(Expr::col(Alias::new("date")))
            .into_model::<UserGrowthTrendData>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// Count total users with optional platform owner filter
    pub async fn count_all(db: DB<'_>, exclude_platform_owners: bool) -> Result<u64> {
        let mut query = Users::find();

        if exclude_platform_owners {
            query = query.filter(users::Column::IsPlatformOwner.eq(false));
        }

        let count = query.count(&db).await?;
        Ok(count)
    }

    /// Count admin users (platform owners + org owners/admins)
    pub async fn count_admin_users(db: DB<'_>) -> Result<i64> {
        use sea_orm::QuerySelect;

        // Count org owners/admins (distinct users)
        let org_admin_ids: Vec<String> = Memberships::find()
            .filter(memberships::Column::Role.is_in(vec!["owner", "admin"]))
            .select_only()
            .column(memberships::Column::UserId)
            .distinct()
            .into_tuple()
            .all(&db)
            .await?;

        // Get unique count by combining both sets
        let mut unique_ids: std::collections::HashSet<String> = org_admin_ids.into_iter().collect();

        // Platform owners might also be in org admin list, so we use a set
        let platform_owner_ids: Vec<String> = Users::find()
            .filter(users::Column::IsPlatformOwner.eq(true))
            .select_only()
            .column(users::Column::Id)
            .into_tuple()
            .all(&db)
            .await?;

        unique_ids.extend(platform_owner_ids);

        Ok(unique_ids.len() as i64)
    }

    /// Delete a user by ID
    /// This will cascade delete all related data (identities, sessions, subscriptions, etc.)
    pub async fn delete(db: DB<'_>, user_id: &str) -> Result<()> {
        let user = Self::find_by_id(db.clone(), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        let user_active: users::ActiveModel = user.into();
        user_active.delete(&db).await?;
        Ok(())
    }

    /// Anonymize a user for GDPR compliance
    /// - Soft deletes the user (sets deleted_at)
    /// - Anonymizes PII (email, password_hash)
    /// - Deletes sensitive authentication data (identities, passkeys, TOTP secrets)
    /// - Preserves audit logs and login events for security integrity
    pub async fn anonymize(db: DB<'_>, user_id: &str) -> Result<()> {
        use crate::entities::prelude::{Identities, Sessions, UserPasskeys, UserTotpSecrets};
        use sea_orm::TransactionTrait;

        // Get the database connection to start a transaction
        let db_conn = match db {
            DB::Conn(conn) => conn,
            DB::Tx(_) => {
                return Err(AppError::InternalServerError(
                    "Cannot nest transactions".to_string(),
                ))
            }
        };

        let user = Self::find_by_id(DB::Conn(db_conn), user_id)
            .await?
            .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

        // Start a transaction to ensure atomicity
        let txn = db_conn.begin().await?;

        // Generate anonymized email using a new UUID to prevent collisions
        let anonymized_email = format!("deleted_{}@redacted.invalid", Uuid::new_v4());
        let now = chrono::Utc::now().naive_utc();

        // Soft delete and anonymize the user
        let mut user_active: users::ActiveModel = user.into();
        user_active.email = Set(anonymized_email);
        user_active.password_hash = Set(None);
        user_active.deleted_at = Set(Some(now));
        user_active.updated_at = Set(Some(now));
        user_active.update(&txn).await?;

        // Delete sensitive authentication data
        // 1. Delete all OAuth identities
        Identities::delete_many()
            .filter(crate::entities::identities::Column::UserId.eq(user_id))
            .exec(&txn)
            .await?;

        // 2. Delete all passkeys (WebAuthn credentials)
        UserPasskeys::delete_many()
            .filter(crate::entities::user_passkeys::Column::UserId.eq(user_id))
            .exec(&txn)
            .await?;

        // 3. Delete TOTP secrets
        UserTotpSecrets::delete_many()
            .filter(crate::entities::user_totp_secrets::Column::UserId.eq(user_id))
            .exec(&txn)
            .await?;

        // 4. Revoke all active sessions (immediate logout on anonymization)
        let sessions_deleted = Sessions::delete_many()
            .filter(crate::entities::sessions::Column::UserId.eq(user_id))
            .exec(&txn)
            .await?;

        tracing::info!(
            user_id = %user_id,
            sessions_revoked = sessions_deleted.rows_affected,
            "Revoked all sessions during user anonymization"
        );

        // Commit the transaction
        txn.commit().await?;

        tracing::info!(
            user_id = %user_id,
            "User anonymized for GDPR compliance"
        );

        Ok(())
    }

    /// Ensures a platform owner exists with the given email and password.
    /// If the user exists, updates them to be a platform owner with the new password.
    /// If the user doesn't exist, creates them as a platform owner.
    /// This is called on startup to allow password-based login for the platform owner.
    pub async fn bootstrap_platform_owner(db: DB<'_>, email: &str, password: &str) -> Result<()> {
        // Hash the provided password
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| {
                AppError::InternalServerError(format!(
                    "Failed to hash platform owner password: {}",
                    e
                ))
            })?
            .to_string();

        // Try to find the user by email first
        match Self::find_by_email(db.clone(), email).await? {
            Some(user) => {
                // User exists, update their record to be a platform owner
                let now = chrono::Utc::now().naive_utc();
                let mut user_active: users::ActiveModel = user.into();
                user_active.is_platform_owner = Set(true);
                user_active.password_hash = Set(Some(password_hash));
                user_active.email_verified_at = Set(Some(now));
                user_active.updated_at = Set(Some(now));
                user_active.update(&db).await?;
                tracing::info!(
                    "Platform owner status and password updated for existing user: {}",
                    email
                );
            }
            None => {
                // User doesn't exist, create them as platform owner using unified method
                let options = UserCreationOptions {
                    is_platform_owner: true,
                    password_hash: Some(password_hash),
                    mark_email_verified: true,
                    ..Default::default()
                };

                let (_user, _was_created) =
                    Self::find_or_create_with_options(db, email, options).await?;
                tracing::info!("Platform owner account created: {}", email);
            }
        }

        Ok(())
    }
}

/// User search result
#[derive(Debug, FromQueryResult)]
pub struct UserSearchResult {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    pub created_at: chrono::NaiveDateTime,
}

/// User growth trend data point
#[derive(Debug, FromQueryResult)]
pub struct UserGrowthTrendData {
    pub date: NaiveDate,
    pub count: i64,
}
