use crate::auth::sso::{configured_basic_client, ConfiguredBasicClient, Provider};
use crate::config::Config;
use crate::entities::prelude::{LoginEvents, Memberships, Organizations, Services};
use crate::entities::{login_events, memberships, organizations, services, users};
use crate::error::{AppError, Result};
use crate::store::DB;
use chrono::NaiveDateTime;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, FromQueryResult, JoinType, PaginatorTrait,
    QueryFilter, QueryOrder, QuerySelect, RelationTrait, Set,
};
use std::collections::HashMap;
use uuid::Uuid;

/// OAuth credentials for an organization
#[derive(Debug, FromQueryResult)]
pub struct OrgOAuthCredentials {
    pub id: String,
    pub client_id: String,
    pub client_secret_encrypted: Vec<u8>,
    pub encryption_key_id: String,
}

#[derive(Debug, FromQueryResult)]
struct StatusCount {
    status: String,
    count: i64,
}

#[derive(Debug, FromQueryResult)]
struct CountByOrg {
    org_id: String,
    count: i64,
}

#[derive(Debug, FromQueryResult)]
struct DistinctLoginUserByOrg {
    org_id: String,
    user_id: String,
}

pub struct OrganizationStore;

impl OrganizationStore {
    /// Find an organization by its ID
    pub async fn find_by_id(db: DB<'_>, org_id: &str) -> Result<Option<organizations::Model>> {
        let result = Organizations::find()
            .filter(organizations::Column::Id.eq(org_id))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find organizations by IDs.
    pub async fn find_by_ids(db: DB<'_>, org_ids: &[String]) -> Result<Vec<organizations::Model>> {
        if org_ids.is_empty() {
            return Ok(Vec::new());
        }

        let result = Organizations::find()
            .filter(organizations::Column::Id.is_in(org_ids.iter().cloned()))
            .all(&db)
            .await?;
        Ok(result)
    }

    /// Find an organization by its slug
    pub async fn find_by_slug(db: DB<'_>, slug: &str) -> Result<Option<organizations::Model>> {
        let result = Organizations::find()
            .filter(organizations::Column::Slug.eq(slug))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Find an organization by custom domain
    pub async fn find_by_custom_domain(
        db: DB<'_>,
        domain: &str,
    ) -> Result<Option<organizations::Model>> {
        let result = Organizations::find()
            .filter(organizations::Column::CustomDomain.eq(domain))
            .one(&db)
            .await?;
        Ok(result)
    }

    /// Create a new organization
    pub async fn create(
        db: DB<'_>,
        slug: &str,
        name: &str,
        owner_user_id: &str,
        tier_id: Option<&str>,
    ) -> Result<organizations::Model> {
        let _now = chrono::Utc::now().naive_utc();

        let new_org = organizations::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            slug: Set(slug.to_string()),
            name: Set(name.to_string()),
            owner_user_id: Set(owner_user_id.to_string()),
            status: Set("pending".to_string()),
            tier_id: Set(tier_id.map(|s| s.to_string())),
            ..Default::default()
        };

        let org = new_org.insert(&db).await?;
        Ok(org)
    }

    /// Create organization with owner membership in a single transaction
    pub async fn create_with_owner(
        db: DB<'_>,
        slug: &str,
        name: &str,
        owner_user_id: &str,
        tier_id: Option<&str>,
    ) -> Result<(organizations::Model, memberships::Model)> {
        // Create organization
        let org = Self::create(db.clone(), slug, name, owner_user_id, tier_id).await?;

        // Create owner membership
        let membership =
            crate::store::memberships::MembershipStore::create(db, &org.id, owner_user_id, "owner")
                .await?;

        Ok((org, membership))
    }

    /// Update organization name
    pub async fn update_name(db: DB<'_>, org_id: &str, name: &str) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.name = Set(name.to_string());
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Update organization status
    pub async fn update_status(
        db: DB<'_>,
        org_id: &str,
        status: &str,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.status = Set(status.to_string());
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Approve an organization
    pub async fn approve(
        db: DB<'_>,
        org_id: &str,
        approved_by: &str,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let now = chrono::Utc::now().naive_utc();
        let mut org_active: organizations::ActiveModel = org.into();
        org_active.status = Set("active".to_string());
        org_active.approved_by = Set(Some(approved_by.to_string()));
        org_active.approved_at = Set(Some(now));
        org_active.updated_at = Set(now);

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Reject an organization
    pub async fn reject(
        db: DB<'_>,
        org_id: &str,
        rejected_by: &str,
        reason: Option<&str>,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let now = chrono::Utc::now().naive_utc();
        let mut org_active: organizations::ActiveModel = org.into();
        org_active.status = Set("rejected".to_string());
        org_active.rejected_by = Set(Some(rejected_by.to_string()));
        org_active.rejected_at = Set(Some(now));
        org_active.rejection_reason = Set(reason.map(|s| s.to_string()));
        org_active.updated_at = Set(now);

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Transfer ownership of an organization
    pub async fn transfer_ownership(
        db: DB<'_>,
        org_id: &str,
        new_owner_id: &str,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.owner_user_id = Set(new_owner_id.to_string());
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Transfer ownership only if the caller still owns the organization.
    /// This compare-and-swap prevents concurrent transfer requests from both
    /// succeeding after reading the same previous owner.
    pub async fn transfer_ownership_if_current(
        db: DB<'_>,
        org_id: &str,
        current_owner_id: &str,
        new_owner_id: &str,
    ) -> Result<organizations::Model> {
        let result = Organizations::update_many()
            .filter(organizations::Column::Id.eq(org_id))
            .filter(organizations::Column::OwnerUserId.eq(current_owner_id))
            .col_expr(
                organizations::Column::OwnerUserId,
                sea_orm::sea_query::Expr::value(new_owner_id.to_string()),
            )
            .col_expr(
                organizations::Column::UpdatedAt,
                sea_orm::sea_query::Expr::value(chrono::Utc::now().naive_utc()),
            )
            .exec(&db)
            .await?;
        if result.rows_affected != 1 {
            return Err(AppError::BadRequest(
                "Organization ownership changed; retry the transfer".to_string(),
            ));
        }

        Self::find_by_id(db, org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))
    }

    /// Update organization tier
    pub async fn update_tier(
        db: DB<'_>,
        org_id: &str,
        tier_id: &str,
        max_services: Option<i32>,
        max_users: Option<i32>,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.tier_id = Set(Some(tier_id.to_string()));
        org_active.max_services = Set(max_services);
        org_active.max_users = Set(max_users);
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Set custom domain for organization
    pub async fn set_custom_domain(
        db: DB<'_>,
        org_id: &str,
        domain: &str,
        verification_token: &str,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.custom_domain = Set(Some(domain.to_string()));
        org_active.domain_verification_token = Set(Some(verification_token.to_string()));
        org_active.domain_verified = Set(false);
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Verify custom domain
    pub async fn verify_domain(db: DB<'_>, org_id: &str) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.domain_verified = Set(true);
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Delete custom domain
    pub async fn delete_custom_domain(db: DB<'_>, org_id: &str) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.custom_domain = Set(None);
        org_active.domain_verified = Set(false);
        org_active.domain_verification_token = Set(None);
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Update organization branding
    pub async fn update_branding(
        db: DB<'_>,
        org_id: &str,
        logo_url: Option<&str>,
        primary_color: Option<&str>,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        if let Some(logo) = logo_url {
            org_active.brand_logo_url = Set(Some(logo.to_string()));
        }
        if let Some(color) = primary_color {
            org_active.brand_primary_color = Set(Some(color.to_string()));
        }
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// List all organizations (optionally filtered by status)
    pub async fn list(
        db: DB<'_>,
        status: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<organizations::Model>> {
        let mut query = Organizations::find();

        if let Some(status_filter) = status {
            query = query.filter(organizations::Column::Status.eq(status_filter));
        }

        let orgs = query
            .order_by_desc(organizations::Column::CreatedAt)
            .limit(limit)
            .offset(offset)
            .all(&db)
            .await?;

        Ok(orgs)
    }

    /// Count organizations (optionally filtered by status)
    pub async fn count(db: DB<'_>, status: Option<&str>) -> Result<u64> {
        let mut query = Organizations::find();

        if let Some(status_filter) = status {
            query = query.filter(organizations::Column::Status.eq(status_filter));
        }

        let count = query.count(&db).await?;
        Ok(count)
    }

    /// Get user's organizations through memberships
    pub async fn list_by_user(db: DB<'_>, user_id: &str) -> Result<Vec<organizations::Model>> {
        // Get all memberships for this user
        let memberships = Memberships::find()
            .filter(memberships::Column::UserId.eq(user_id))
            .all(&db)
            .await?;

        // Get org IDs from memberships
        let org_ids: Vec<String> = memberships.into_iter().map(|m| m.org_id).collect();

        if org_ids.is_empty() {
            return Ok(vec![]);
        }

        // Fetch all organizations
        let orgs = Organizations::find()
            .filter(organizations::Column::Id.is_in(org_ids))
            .order_by_desc(organizations::Column::CreatedAt)
            .all(&db)
            .await?;

        Ok(orgs)
    }

    /// Get organization OAuth credentials for a specific provider
    pub async fn get_oauth_credentials(
        db: DB<'_>,
        org_id: &str,
        provider: &str,
    ) -> Result<Option<OrgOAuthCredentials>> {
        use crate::entities::{
            organization_oauth_credentials, prelude::OrganizationOauthCredentials,
        };

        let credentials = OrganizationOauthCredentials::find()
            .filter(organization_oauth_credentials::Column::OrgId.eq(org_id))
            .filter(organization_oauth_credentials::Column::Provider.eq(provider))
            .one(&db)
            .await?;

        Ok(credentials.map(|c| OrgOAuthCredentials {
            id: c.id,
            client_id: c.client_id,
            client_secret_encrypted: c.client_secret_encrypted,
            encryption_key_id: c.encryption_key_id,
        }))
    }

    /// List all available providers for an organization
    pub async fn list_oauth_providers(db: DB<'_>, org_id: &str) -> Result<Vec<String>> {
        use crate::entities::{
            organization_oauth_credentials, prelude::OrganizationOauthCredentials,
        };

        let credentials = OrganizationOauthCredentials::find()
            .filter(organization_oauth_credentials::Column::OrgId.eq(org_id))
            .all(&db)
            .await?;

        Ok(credentials.into_iter().map(|c| c.provider).collect())
    }

    /// Update only the updated_at timestamp
    pub async fn update_timestamp(db: DB<'_>, org_id: &str) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Update organization SMTP configuration
    #[allow(clippy::too_many_arguments)]
    pub async fn update_smtp_config(
        db: DB<'_>,
        org_id: &str,
        host: &str,
        port: i64,
        username: &str,
        password_encrypted: Vec<u8>,
        from_email: &str,
        from_name: Option<&str>,
        encryption_key_id: Option<&str>,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.smtp_host = Set(Some(host.to_string()));
        org_active.smtp_port = Set(Some(port as i32));
        org_active.smtp_username = Set(Some(username.to_string()));
        org_active.smtp_password_encrypted = Set(Some(password_encrypted));
        org_active.smtp_from_email = Set(Some(from_email.to_string()));
        org_active.smtp_from_name = Set(from_name.map(|s| s.to_string()));
        org_active.smtp_encryption_key_id = Set(encryption_key_id.map(|s| s.to_string()));
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// Clear organization SMTP configuration
    pub async fn clear_smtp_config(db: DB<'_>, org_id: &str) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.smtp_host = Set(None);
        org_active.smtp_port = Set(None);
        org_active.smtp_username = Set(None);
        org_active.smtp_password_encrypted = Set(None);
        org_active.smtp_from_email = Set(None);
        org_active.smtp_from_name = Set(None);
        org_active.smtp_encryption_key_id = Set(None);
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }

    /// List organizations for a user with optional status filter
    /// Uses JOIN through memberships
    pub async fn list_by_user_with_status(
        db: DB<'_>,
        user_id: &str,
        status: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<organizations::Model>> {
        use sea_orm::{JoinType, QueryOrder, QuerySelect, RelationTrait};

        let mut query = Organizations::find()
            .select_only()
            .column(organizations::Column::Id)
            .column(organizations::Column::Slug)
            .column(organizations::Column::Name)
            .column(organizations::Column::OwnerUserId)
            .column(organizations::Column::Status)
            .column(organizations::Column::TierId)
            .column(organizations::Column::MaxServices)
            .column(organizations::Column::MaxUsers)
            .column(organizations::Column::ApprovedBy)
            .column(organizations::Column::ApprovedAt)
            .column(organizations::Column::RejectedBy)
            .column(organizations::Column::RejectedAt)
            .column(organizations::Column::CustomDomain)
            .column(organizations::Column::DomainVerified)
            .column(organizations::Column::DomainVerificationToken)
            .column(organizations::Column::SmtpHost)
            .column(organizations::Column::SmtpPort)
            .column(organizations::Column::SmtpUsername)
            .column(organizations::Column::SmtpPasswordEncrypted)
            .column(organizations::Column::SmtpFromEmail)
            .column(organizations::Column::SmtpFromName)
            .column(organizations::Column::SmtpEncryptionKeyId)
            .column(organizations::Column::BrandLogoUrl)
            .column(organizations::Column::BrandPrimaryColor)
            .column(organizations::Column::CreatedAt)
            .column(organizations::Column::UpdatedAt)
            .join(
                JoinType::InnerJoin,
                organizations::Relation::Memberships.def(),
            )
            .filter(memberships::Column::UserId.eq(user_id));

        if let Some(status_filter) = status {
            query = query.filter(organizations::Column::Status.eq(status_filter));
        }

        let orgs = query
            .order_by_asc(memberships::Column::CreatedAt)
            .limit(limit)
            .offset(offset)
            .into_model::<organizations::Model>()
            .all(&db)
            .await?;

        Ok(orgs)
    }

    /// Count organizations with optional filters (status and/or tier_id)
    pub async fn count_with_filters(
        db: DB<'_>,
        status: Option<&str>,
        tier_id: Option<&str>,
    ) -> Result<u64> {
        let mut query = Organizations::find();

        if let Some(status_filter) = status {
            query = query.filter(organizations::Column::Status.eq(status_filter));
        }
        if let Some(tier_filter) = tier_id {
            query = query.filter(organizations::Column::TierId.eq(tier_filter));
        }

        let count = query.count(&db).await?;
        Ok(count)
    }

    /// Count all organizations
    pub async fn count_all(db: DB<'_>) -> Result<u64> {
        let count = Organizations::find().count(&db).await?;
        Ok(count)
    }

    /// Count organizations by specific status
    pub async fn count_by_status(db: DB<'_>, status: &str) -> Result<u64> {
        let count = Organizations::find()
            .filter(organizations::Column::Status.eq(status))
            .count(&db)
            .await?;
        Ok(count)
    }

    /// Count organizations grouped by status in one query.
    pub async fn count_by_statuses(db: DB<'_>, statuses: &[&str]) -> Result<HashMap<String, i64>> {
        if statuses.is_empty() {
            return Ok(HashMap::new());
        }

        let rows = Organizations::find()
            .filter(organizations::Column::Status.is_in(statuses.iter().copied()))
            .select_only()
            .column(organizations::Column::Status)
            .column_as(organizations::Column::Id.count(), "count")
            .group_by(organizations::Column::Status)
            .into_model::<StatusCount>()
            .all(&db)
            .await?;

        Ok(rows
            .into_iter()
            .map(|row| (row.status, row.count))
            .collect())
    }

    /// List recent organizations ordered by creation date
    pub async fn list_recent(db: DB<'_>, limit: u64) -> Result<Vec<RecentOrganizationData>> {
        #[derive(FromQueryResult)]
        struct TempResult {
            id: String,
            name: String,
            slug: String,
            status: String,
            created_at: NaiveDateTime,
        }

        let orgs = Organizations::find()
            .select_only()
            .column(organizations::Column::Id)
            .column(organizations::Column::Name)
            .column(organizations::Column::Slug)
            .column(organizations::Column::Status)
            .column(organizations::Column::CreatedAt)
            .order_by_desc(organizations::Column::CreatedAt)
            .limit(limit)
            .into_model::<TempResult>()
            .all(&db)
            .await?;

        let results = orgs
            .into_iter()
            .map(|o| RecentOrganizationData {
                id: o.id,
                name: o.name,
                slug: o.slug,
                status: o.status,
                created_at: o.created_at,
            })
            .collect();

        Ok(results)
    }

    /// List organizations with owner and tier details for platform admin view
    pub async fn list_with_owner_and_tier(
        db: DB<'_>,
        status: Option<&str>,
        tier_id: Option<&str>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<OrgWithOwner>> {
        let mut query = Organizations::find()
            .select_only()
            .column(organizations::Column::Id)
            .column(organizations::Column::Slug)
            .column(organizations::Column::Name)
            .column(organizations::Column::OwnerUserId)
            .column(organizations::Column::Status)
            .column(organizations::Column::TierId)
            .column(organizations::Column::MaxServices)
            .column(organizations::Column::MaxUsers)
            .column(organizations::Column::ApprovedBy)
            .column(organizations::Column::ApprovedAt)
            .column(organizations::Column::RejectedBy)
            .column(organizations::Column::RejectedAt)
            .column(organizations::Column::RejectionReason)
            .column(organizations::Column::CustomDomain)
            .column(organizations::Column::DomainVerified)
            .column(organizations::Column::DomainVerificationToken)
            .column(organizations::Column::BrandLogoUrl)
            .column(organizations::Column::BrandPrimaryColor)
            .column(organizations::Column::FeatureOverrides)
            .column(organizations::Column::CreatedAt)
            .column(organizations::Column::UpdatedAt)
            .column_as(users::Column::Id, "owner_id")
            .column_as(users::Column::Email, "owner_email")
            .column_as(users::Column::IsPlatformOwner, "owner_is_platform_owner")
            .column_as(users::Column::CreatedAt, "owner_created_at")
            .join(JoinType::LeftJoin, organizations::Relation::Users1.def());

        // Apply filters
        if let Some(status_filter) = status {
            query = query.filter(organizations::Column::Status.eq(status_filter));
        }
        if let Some(tier_filter) = tier_id {
            query = query.filter(organizations::Column::TierId.eq(tier_filter));
        }

        // Apply ordering and pagination
        let results = query
            .order_by_desc(organizations::Column::CreatedAt)
            .limit(limit)
            .offset(offset)
            .into_model::<OrgWithOwner>()
            .all(&db)
            .await?;

        Ok(results)
    }

    /// Get top organizations by activity for platform analytics
    pub async fn get_top_organizations(db: DB<'_>, limit: u64) -> Result<Vec<TopOrganizationData>> {
        use chrono::{Duration, Utc};
        use sea_orm::sea_query::Expr;

        if limit == 0 {
            return Ok(Vec::new());
        }

        let orgs = Organizations::find()
            .filter(organizations::Column::Status.eq("active"))
            .all(&db)
            .await?;
        if orgs.is_empty() {
            return Ok(Vec::new());
        }

        let org_ids: Vec<String> = orgs.iter().map(|org| org.id.clone()).collect();
        let thirty_days_ago = (Utc::now() - Duration::days(30)).naive_utc();
        let service_counts = Services::find()
            .filter(services::Column::OrgId.is_in(org_ids.iter().cloned()))
            .select_only()
            .column(services::Column::OrgId)
            .column_as(services::Column::Id.count(), "count")
            .group_by(services::Column::OrgId)
            .into_model::<CountByOrg>()
            .all(&db)
            .await?
            .into_iter()
            .map(|row| (row.org_id, row.count))
            .collect::<HashMap<_, _>>();

        let direct_users = LoginEvents::find()
            .filter(login_events::Column::ServiceId.is_null())
            .filter(login_events::Column::OrgId.is_in(org_ids.iter().cloned()))
            .select_only()
            .column_as(login_events::Column::OrgId, "org_id")
            .column_as(login_events::Column::UserId, "user_id")
            .group_by(login_events::Column::OrgId)
            .group_by(login_events::Column::UserId)
            .into_model::<DistinctLoginUserByOrg>()
            .all(&db)
            .await?;
        let service_users = LoginEvents::find()
            .join(JoinType::InnerJoin, login_events::Relation::Services.def())
            .filter(services::Column::OrgId.is_in(org_ids.iter().cloned()))
            .filter(
                sea_orm::Condition::any()
                    .add(login_events::Column::OrgId.is_null())
                    .add(
                        Expr::col((login_events::Entity, login_events::Column::OrgId))
                            .equals((services::Entity, services::Column::OrgId)),
                    ),
            )
            .select_only()
            .column_as(services::Column::OrgId, "org_id")
            .column_as(login_events::Column::UserId, "user_id")
            .group_by(services::Column::OrgId)
            .group_by(login_events::Column::UserId)
            .into_model::<DistinctLoginUserByOrg>()
            .all(&db)
            .await?;
        let user_counts = direct_users
            .into_iter()
            .chain(service_users)
            .map(|row| (row.org_id, row.user_id))
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .fold(HashMap::new(), |mut counts, (org_id, _)| {
                *counts.entry(org_id).or_insert(0) += 1;
                counts
            });

        let direct_login_counts = LoginEvents::find()
            .filter(login_events::Column::ServiceId.is_null())
            .filter(login_events::Column::OrgId.is_in(org_ids.iter().cloned()))
            .filter(login_events::Column::CreatedAt.gte(thirty_days_ago))
            .select_only()
            .column_as(login_events::Column::OrgId, "org_id")
            .column_as(
                Expr::col((login_events::Entity, login_events::Column::Id)).count(),
                "count",
            )
            .group_by(login_events::Column::OrgId)
            .into_model::<CountByOrg>()
            .all(&db)
            .await?;
        let service_login_counts = LoginEvents::find()
            .join(JoinType::InnerJoin, login_events::Relation::Services.def())
            .filter(services::Column::OrgId.is_in(org_ids.iter().cloned()))
            .filter(
                sea_orm::Condition::any()
                    .add(login_events::Column::OrgId.is_null())
                    .add(
                        Expr::col((login_events::Entity, login_events::Column::OrgId))
                            .equals((services::Entity, services::Column::OrgId)),
                    ),
            )
            .filter(login_events::Column::CreatedAt.gte(thirty_days_ago))
            .select_only()
            .column_as(services::Column::OrgId, "org_id")
            .column_as(
                Expr::col((login_events::Entity, login_events::Column::Id)).count(),
                "count",
            )
            .group_by(services::Column::OrgId)
            .into_model::<CountByOrg>()
            .all(&db)
            .await?;
        let login_counts_30d = direct_login_counts
            .into_iter()
            .chain(service_login_counts)
            .fold(HashMap::new(), |mut counts, row| {
                *counts.entry(row.org_id).or_insert(0) += row.count;
                counts
            });

        let mut results: Vec<TopOrganizationData> = orgs
            .into_iter()
            .map(|org| {
                let user_count = *user_counts.get(&org.id).unwrap_or(&0);
                let service_count = *service_counts.get(&org.id).unwrap_or(&0);
                let login_count_30d = *login_counts_30d.get(&org.id).unwrap_or(&0);

                TopOrganizationData {
                    id: org.id,
                    name: org.name,
                    slug: org.slug,
                    user_count,
                    service_count,
                    login_count_30d,
                }
            })
            .collect();

        // Sort by login count (desc), then user count (desc)
        results.sort_by(|a, b| {
            b.login_count_30d
                .cmp(&a.login_count_30d)
                .then(b.user_count.cmp(&a.user_count))
        });

        // Limit results
        results.truncate(usize::try_from(limit).unwrap_or(usize::MAX));

        Ok(results)
    }

    /// Get organization growth trends by date
    pub async fn get_growth_trends(
        db: DB<'_>,
        start_date: chrono::NaiveDateTime,
        end_date: chrono::NaiveDateTime,
    ) -> Result<Vec<GrowthTrendData>> {
        use sea_orm::sea_query::{Alias, Expr, SimpleExpr};

        // Use DATE() function - works in SQLite, MySQL, PostgreSQL
        let date_expr: SimpleExpr =
            Expr::cust_with_expr("DATE($1)", Expr::col(organizations::Column::CreatedAt));

        let trends = Organizations::find()
            .select_only()
            .column_as(date_expr.clone(), "date")
            .column_as(Expr::col(organizations::Column::Id).count(), "count")
            .filter(organizations::Column::CreatedAt.gte(start_date))
            .filter(organizations::Column::CreatedAt.lte(end_date))
            .group_by(date_expr)
            .order_by_asc(Expr::col(Alias::new("date")))
            .into_model::<GrowthTrendData>()
            .all(&db)
            .await?;

        Ok(trends)
    }

    /// Delete an organization (cascading delete via database constraints)
    pub async fn delete(db: DB<'_>, org_id: &str) -> Result<()> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let org_active: organizations::ActiveModel = org.into();
        org_active.delete(&db).await?;

        Ok(())
    }

    /// Get OAuth client for an organization and provider
    /// Returns a configured BasicClient using organization's BYOO credentials
    pub async fn get_oauth_client_for_org(
        db: DB<'_>,
        org_id: &str,
        provider: Provider,
        encryption_service: &crate::encryption::EncryptionService,
    ) -> Result<ConfiguredBasicClient> {
        let provider_str = provider.as_str();

        // Get organization's OAuth credentials
        let credentials = Self::get_oauth_credentials(db, org_id, provider_str)
            .await?
            .ok_or_else(|| {
                AppError::OAuth(format!(
                    "BYOO credentials not found for organization '{}' and provider '{}'",
                    org_id, provider_str
                ))
            })?;

        // Decrypt the client secret
        let client_secret = encryption_service
            .decrypt_with_context(
                &credentials.client_secret_encrypted,
                crate::encryption::EncryptionContext::new(
                    "organization_oauth_credentials",
                    &credentials.id,
                    "client_secret_encrypted",
                ),
            )
            .map_err(|e| {
                AppError::InternalServerError(format!("Failed to decrypt client secret: {}", e))
            })?;

        // Load configuration
        let config =
            Config::from_env().map_err(|e| AppError::InternalServerError(e.to_string()))?;

        // Create and return the OAuth client
        create_custom_oauth_client(&config, provider, &credentials.client_id, &client_secret)
    }

    /// Count organizations owned by a specific user (non-deleted, non-rejected)
    /// Used for rate limiting organization creation per user
    pub async fn count_by_owner(db: DB<'_>, owner_user_id: &str) -> Result<u64> {
        let count = Organizations::find()
            .filter(organizations::Column::OwnerUserId.eq(owner_user_id))
            .filter(organizations::Column::Status.ne("rejected"))
            .count(&db)
            .await?;
        Ok(count)
    }

    /// Update organization's feature overrides JSON
    /// Used by platform admins to customize features for specific organizations
    pub async fn update_feature_overrides(
        db: DB<'_>,
        org_id: &str,
        overrides_json: Option<&str>,
    ) -> Result<organizations::Model> {
        let org = Self::find_by_id(db.clone(), org_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

        let mut org_active: organizations::ActiveModel = org.into();
        org_active.feature_overrides = Set(overrides_json.map(|s| s.to_string()));
        org_active.updated_at = Set(chrono::Utc::now().naive_utc());

        let updated_org = org_active.update(&db).await?;
        Ok(updated_org)
    }
}

/// Create a custom OAuth client using provided credentials
fn create_custom_oauth_client(
    config: &Config,
    provider: Provider,
    client_id: &str,
    client_secret: &str,
) -> Result<ConfiguredBasicClient> {
    let callback_uri = format!("{}/auth/{}/callback", config.base_url, provider.as_str());
    build_oauth_client(
        provider,
        client_id.to_string(),
        client_secret.to_string(),
        callback_uri,
        config,
    )
}

/// Build an OAuth client for a specific provider
/// Uses platform OAuth URLs from config (supporting mock server in test environments)
fn build_oauth_client(
    provider: Provider,
    client_id: String,
    client_secret: String,
    callback_uri: String,
    config: &Config,
) -> Result<ConfiguredBasicClient> {
    // Use config OAuth URLs (defaults to real provider URLs if not set)
    let (auth_url, token_url) = match provider {
        Provider::Github => {
            let auth = config
                .platform_github_auth_url
                .as_deref()
                .unwrap_or("https://github.com/login/oauth/authorize");
            let token = config
                .platform_github_token_url
                .as_deref()
                .unwrap_or("https://github.com/login/oauth/access_token");
            (auth.to_string(), token.to_string())
        }
        Provider::Google => {
            let auth = config
                .platform_google_auth_url
                .as_deref()
                .unwrap_or("https://accounts.google.com/o/oauth2/v2/auth");
            let token = config
                .platform_google_token_url
                .as_deref()
                .unwrap_or("https://oauth2.googleapis.com/token");
            (auth.to_string(), token.to_string())
        }
        Provider::Microsoft => {
            let auth = config
                .platform_microsoft_auth_url
                .as_deref()
                .unwrap_or("https://login.microsoftonline.com/common/oauth2/v2.0/authorize");
            let token = config
                .platform_microsoft_token_url
                .as_deref()
                .unwrap_or("https://login.microsoftonline.com/common/oauth2/v2.0/token");
            (auth.to_string(), token.to_string())
        }
        Provider::Oidc => {
            return Err(AppError::InternalServerError(
                "OIDC not supported in organizations::build_oauth_client".to_string(),
            ))
        }
        Provider::Password => {
            return Err(AppError::InternalServerError(
                "Password provider not supported in organizations::build_oauth_client".to_string(),
            ))
        }
    };

    configured_basic_client(client_id, client_secret, auth_url, token_url, callback_uri)
}

/// Result structure for organization with owner details
#[derive(Debug, FromQueryResult)]
pub struct OrgWithOwner {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub owner_user_id: String,
    pub status: String,
    pub tier_id: Option<String>,
    pub max_services: Option<i32>,
    pub max_users: Option<i32>,
    pub approved_by: Option<String>,
    pub approved_at: Option<NaiveDateTime>,
    pub rejected_by: Option<String>,
    pub rejected_at: Option<NaiveDateTime>,
    pub rejection_reason: Option<String>,
    pub custom_domain: Option<String>,
    pub domain_verified: bool,
    pub domain_verification_token: Option<String>,
    pub brand_logo_url: Option<String>,
    pub brand_primary_color: Option<String>,
    pub feature_overrides: Option<String>,
    pub created_at: NaiveDateTime,
    pub updated_at: NaiveDateTime,
    pub owner_id: Option<String>,
    pub owner_email: Option<String>,
    pub owner_is_platform_owner: Option<bool>,
    pub owner_created_at: Option<NaiveDateTime>,
}

/// Recent organization data
#[derive(Debug, FromQueryResult)]
pub struct RecentOrganizationData {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub status: String,
    pub created_at: NaiveDateTime,
}

/// Top organization analytics data
#[derive(Debug, FromQueryResult)]
pub struct TopOrganizationData {
    pub id: String,
    pub name: String,
    pub slug: String,
    pub user_count: i64,
    pub service_count: i64,
    pub login_count_30d: i64,
}

/// Growth trend data point
#[derive(Debug, FromQueryResult)]
pub struct GrowthTrendData {
    pub date: String,
    pub count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::login_events::LoginEventStore;
    use crate::store::services::ServiceStore;
    use crate::store::users::{UserCreationOptions, UserStore};
    use chrono::{Duration, Utc};
    use migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, IntoActiveModel, PaginatorTrait};

    #[tokio::test]
    async fn count_by_statuses_groups_requested_statuses_in_one_result() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "org-status-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;

        let org_a =
            OrganizationStore::create(DB::Conn(&db), "status-a", "Status A", &owner.id, None)
                .await
                .expect("create org a");
        let org_b =
            OrganizationStore::create(DB::Conn(&db), "status-b", "Status B", &owner.id, None)
                .await
                .expect("create org b");
        let org_c =
            OrganizationStore::create(DB::Conn(&db), "status-c", "Status C", &owner.id, None)
                .await
                .expect("create org c");

        let mut active_a = org_a.into_active_model();
        active_a.status = Set("active".to_string());
        active_a.update(&db).await.expect("set active");

        let mut active_c = org_c.into_active_model();
        active_c.status = Set("suspended".to_string());
        active_c.update(&db).await.expect("set suspended");

        let counts = OrganizationStore::count_by_statuses(
            DB::Conn(&db),
            &["active", "pending", "suspended", "rejected"],
        )
        .await
        .expect("count statuses");

        assert_eq!(*counts.get("active").unwrap_or(&0), 1);
        assert_eq!(*counts.get("pending").unwrap_or(&0), 1);
        assert_eq!(*counts.get("suspended").unwrap_or(&0), 1);
        assert_eq!(*counts.get("rejected").unwrap_or(&0), 0);
        assert!(!counts.contains_key("status-a"));
        assert_eq!(org_b.status, "pending");
    }

    #[tokio::test]
    async fn get_top_organizations_groups_activity_without_per_org_queries() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let audit_reconciler = crate::services::audit_actor::AuditHandle::new(db.clone());

        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "top-owner@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let user_a = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "top-user-a@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user a")
        .0;
        let user_b = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "top-user-b@example.com",
            UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create user b")
        .0;

        let active_high =
            OrganizationStore::create(DB::Conn(&db), "active-high", "Active High", &owner.id, None)
                .await
                .expect("create active high");
        let active_low =
            OrganizationStore::create(DB::Conn(&db), "active-low", "Active Low", &owner.id, None)
                .await
                .expect("create active low");
        let pending =
            OrganizationStore::create(DB::Conn(&db), "pending", "Pending", &owner.id, None)
                .await
                .expect("create pending");

        for org in [&active_high, &active_low] {
            let mut model = org.clone().into_active_model();
            model.status = Set("active".to_string());
            model.update(&db).await.expect("activate org");
        }

        let high_service_a = ServiceStore::create_with_options(
            DB::Conn(&db),
            "svc-high-a",
            &active_high.id,
            "high-a",
            "High A",
            "web",
            "client-high-a",
            "secret-hash",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create high service a");
        ServiceStore::create_with_options(
            DB::Conn(&db),
            "svc-high-b",
            &active_high.id,
            "high-b",
            "High B",
            "web",
            "client-high-b",
            "secret-hash",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create high service b");
        let low_service = ServiceStore::create_with_options(
            DB::Conn(&db),
            "svc-low",
            &active_low.id,
            "low",
            "Low",
            "web",
            "client-low",
            "secret-hash",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create low service");
        let pending_service = ServiceStore::create_with_options(
            DB::Conn(&db),
            "svc-pending",
            &pending.id,
            "pending",
            "Pending",
            "web",
            "client-pending",
            "secret-hash",
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
        .expect("create pending service");

        LoginEventStore::create(
            DB::Conn(&db),
            &user_a.id,
            Some(&high_service_a.id),
            "password",
        )
        .await
        .expect("create high login 1");
        LoginEventStore::create(
            DB::Conn(&db),
            &user_a.id,
            Some(&high_service_a.id),
            "password",
        )
        .await
        .expect("create high login 2");
        LoginEventStore::create(
            DB::Conn(&db),
            &user_b.id,
            Some(&high_service_a.id),
            "github",
        )
        .await
        .expect("create high login 3");
        LoginEventStore::create(DB::Conn(&db), &user_a.id, Some(&low_service.id), "password")
            .await
            .expect("create low login");
        LoginEventStore::create(
            DB::Conn(&db),
            &user_a.id,
            Some(&pending_service.id),
            "password",
        )
        .await
        .expect("create pending login");

        for _ in 0..50 {
            if crate::entities::login_events::Entity::find()
                .count(&db)
                .await
                .expect("count delivered login events")
                == 5
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(
            crate::entities::login_events::Entity::find()
                .count(&db)
                .await
                .expect("count delivered login events"),
            5
        );

        login_events::ActiveModel {
            id: Set("old-low-login".to_string()),
            user_id: Set(user_b.id.clone()),
            service_id: Set(Some(low_service.id.clone())),
            provider: Set("password".to_string()),
            created_at: Set((Utc::now() - Duration::days(45)).naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .expect("create old login");

        login_events::ActiveModel {
            id: Set("service-less-low-login".to_string()),
            user_id: Set(user_b.id.clone()),
            org_id: Set(Some(active_low.id.clone())),
            service_id: Set(None),
            provider: Set("magic".to_string()),
            created_at: Set(Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .expect("create directly scoped service-less login");

        login_events::ActiveModel {
            id: Set("inconsistent-low-login".to_string()),
            user_id: Set(user_b.id.clone()),
            org_id: Set(Some(active_low.id.clone())),
            service_id: Set(Some(high_service_a.id.clone())),
            provider: Set("passkey".to_string()),
            created_at: Set(Utc::now().naive_utc()),
            ..Default::default()
        }
        .insert(&db)
        .await
        .expect("create inconsistent org/service login");

        let top = OrganizationStore::get_top_organizations(DB::Conn(&db), 10)
            .await
            .expect("get top organizations");

        assert_eq!(top.len(), 2);
        assert_eq!(top[0].slug, "active-high");
        assert_eq!(top[0].service_count, 2);
        assert_eq!(top[0].user_count, 2);
        assert_eq!(top[0].login_count_30d, 3);
        assert_eq!(top[1].slug, "active-low");
        assert_eq!(top[1].service_count, 1);
        assert_eq!(top[1].user_count, 2);
        assert_eq!(top[1].login_count_30d, 2);
        assert!(top.iter().all(|org| org.slug != "pending"));
        audit_reconciler.shutdown().await;
    }
}
