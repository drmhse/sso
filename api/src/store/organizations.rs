use crate::auth::sso::Provider;
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
use uuid::Uuid;

/// OAuth credentials for an organization
#[derive(Debug, FromQueryResult)]
pub struct OrgOAuthCredentials {
    pub client_id: String,
    pub client_secret_encrypted: Vec<u8>,
    pub encryption_key_id: String,
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
        org_active.approved_at = Set(Some(now.clone()));
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
        org_active.rejected_at = Set(Some(now.clone()));
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

        // Get active organizations
        let orgs = Organizations::find()
            .filter(organizations::Column::Status.eq("active"))
            .all(&db)
            .await?;

        let thirty_days_ago = (Utc::now() - Duration::days(30)).naive_utc();

        let mut results = Vec::new();

        for org in orgs {
            // Count services for this org
            let service_count = Services::find()
                .filter(services::Column::OrgId.eq(&org.id))
                .count(&db)
                .await? as i64;

            // Get login events for this org's services
            let svc_models = Services::find()
                .filter(services::Column::OrgId.eq(&org.id))
                .all(&db)
                .await?;

            let service_ids: Vec<String> = svc_models.iter().map(|s| s.id.clone()).collect();

            // Count unique users who logged in (all time)
            let user_count = if !service_ids.is_empty() {
                let user_ids: Vec<String> = LoginEvents::find()
                    .filter(login_events::Column::ServiceId.is_in(service_ids.clone()))
                    .select_only()
                    .column(login_events::Column::UserId)
                    .distinct()
                    .into_tuple()
                    .all(&db)
                    .await?;
                user_ids.len() as i64
            } else {
                0
            };

            // Count logins in last 30 days using SeaORM
            let login_count_30d = if !service_ids.is_empty() {
                use sea_orm::PaginatorTrait;

                let count = LoginEvents::find()
                    .filter(login_events::Column::ServiceId.is_in(service_ids.clone()))
                    .filter(login_events::Column::CreatedAt.gte(thirty_days_ago.clone()))
                    .count(&db)
                    .await?;

                count as i64
            } else {
                0
            };

            results.push(TopOrganizationData {
                id: org.id,
                name: org.name,
                slug: org.slug,
                user_count,
                service_count,
                login_count_30d,
            });
        }

        // Sort by login count (desc), then user count (desc)
        results.sort_by(|a, b| {
            b.login_count_30d
                .cmp(&a.login_count_30d)
                .then(b.user_count.cmp(&a.user_count))
        });

        // Limit results
        results.truncate(limit as usize);

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
    ) -> Result<oauth2::basic::BasicClient> {
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
            .decrypt(&credentials.client_secret_encrypted)
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
) -> Result<oauth2::basic::BasicClient> {
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
) -> Result<oauth2::basic::BasicClient> {
    use oauth2::{basic::BasicClient, AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

    let client_id = ClientId::new(client_id);
    let client_secret = ClientSecret::new(client_secret);
    let redirect_url = RedirectUrl::new(callback_uri)
        .map_err(|e| AppError::InternalServerError(format!("Invalid redirect URL: {}", e)))?;

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
            (
                AuthUrl::new(auth.to_string()).map_err(|e| {
                    AppError::InternalServerError(format!("Invalid GitHub auth URL: {}", e))
                })?,
                TokenUrl::new(token.to_string()).map_err(|e| {
                    AppError::InternalServerError(format!("Invalid GitHub token URL: {}", e))
                })?,
            )
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
            (
                AuthUrl::new(auth.to_string()).map_err(|e| {
                    AppError::InternalServerError(format!("Invalid Google auth URL: {}", e))
                })?,
                TokenUrl::new(token.to_string()).map_err(|e| {
                    AppError::InternalServerError(format!("Invalid Google token URL: {}", e))
                })?,
            )
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
            (
                AuthUrl::new(auth.to_string()).map_err(|e| {
                    AppError::InternalServerError(format!("Invalid Microsoft auth URL: {}", e))
                })?,
                TokenUrl::new(token.to_string()).map_err(|e| {
                    AppError::InternalServerError(format!("Invalid Microsoft token URL: {}", e))
                })?,
            )
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

    Ok(
        BasicClient::new(client_id, Some(client_secret), auth_url, Some(token_url))
            .set_redirect_uri(redirect_url),
    )
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
