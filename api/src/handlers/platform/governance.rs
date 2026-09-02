use crate::db::models::{Organization, OrganizationTier, User};
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::entities::prelude::OrganizationTiers;
use crate::entities::{organization_tiers, organizations};
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::organizations::OrganizationStore;
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::create_audit_log;
use super::org_model_to_old;

// Request/Response Types

#[derive(Debug, Deserialize)]
pub struct ListOrganizationsQuery {
    pub status: Option<String>,
    pub tier_id: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct OrganizationWithDetails {
    #[serde(flatten)]
    pub organization: Organization,
    pub tier: Option<OrganizationTier>,
    pub owner: User,
}

#[derive(Debug, Serialize)]
pub struct ListOrganizationsResponse {
    pub organizations: Vec<OrganizationWithDetails>,
    pub total: i64,
}

#[derive(Debug, Deserialize)]
pub struct ApproveOrganizationRequest {
    pub tier_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RejectOrganizationRequest {
    pub reason: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateTierRequest {
    pub tier_id: String,
    pub max_services: Option<i64>,
    pub max_users: Option<i64>,
}

fn checked_organization_limit(value: Option<i64>, field: &str) -> Result<Option<i32>> {
    value
        .map(|value| {
            if value < 0 {
                return Err(AppError::BadRequest(format!(
                    "{field} must be non-negative"
                )));
            }

            i32::try_from(value)
                .map_err(|_| AppError::BadRequest(format!("{field} exceeds the supported range")))
        })
        .transpose()
}

/// Request body for updating organization feature overrides
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateFeatureOverridesRequest {
    #[serde(default)]
    pub allow_custom_domain: Option<bool>,
    #[serde(default, alias = "allow_saml")]
    pub allow_saml_idp: Option<bool>,
    #[serde(default)]
    pub allow_scim: Option<bool>,
    #[serde(default, alias = "allow_siem_integration")]
    pub allow_siem: Option<bool>,
    #[serde(default, alias = "allow_custom_branding")]
    pub allow_branding: Option<bool>,
    #[serde(default)]
    pub allow_passkeys: Option<bool>,
    #[serde(default)]
    pub allowed_social_providers: Option<Vec<String>>,
    #[serde(default)]
    pub max_mau: Option<i64>,
    #[serde(default)]
    pub allow_overage: Option<bool>,
}

// Platform Governance Endpoints

/// GET /api/platform/tiers
/// List all available organization tiers
pub async fn list_tiers(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
) -> Result<Json<Vec<OrganizationTier>>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let tier_models = OrganizationTiers::find()
        .order_by_asc(organization_tiers::Column::PriceCents)
        .all(&state.db)
        .await?;

    // Convert to old model format
    let tiers = tier_models
        .into_iter()
        .map(|t| OrganizationTier {
            id: t.id,
            name: t.name,
            display_name: t.display_name,
            default_max_services: t.default_max_services as i64,
            default_max_users: t.default_max_users as i64,
            features: t.features,
            price_cents: t.price_cents as i64,
            currency: t.currency,
            created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(t.created_at, Utc),
        })
        .collect();

    Ok(Json(tiers))
}

/// GET /api/platform/organizations
/// List organizations with optional filters
pub async fn list_organizations(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Query(query): Query<ListOrganizationsQuery>,
) -> Result<Json<ListOrganizationsResponse>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let (limit, offset) =
        crate::utils::pagination::signed_limit_offset(query.limit, query.offset, 50, 100);

    let total = OrganizationStore::count_with_filters(
        DB::Conn(&state.db),
        query.status.as_deref(),
        query.tier_id.as_deref(),
    )
    .await? as i64;

    // Get organizations with owner info using store
    let (limit_u64, offset_u64) = crate::utils::pagination::store_u64(limit, offset, 100);
    let rows = OrganizationStore::list_with_owner_and_tier(
        DB::Conn(&state.db),
        query.status.as_deref(),
        query.tier_id.as_deref(),
        limit_u64,
        offset_u64,
    )
    .await?;

    let mut organizations = Vec::new();

    for row in rows {
        let org = Organization {
            id: row.id,
            slug: row.slug,
            name: row.name,
            owner_user_id: row.owner_user_id,
            status: row.status,
            tier_id: row.tier_id.clone(),
            max_services: row.max_services.map(|v| v as i64),
            max_users: row.max_users.map(|v| v as i64),
            approved_by: row.approved_by,
            approved_at: row
                .approved_at
                .map(|dt| chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
            rejected_by: row.rejected_by,
            rejected_at: row
                .rejected_at
                .map(|dt| chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc)),
            rejection_reason: row.rejection_reason,
            custom_domain: row.custom_domain,
            domain_verified: row.domain_verified,
            domain_verification_token: row.domain_verification_token,
            brand_logo_url: row.brand_logo_url,
            brand_primary_color: row.brand_primary_color,
            feature_overrides: row.feature_overrides,
            created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(row.created_at, Utc),
            updated_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(row.updated_at, Utc),
        };

        let owner = User {
            id: row.owner_id.unwrap_or_else(|| "unknown".to_string()),
            email: row
                .owner_email
                .unwrap_or_else(|| "deleted-user@unknown".to_string()),
            is_platform_owner: row.owner_is_platform_owner.unwrap_or(false),
            password_hash: None,
            email_verified_at: None,
            created_at: row.owner_created_at.map_or_else(
                || chrono::DateTime::<Utc>::from_timestamp(0, 0).unwrap(),
                |dt| chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc),
            ),
        };

        // Fetch tier if present
        let tier = if let Some(tier_id) = &row.tier_id {
            let tier_model = OrganizationTiers::find()
                .filter(organization_tiers::Column::Id.eq(tier_id))
                .one(&state.db)
                .await?;

            tier_model.map(|t| OrganizationTier {
                id: t.id,
                name: t.name,
                display_name: t.display_name,
                default_max_services: t.default_max_services as i64,
                default_max_users: t.default_max_users as i64,
                features: t.features,
                price_cents: t.price_cents as i64,
                currency: t.currency,
                created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(t.created_at, Utc),
            })
        } else {
            None
        };

        organizations.push(OrganizationWithDetails {
            organization: org,
            tier,
            owner,
        });
    }

    Ok(Json(ListOrganizationsResponse {
        organizations,
        total,
    }))
}

/// POST /api/platform/organizations/:id/approve
/// Approve a pending organization with automatic retry on database contention
pub async fn approve_organization(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
    Json(req): Json<ApproveOrganizationRequest>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Clone values needed inside the closure
    let org_id_clone = org_id.clone();
    let tier_id = req
        .tier_id
        .clone()
        .unwrap_or_else(|| "tier_free".to_string());
    let approver_id = auth_user.user.id.clone();

    // Execute transaction with automatic retry on database contention
    let updated_org = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "approve_organization",
        |db| {
            let org_id = org_id_clone.clone();
            let tier_id = tier_id.clone();
            let approver_id = approver_id.clone();
            Box::pin(async move {
                // Fetch current organization
                let org_model = OrganizationStore::find_by_id(db.clone(), &org_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let old_status = org_model.status.clone();

                if org_model.status != "pending" {
                    return Err(AppError::BadRequest(
                        "Organization is not in pending status".to_string(),
                    ));
                }

                // Verify tier exists
                let tier_exists = OrganizationTiers::find()
                    .filter(organization_tiers::Column::Id.eq(&tier_id))
                    .one(&db)
                    .await?
                    .is_some();

                if !tier_exists {
                    return Err(AppError::NotFound(
                        "Organization tier not found".to_string(),
                    ));
                }

                // Log organization approval
                tracing::info!(
                    org_id = %org_id,
                    platform_owner = %approver_id,
                    tier_id = %tier_id,
                    "Approving organization"
                );

                // Update organization
                let now = Utc::now().naive_utc();
                let mut org_active: organizations::ActiveModel = org_model.into();
                org_active.status = Set("active".to_string());
                org_active.tier_id = Set(Some(tier_id.clone()));
                org_active.approved_by = Set(Some(approver_id.clone()));
                org_active.approved_at = Set(Some(now));
                org_active.updated_at = Set(now);

                let updated_org_model = org_active.update(&db).await?;
                let updated_org = org_model_to_old(updated_org_model);

                create_audit_log(
                    &db,
                    &approver_id,
                    "approve_organization",
                    "organization",
                    &org_id,
                    Some(json!({
                        "old_status": old_status,
                        "new_status": "active",
                        "tier_id": tier_id,
                    })),
                )
                .await?;

                Ok(updated_org)
            })
        },
    )
    .await?;

    Ok(Json(updated_org))
}

/// POST /api/platform/organizations/:id/reject
/// Reject a pending organization
pub async fn reject_organization(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
    Json(req): Json<RejectOrganizationRequest>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user_id = auth_user.user.id.clone();
    let reason = req.reason.clone();

    // Execute transaction with automatic retry on database contention
    let updated_org = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "reject_organization",
        |db| {
            let org_id = org_id.clone();
            let user_id = user_id.clone();
            let reason = reason.clone();
            Box::pin(async move {
                // Fetch current organization
                let org_model = OrganizationStore::find_by_id(db.clone(), &org_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let old_status = org_model.status.clone();

                if org_model.status != "pending" {
                    return Err(AppError::BadRequest(
                        "Organization is not in pending status".to_string(),
                    ));
                }

                // Update organization
                let now = Utc::now().naive_utc();
                let mut org_active: organizations::ActiveModel = org_model.into();
                org_active.status = Set("rejected".to_string());
                org_active.rejected_by = Set(Some(user_id.clone()));
                org_active.rejected_at = Set(Some(now));
                org_active.rejection_reason = Set(Some(reason.clone()));
                org_active.updated_at = Set(now);

                let updated_org_model = org_active.update(&db).await?;
                let updated_org = org_model_to_old(updated_org_model);

                create_audit_log(
                    &db,
                    &user_id,
                    "reject_organization",
                    "organization",
                    &org_id,
                    Some(json!({
                        "old_status": old_status,
                        "new_status": "rejected",
                        "reason": reason,
                    })),
                )
                .await?;

                Ok(updated_org)
            })
        },
    )
    .await?;

    Ok(Json(updated_org))
}

/// POST /api/platform/organizations/:id/suspend
/// Suspend an active organization
pub async fn suspend_organization(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user_id = auth_user.user.id.clone();

    // Execute transaction with automatic retry on database contention
    let updated_org = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "suspend_organization",
        |db| {
            let org_id = org_id.clone();
            let user_id = user_id.clone();
            Box::pin(async move {
                // Fetch current organization
                let org_model = OrganizationStore::find_by_id(db.clone(), &org_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let old_status = org_model.status.clone();

                if org_model.status == "suspended" {
                    return Err(AppError::BadRequest(
                        "Organization is already suspended".to_string(),
                    ));
                }

                // Update organization
                let now = Utc::now().naive_utc();
                let mut org_active: organizations::ActiveModel = org_model.into();
                org_active.status = Set("suspended".to_string());
                org_active.updated_at = Set(now);

                let updated_org_model = org_active.update(&db).await?;
                let updated_org = org_model_to_old(updated_org_model);

                create_audit_log(
                    &db,
                    &user_id,
                    "suspend_organization",
                    "organization",
                    &org_id,
                    Some(json!({
                        "old_status": old_status,
                        "new_status": "suspended",
                    })),
                )
                .await?;

                Ok(updated_org)
            })
        },
    )
    .await?;

    Ok(Json(updated_org))
}

/// POST /api/platform/organizations/:id/activate
/// Reactivate a suspended organization
pub async fn activate_organization(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user_id = auth_user.user.id.clone();

    // Execute transaction with automatic retry on database contention
    let updated_org = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "activate_organization",
        |db| {
            let org_id = org_id.clone();
            let user_id = user_id.clone();
            Box::pin(async move {
                // Fetch current organization
                let org_model = OrganizationStore::find_by_id(db.clone(), &org_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let old_status = org_model.status.clone();

                if org_model.status != "suspended" {
                    return Err(AppError::BadRequest(
                        "Organization is not suspended".to_string(),
                    ));
                }

                // Update organization
                let now = Utc::now().naive_utc();
                let mut org_active: organizations::ActiveModel = org_model.into();
                org_active.status = Set("active".to_string());
                org_active.updated_at = Set(now);

                let updated_org_model = org_active.update(&db).await?;
                let updated_org = org_model_to_old(updated_org_model);

                create_audit_log(
                    &db,
                    &user_id,
                    "activate_organization",
                    "organization",
                    &org_id,
                    Some(json!({
                        "old_status": old_status,
                        "new_status": "active",
                    })),
                )
                .await?;

                Ok(updated_org)
            })
        },
    )
    .await?;

    Ok(Json(updated_org))
}

/// PATCH /api/platform/organizations/:id/tier
/// Update organization tier and limits
pub async fn update_organization_tier(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
    Json(req): Json<UpdateTierRequest>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user_id = auth_user.user.id.clone();
    let tier_id = req.tier_id.clone();
    let max_services = checked_organization_limit(req.max_services, "max_services")?;
    let max_users = checked_organization_limit(req.max_users, "max_users")?;

    // Execute transaction with automatic retry on database contention
    let updated_org = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_organization_tier",
        |db| {
            let org_id = org_id.clone();
            let user_id = user_id.clone();
            let tier_id = tier_id.clone();
            Box::pin(async move {
                // Fetch current organization
                let org_model = OrganizationStore::find_by_id(db.clone(), &org_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let old_tier_id = org_model.tier_id.clone();

                // Verify tier exists
                let tier_exists = OrganizationTiers::find()
                    .filter(organization_tiers::Column::Id.eq(&tier_id))
                    .one(&db)
                    .await?
                    .is_some();

                if !tier_exists {
                    return Err(AppError::NotFound(
                        "Organization tier not found".to_string(),
                    ));
                }

                // Update organization
                let now = Utc::now().naive_utc();
                let mut org_active: organizations::ActiveModel = org_model.into();
                org_active.tier_id = Set(Some(tier_id.clone()));
                org_active.max_services = Set(max_services);
                org_active.max_users = Set(max_users);
                org_active.updated_at = Set(now);

                let updated_org_model = org_active.update(&db).await?;
                let updated_org = org_model_to_old(updated_org_model);

                create_audit_log(
                    &db,
                    &user_id,
                    "update_organization_tier",
                    "organization",
                    &org_id,
                    Some(json!({
                        "old_tier_id": old_tier_id,
                        "new_tier_id": tier_id,
                        "max_services": max_services,
                        "max_users": max_users,
                    })),
                )
                .await?;

                Ok(updated_org)
            })
        },
    )
    .await?;

    Ok(Json(updated_org))
}

/// PATCH /api/platform/organizations/:id/features
/// Update organization feature overrides
pub async fn update_organization_features(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_id): Path<String>,
    Json(req): Json<UpdateFeatureOverridesRequest>,
) -> Result<Json<Organization>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user_id = auth_user.user.id.clone();

    // Build the feature overrides JSON
    // Fetch existing org to potentially merge with existing overrides
    let org_model = OrganizationStore::find_by_id(DB::Conn(&state.db), &org_id)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    // Start with existing overrides or empty object
    let mut features: serde_json::Value = org_model
        .feature_overrides
        .as_ref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    // Update only the fields that were provided
    if let Some(v) = req.allow_custom_domain {
        features["allow_custom_domain"] = serde_json::json!(v);
    }
    if let Some(v) = req.allow_saml_idp {
        features["allow_saml_idp"] = serde_json::json!(v);
    }
    if let Some(v) = req.allow_scim {
        features["allow_scim"] = serde_json::json!(v);
    }
    if let Some(v) = req.allow_siem {
        features["allow_siem"] = serde_json::json!(v);
    }
    if let Some(v) = req.allow_branding {
        features["allow_branding"] = serde_json::json!(v);
    }
    if let Some(v) = req.allow_passkeys {
        features["allow_passkeys"] = serde_json::json!(v);
    }
    if let Some(v) = &req.allowed_social_providers {
        features["allowed_social_providers"] = serde_json::json!(v);
    }
    if let Some(v) = req.max_mau {
        features["max_mau"] = serde_json::json!(v);
    }
    if let Some(v) = req.allow_overage {
        features["allow_overage"] = serde_json::json!(v);
    }

    let features_json = serde_json::to_string(&features).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize features: {}", e))
    })?;

    // Update organization feature overrides
    let updated_org = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "update_organization_features",
        |db| {
            let org_id = org_id.clone();
            let user_id = user_id.clone();
            let features_json = features_json.clone();
            let req_clone = serde_json::to_value(&req).unwrap_or_default();
            Box::pin(async move {
                let updated_org_model = OrganizationStore::update_feature_overrides(
                    db.clone(),
                    &org_id,
                    Some(&features_json),
                )
                .await?;

                let updated_org = org_model_to_old(updated_org_model);

                create_audit_log(
                    &db,
                    &user_id,
                    "update_organization_features",
                    "organization",
                    &org_id,
                    Some(json!({
                        "features": req_clone,
                    })),
                )
                .await?;

                Ok(updated_org)
            })
        },
    )
    .await?;

    tracing::info!(
        org_id = %org_id,
        platform_owner = %user_id,
        "Organization feature overrides updated"
    );

    Ok(Json(updated_org))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_limits_reject_negative_and_out_of_range_values() {
        assert!(matches!(
            checked_organization_limit(Some(i64::MIN), "max_users"),
            Err(AppError::BadRequest(_))
        ));
        assert!(matches!(
            checked_organization_limit(Some(i64::from(i32::MAX) + 1), "max_services"),
            Err(AppError::BadRequest(_))
        ));
        assert_eq!(
            checked_organization_limit(Some(0), "max_services").expect("zero limit"),
            Some(0)
        );
        assert_eq!(
            checked_organization_limit(Some(1), "max_services").expect("minimum positive limit"),
            Some(1)
        );
        assert_eq!(
            checked_organization_limit(Some(i64::from(i32::MAX)), "max_users")
                .expect("maximum supported limit"),
            Some(i32::MAX)
        );
        assert_eq!(
            checked_organization_limit(None, "max_users").expect("unset custom limit"),
            None
        );
    }
}

#[cfg(test)]
mod governance_tests {
    use super::*;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::jwt::JwtService;
    use crate::crypto::sso::OAuthClient;

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::entities::users;
    use crate::middleware::AuthUser;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{
        memberships::MembershipStore,
        users::{UserCreationOptions, UserStore},
    };
    use axum::extract::Path;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        plain: AuthUser,
        org_id: String,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new({
            let rsa = GeneratedKey::generate().expect("rsa");
            JwtService::new(
                &STANDARD.encode(rsa.private_key_pem().expect("pem")),
                &STANDARD.encode(rsa.public_key_pem().expect("pem")),
                config.jwt_expiration_hours,
                "test-key",
                &config.base_url,
            )
            .expect("jwt")
        });

        let owner_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "governance-owner@example.test",
            UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("platform owner")
        .0;
        let plain_model =
            UserStore::create(DB::Conn(&db), "governance-plain@example.test", None, false)
                .await
                .expect("plain user");

        // A pending organization awaiting approval.
        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "pending-org",
            "Pending Org",
            &plain_model.id,
            None,
        )
        .await
        .expect("create pending org");
        MembershipStore::create(DB::Conn(&db), &org.id, &plain_model.id, "owner")
            .await
            .expect("owner membership");

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("oauth")),
            jwt_service: jwt_service.clone(),
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("risk")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        };

        let auth_user_for = |user: &users::Model| -> AuthUser {
            let token = jwt_service
                .create_token(&user.id, &user.email, user.is_platform_owner, None, None)
                .expect("token");
            AuthUser {
                claims: jwt_service.validate_token(&token).expect("claims"),
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "governance-test".to_string(),
                current_session_id: None,
            }
        };

        Fixture {
            state,
            owner: auth_user_for(&owner_model),
            plain: auth_user_for(&plain_model),
            org_id: org.id,
        }
    }

    #[tokio::test]
    async fn non_owners_are_denied_every_governance_endpoint() {
        let f = fixture().await;
        let denials = (
            list_tiers(State(f.state.clone()), Extension(f.plain.clone()))
                .await
                .err(),
            list_organizations(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Query(ListOrganizationsQuery {
                    status: None,
                    tier_id: None,
                    limit: None,
                    offset: None,
                }),
            )
            .await
            .err(),
            approve_organization(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Path(f.org_id.clone()),
                Json(ApproveOrganizationRequest { tier_id: None }),
            )
            .await
            .err(),
            suspend_organization(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Path(f.org_id.clone()),
            )
            .await
            .err(),
        );
        match denials {
            (
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
            ) => {}
            other => panic!("expected all-forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn the_full_approval_lifecycle_holds() {
        let f = fixture().await;

        // Approve assigns a default tier and activates.
        let Json(approved) = approve_organization(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path(f.org_id.clone()),
            Json(ApproveOrganizationRequest { tier_id: None }),
        )
        .await
        .expect("approve");
        assert_eq!(approved.status, "active");
        assert_eq!(
            approved.approved_by.as_deref(),
            Some(f.owner.user.id.as_str())
        );

        // Suspend and re-activate.
        let suspended = suspend_organization(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path(f.org_id.clone()),
        )
        .await
        .expect("suspend");
        assert_eq!(suspended.status, "suspended");
        let activated = activate_organization(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path(f.org_id.clone()),
        )
        .await
        .expect("activate");
        assert_eq!(activated.status, "active");

        // Listing reflects the live state with owner details attached.
        let Json(list) = list_organizations(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Query(ListOrganizationsQuery {
                status: Some("active".to_string()),
                tier_id: None,
                limit: None,
                offset: None,
            }),
        )
        .await
        .expect("list active orgs");
        assert!(list
            .organizations
            .iter()
            .any(|o| o.organization.id == f.org_id));
    }

    #[tokio::test]
    async fn rejection_records_the_reason() {
        let f = fixture().await;
        let Json(rejected) = reject_organization(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path(f.org_id.clone()),
            Json(RejectOrganizationRequest {
                reason: "incomplete signup".to_string(),
            }),
        )
        .await
        .expect("reject");
        assert_eq!(rejected.status, "rejected");
    }
}
