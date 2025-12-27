use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    db::models::{
        BrandingConfiguration, DomainConfiguration, DomainVerificationMethod,
        DomainVerificationResponse, DomainVerificationResult,
    },
    entities::organizations,
    error::{with_retrying_transaction, AppError},
    middleware::AuthUser,
    state::AppState,
    store::{memberships::MembershipStore, organizations::OrganizationStore, DB},
};
use crate::services::tier_enforcement::TierService;

// Helper function to check if user has owner/admin access
async fn check_owner_or_admin(
    db: &sea_orm::DatabaseConnection,
    org_id: &str,
    user_id: &str,
    is_platform_owner: bool,
) -> Result<(), AppError> {
    if is_platform_owner {
        return Ok(());
    }

    let is_owner_or_admin =
        MembershipStore::is_owner_or_admin(DB::Conn(db), org_id, user_id).await?;

    if is_owner_or_admin {
        Ok(())
    } else {
        Err(AppError::Forbidden(
            "Only organization owners and admins can perform this action".to_string(),
        ))
    }
}

// Request/Response Types

#[derive(Debug, Deserialize)]
pub struct SetCustomDomainRequest {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateBrandingRequest {
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
}

// Domain Management Handlers

pub async fn set_custom_domain(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<SetCustomDomainRequest>,
) -> Result<Json<DomainVerificationResponse>, AppError> {
    // Verify user has permission
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    check_owner_or_admin(
        &state.db,
        &org.id,
        &auth_user.claims.sub,
        auth_user.claims.is_platform_owner,
    )
    .await?;

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_custom_domain,
        "Custom Domain",
    )
    .await?;

    // Validate domain format
    let domain = req.domain.trim().to_lowercase();
    if domain.is_empty() {
        return Err(AppError::BadRequest("domain cannot be empty".to_string()));
    }

    // Basic domain validation - must contain at least one dot and no spaces
    if !domain.contains('.') || domain.contains(' ') {
        return Err(AppError::BadRequest("Invalid domain format".to_string()));
    }

    // Check if domain is already in use by another organization
    use crate::entities::prelude::Organizations;
    let existing = Organizations::find()
        .filter(organizations::Column::CustomDomain.eq(&domain))
        .filter(organizations::Column::Id.ne(&org.id))
        .one(&state.db)
        .await?;

    if existing.is_some() {
        return Err(AppError::BadRequest(
            "This domain is already in use by another organization".to_string(),
        ));
    }

    // Generate verification token
    let verification_token = Uuid::new_v4().to_string();

    // Update organization with new domain and verification token
    let org_id = org.id.clone();
    let domain_clone = domain.clone();
    let verification_token_clone = verification_token.clone();

    with_retrying_transaction(&state.db, #[cfg(feature = "db_sqlite")] &state.db_writer, "set_custom_domain", |db| {
        let org_id = org_id.clone();
        let domain = domain_clone.clone();
        let verification_token = verification_token_clone.clone();
        Box::pin(async move {
            let org_model = Organizations::find()
                .filter(organizations::Column::Id.eq(&org_id))
                .one(&db)
                .await?
                .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

            let mut org_active: organizations::ActiveModel = org_model.into();
            org_active.custom_domain = Set(Some(domain));
            org_active.domain_verified = Set(false);
            org_active.domain_verification_token = Set(Some(verification_token));
            org_active.updated_at = Set(chrono::Utc::now().naive_utc());
            org_active.update(&db).await?;
            Ok(())
        })
    })
    .await?;

    // Non-blocking audit via actor
    use crate::services::audit_builder::OrgAuditBuilder;
    let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.claims.sub), "domain.set")
        .target("organization", &org.id)
        .success(true)
        .details_json(Some(serde_json::json!({ "domain": domain })))
        .build();
    state.audit_actor.log_org(event).await;

    // Return verification instructions
    let verification_methods = vec![
        DomainVerificationMethod {
            method: "DNS TXT Record".to_string(),
            instructions: "Add a TXT record to your domain's DNS settings".to_string(),
            record_type: Some("TXT".to_string()),
            record_name: Some(format!("_sso-verification.{}", domain)),
            record_value: Some(verification_token.clone()),
        },
        DomainVerificationMethod {
            method: "HTTP File".to_string(),
            instructions: format!(
                "Upload a file to http://{}/.well-known/sso-verification.txt containing the verification token",
                domain
            ),
            record_type: None,
            record_name: None,
            record_value: Some(verification_token.clone()),
        },
    ];

    Ok(Json(DomainVerificationResponse {
        verification_token,
        verification_methods,
    }))
}

pub async fn verify_custom_domain(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<DomainVerificationResult>, AppError> {
    // Verify user has permission
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    check_owner_or_admin(
        &state.db,
        &org.id,
        &auth_user.claims.sub,
        auth_user.claims.is_platform_owner,
    )
    .await?;

    // Check if domain is set
    let domain = org
        .custom_domain
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("No custom domain configured".to_string()))?;

    let verification_token = org
        .domain_verification_token
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("No verification token found".to_string()))?;

    // If already verified, return success
    if org.domain_verified {
        return Ok(Json(DomainVerificationResult {
            verified: true,
            message: "Domain is already verified".to_string(),
        }));
    }

    // Attempt DNS verification
    let dns_verified = verify_dns_txt_record(domain, verification_token).await;

    // Attempt HTTP verification
    let http_verified = verify_http_file(domain, verification_token).await;

    if dns_verified || http_verified {
        // Mark domain as verified
        let org_id = org.id.clone();
        with_retrying_transaction(&state.db, #[cfg(feature = "db_sqlite")] &state.db_writer, "verify_custom_domain", |db| {
            let org_id = org_id.clone();
            Box::pin(async move {
                use crate::entities::prelude::Organizations;
                let org_model = Organizations::find()
                    .filter(organizations::Column::Id.eq(&org_id))
                    .one(&db)
                    .await?
                    .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

                let mut org_active: organizations::ActiveModel = org_model.into();
                org_active.domain_verified = Set(true);
                org_active.updated_at = Set(chrono::Utc::now().naive_utc());
                org_active.update(&db).await?;
                Ok(())
            })
        })
        .await?;

        // Non-blocking audit via actor
        use crate::services::audit_builder::OrgAuditBuilder;
        let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.claims.sub), "domain.verified")
            .target("organization", &org.id)
            .success(true)
            .details_json(Some(serde_json::json!({
                "domain": domain,
                "method": if dns_verified { "DNS" } else { "HTTP" }
            })))
            .build();
        state.audit_actor.log_org(event).await;

        Ok(Json(DomainVerificationResult {
            verified: true,
            message: format!(
                "Domain verified successfully via {}",
                if dns_verified {
                    "DNS TXT record"
                } else {
                    "HTTP file"
                }
            ),
        }))
    } else {
        Ok(Json(DomainVerificationResult {
            verified: false,
            message: "Domain verification failed. Please ensure the TXT record or HTTP file is correctly configured.".to_string(),
        }))
    }
}

pub async fn get_domain_configuration(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<DomainConfiguration>, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !auth_user.claims.is_platform_owner {
        let is_member =
            MembershipStore::is_member(DB::Conn(&state.db), &org.id, &auth_user.claims.sub).await?;

        if !is_member {
            return Err(AppError::Forbidden(
                "You must be a member of this organization".to_string(),
            ));
        }
    }

    Ok(Json(DomainConfiguration {
        custom_domain: org.custom_domain,
        domain_verified: org.domain_verified,
    }))
}

pub async fn delete_custom_domain(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<StatusCode, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    check_owner_or_admin(
        &state.db,
        &org.id,
        &auth_user.claims.sub,
        auth_user.claims.is_platform_owner,
    )
    .await?;

    let domain = org.custom_domain.clone();
    let org_id = org.id.clone();

    with_retrying_transaction(&state.db, #[cfg(feature = "db_sqlite")] &state.db_writer, "delete_custom_domain", |db| {
        let org_id = org_id.clone();
        Box::pin(async move {
            use crate::entities::prelude::Organizations;
            let org_model = Organizations::find()
                .filter(organizations::Column::Id.eq(&org_id))
                .one(&db)
                .await?
                .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

            let mut org_active: organizations::ActiveModel = org_model.into();
            org_active.custom_domain = Set(None);
            org_active.domain_verified = Set(false);
            org_active.domain_verification_token = Set(None);
            org_active.updated_at = Set(chrono::Utc::now().naive_utc());
            org_active.update(&db).await?;
            Ok(())
        })
    })
    .await?;

    // Non-blocking audit via actor
    if let Some(domain) = domain {
        use crate::services::audit_builder::OrgAuditBuilder;
        let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.claims.sub), "domain.deleted")
            .target("organization", &org.id)
            .success(true)
            .details_json(Some(serde_json::json!({ "domain": domain })))
            .build();
        state.audit_actor.log_org(event).await;
    }

    Ok(StatusCode::NO_CONTENT)
}

// Branding Management Handlers

pub async fn update_branding(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<UpdateBrandingRequest>,
) -> Result<Json<BrandingConfiguration>, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    check_owner_or_admin(
        &state.db,
        &org.id,
        &auth_user.claims.sub,
        auth_user.claims.is_platform_owner,
    )
    .await?;

    // Tier/Entitlement Check
    TierService::check_feature_access(
        DB::Conn(&state.db),
        &org.id,
        |f| f.allow_branding,
        "Custom Branding",
    )
    .await?;

    // Validate color format if provided
    if let Some(ref color) = req.primary_color {
        // Must start with # and be 4 or 7 characters total
        if !color.starts_with('#') || (color.len() != 7 && color.len() != 4) {
            return Err(AppError::BadRequest(
                "Invalid color format. Must be a hex color (e.g., #FF5733 or #F57)".to_string(),
            ));
        }

        // Validate hex characters after #
        let hex_part = &color[1..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AppError::BadRequest(
                "Invalid color format. Must be a hex color (e.g., #FF5733 or #F57)".to_string(),
            ));
        }
    }

    let org_id = org.id.clone();
    let logo_url = req.logo_url.clone();
    let primary_color = req.primary_color.clone();

    with_retrying_transaction(&state.db, #[cfg(feature = "db_sqlite")] &state.db_writer, "update_branding", |db| {
        let org_id = org_id.clone();
        let logo_url = logo_url.clone();
        let primary_color = primary_color.clone();
        Box::pin(async move {
            use crate::entities::prelude::Organizations;
            let org_model = Organizations::find()
                .filter(organizations::Column::Id.eq(&org_id))
                .one(&db)
                .await?
                .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

            let mut org_active: organizations::ActiveModel = org_model.into();
            org_active.brand_logo_url = Set(logo_url);
            org_active.brand_primary_color = Set(primary_color);
            org_active.updated_at = Set(chrono::Utc::now().naive_utc());
            org_active.update(&db).await?;
            Ok(())
        })
    })
    .await?;

    // Non-blocking audit via actor
    use crate::services::audit_builder::OrgAuditBuilder;
    let event = OrgAuditBuilder::new(&org.id, Some(&auth_user.claims.sub), "branding.updated")
        .target("organization", &org.id)
        .success(true)
        .details_json(Some(serde_json::json!({
            "logo_url": req.logo_url,
            "primary_color": req.primary_color
        })))
        .build();
    state.audit_actor.log_org(event).await;

    Ok(Json(BrandingConfiguration {
        logo_url: req.logo_url,
        primary_color: req.primary_color,
    }))
}

pub async fn get_branding(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<BrandingConfiguration>, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !auth_user.claims.is_platform_owner {
        let is_member =
            MembershipStore::is_member(DB::Conn(&state.db), &org.id, &auth_user.claims.sub).await?;

        if !is_member {
            return Err(AppError::Forbidden(
                "You must be a member of this organization".to_string(),
            ));
        }
    }

    Ok(Json(BrandingConfiguration {
        logo_url: org.brand_logo_url,
        primary_color: org.brand_primary_color,
    }))
}

pub async fn get_public_branding(
    State(state): State<AppState>,
    Path(org_slug): Path<String>,
) -> Result<Json<BrandingConfiguration>, AppError> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    Ok(Json(BrandingConfiguration {
        logo_url: org.brand_logo_url,
        primary_color: org.brand_primary_color,
    }))
}

// Helper functions for domain verification

async fn verify_dns_txt_record(domain: &str, expected_token: &str) -> bool {
    use hickory_resolver::TokioAsyncResolver;

    // Create DNS resolver with system configuration
    let resolver = match TokioAsyncResolver::tokio_from_system_conf() {
        Ok(r) => r,
        Err(_) => return false,
    };

    // Look up TXT records for _sso-verification.{domain}
    let record_name = format!("_sso-verification.{}", domain);

    match resolver.txt_lookup(&record_name).await {
        Ok(records) => {
            // Check if any TXT record matches the expected token
            for record in records.iter() {
                // TXT records can have multiple strings; concatenate them
                let txt_value = record
                    .txt_data()
                    .iter()
                    .map(|data| String::from_utf8_lossy(data.as_ref()))
                    .collect::<Vec<_>>()
                    .join("");

                if txt_value.trim() == expected_token {
                    return true;
                }
            }
            false
        }
        Err(_) => false,
    }
}

async fn verify_http_file(domain: &str, expected_token: &str) -> bool {
    // Try to fetch http://domain/.well-known/sso-verification.txt
    let url = format!("http://{}/.well-known/sso-verification.txt", domain);

    match reqwest::get(&url).await {
        Ok(response) => {
            if let Ok(body) = response.text().await {
                body.trim() == expected_token
            } else {
                false
            }
        }
        Err(_) => false,
    }
}
