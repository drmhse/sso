use crate::entities::verified_domains;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::domain_verification::{
    normalize_verifiable_domain, verify_dns_txt_record, verify_http_file,
};
use crate::services::permission_service::{PermissionService, CAP_INTEGRATIONS_MANAGE};
use crate::state::AppState;
use crate::store::{
    organizations::OrganizationStore, upstream_providers::UpstreamProviderStore,
    verified_domains::VerifiedDomainStore, DB,
};
use axum::{
    extract::{Path, State},
    Json,
};
use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, Set};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Deserialize)]
pub struct CreateDomainRouteRequest {
    pub domain: String,
    pub upstream_provider_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateDomainRouteRequest {
    pub upstream_provider_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DomainRouteResponse {
    pub id: String,
    pub domain: String,
    pub upstream_provider_id: Option<String>,
    pub verification_token: String,
    pub verified: bool,
    pub verified_at: Option<chrono::NaiveDateTime>,
    pub created_at: chrono::NaiveDateTime,
    pub updated_at: chrono::NaiveDateTime,
}

fn to_response(model: verified_domains::Model) -> DomainRouteResponse {
    DomainRouteResponse {
        id: model.id,
        domain: model.domain,
        upstream_provider_id: model.upstream_provider_id,
        verification_token: model.verification_token,
        verified: model.verified,
        verified_at: model.verified_at,
        created_at: model.created_at,
        updated_at: model.updated_at,
    }
}

async fn require_integration_manager(state: &AppState, org_id: &str, user_id: &str) -> Result<()> {
    if PermissionService::check(
        DB::Conn(&state.db),
        org_id,
        user_id,
        CAP_INTEGRATIONS_MANAGE,
    )
    .await?
    {
        return Ok(());
    }

    Err(AppError::Forbidden(
        "Insufficient permissions to manage integrations".to_string(),
    ))
}

fn normalize_domain(domain: &str) -> Result<String> {
    normalize_verifiable_domain(domain)
}

async fn ensure_provider_belongs_to_org(
    state: &AppState,
    org_id: &str,
    provider_id: Option<&str>,
) -> Result<()> {
    if let Some(provider_id) = provider_id {
        let provider = UpstreamProviderStore::find_by_id(DB::Conn(&state.db), provider_id)
            .await?
            .ok_or_else(|| AppError::NotFound("Upstream provider not found".to_string()))?;

        if provider.org_id != org_id {
            return Err(AppError::NotFound(
                "Upstream provider not found".to_string(),
            ));
        }
    }

    Ok(())
}

pub async fn list_domain_routes(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
) -> Result<Json<Vec<DomainRouteResponse>>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    let domains = VerifiedDomainStore::find_by_org(DB::Conn(&state.db), &org.id).await?;
    Ok(Json(domains.into_iter().map(to_response).collect()))
}

pub async fn create_domain_route(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(org_slug): Path<String>,
    Json(req): Json<CreateDomainRouteRequest>,
) -> Result<Json<DomainRouteResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;
    ensure_provider_belongs_to_org(&state, &org.id, req.upstream_provider_id.as_deref()).await?;

    let domain = normalize_domain(&req.domain)?;
    if VerifiedDomainStore::find_by_domain(DB::Conn(&state.db), &domain)
        .await?
        .is_some()
    {
        return Err(AppError::BadRequest(
            "This domain is already configured".to_string(),
        ));
    }

    let model = VerifiedDomainStore::create(
        DB::Conn(&state.db),
        &Uuid::new_v4().to_string(),
        &org.id,
        &domain,
        &Uuid::new_v4().to_string(),
        req.upstream_provider_id.as_deref(),
    )
    .await?;

    Ok(Json(to_response(model)))
}

pub async fn update_domain_route(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, domain_id)): Path<(String, String)>,
    Json(req): Json<UpdateDomainRouteRequest>,
) -> Result<Json<DomainRouteResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;
    ensure_provider_belongs_to_org(&state, &org.id, req.upstream_provider_id.as_deref()).await?;

    let domain = crate::entities::prelude::VerifiedDomains::find_by_id(&domain_id)
        .one(&state.db)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Domain route not found".to_string()))?;

    if domain.org_id != org.id {
        return Err(AppError::NotFound("Domain route not found".to_string()));
    }

    let mut active = domain.into_active_model();
    active.upstream_provider_id = Set(req.upstream_provider_id);
    active.updated_at = Set(chrono::Utc::now().naive_utc());
    let updated = active.update(&state.db).await.map_err(|e| {
        AppError::InternalServerError(format!("Failed to update domain route: {}", e))
    })?;

    Ok(Json(to_response(updated)))
}

pub async fn verify_domain_route(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, domain_id)): Path<(String, String)>,
) -> Result<Json<DomainRouteResponse>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    let domain = crate::entities::prelude::VerifiedDomains::find_by_id(&domain_id)
        .one(&state.db)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Domain route not found".to_string()))?;

    if domain.org_id != org.id {
        return Err(AppError::NotFound("Domain route not found".to_string()));
    }

    let dns_verified = verify_dns_txt_record(&domain.domain, &domain.verification_token).await;
    let http_verified = verify_http_file(&domain.domain, &domain.verification_token).await;

    if !dns_verified && !http_verified {
        return Err(AppError::BadRequest(
            "Domain verification failed. Add the DNS TXT record or HTTP verification file and try again.".to_string(),
        ));
    }

    let updated = VerifiedDomainStore::mark_verified(DB::Conn(&state.db), &domain_id).await?;
    Ok(Json(to_response(updated)))
}

pub async fn delete_domain_route(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path((org_slug, domain_id)): Path<(String, String)>,
) -> Result<Json<()>> {
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    require_integration_manager(&state, &org.id, &auth_user.user.id).await?;

    let domain = crate::entities::prelude::VerifiedDomains::find_by_id(&domain_id)
        .one(&state.db)
        .await
        .map_err(|e| AppError::InternalServerError(format!("Database error: {}", e)))?
        .ok_or_else(|| AppError::NotFound("Domain route not found".to_string()))?;

    if domain.org_id != org.id {
        return Err(AppError::NotFound("Domain route not found".to_string()));
    }

    VerifiedDomainStore::delete(DB::Conn(&state.db), &domain_id).await?;
    Ok(Json(()))
}
