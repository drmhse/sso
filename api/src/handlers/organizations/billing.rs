//! Billing handlers for organization billing management

use crate::db::DB;
use crate::entities::billing_customers;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::permission_service::{PermissionService, CAP_BILLING_MANAGE};
use crate::state::AppState;
use crate::store::{memberships::MembershipStore, organizations::OrganizationStore};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};

/// Response for billing portal session creation
#[derive(Debug, Serialize)]
pub struct BillingPortalResponse {
    /// The URL to redirect the user to for the billing portal
    pub url: String,
}

/// Request for billing portal session creation
#[derive(Debug, Deserialize)]
pub struct BillingPortalRequest {
    /// The URL to redirect the user to after they leave the portal
    pub return_url: String,
}

/// POST /api/organizations/:org_slug/billing/portal
/// Creates a billing portal session for self-serve subscription management
pub async fn create_portal_session(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_slug): Path<String>,
    Json(req): Json<BillingPortalRequest>,
) -> Result<Json<BillingPortalResponse>> {
    MembershipStore::find_by_org_slug_and_user(
        DB::Conn(&state.db),
        &org_slug,
        &auth_user.claims.sub,
    )
    .await?
    .ok_or_else(|| AppError::Forbidden("You are not a member of this organization".to_string()))?;

    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_BILLING_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to manage billing".to_string(),
        ));
    }

    let provider_type = state.billing_provider.provider_type();
    if provider_type == crate::billing::BillingProviderType::Disabled {
        return Err(AppError::ServiceUnavailable(
            "Billing is disabled for this AuthOS instance.".to_string(),
        ));
    }

    let billing_customer = billing_customers::Entity::find()
        .filter(billing_customers::Column::OrgId.eq(&org.id))
        .filter(billing_customers::Column::Provider.eq(provider_type.to_string()))
        .one(&state.db)
        .await?;

    let billing_customer = match billing_customer {
        Some(customer) => customer,
        None => {
            // Create on demand if not found (e.g. for existing orgs or if creation failed)
            create_billing_customer(&state, &org.id, &org.name).await?
        }
    };

    let result = state
        .billing_provider
        .create_portal_session(&billing_customer.external_customer_id, &req.return_url)
        .await?;

    Ok(Json(BillingPortalResponse { url: result.url }))
}

/// GET /api/organizations/:org_slug/billing/info
/// Get billing information for the organization
#[derive(Debug, Serialize)]
pub struct BillingInfoResponse {
    pub has_billing_account: bool,
    pub provider: Option<String>,
}

pub async fn get_billing_info(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(org_slug): Path<String>,
) -> Result<Json<BillingInfoResponse>> {
    // Verify membership
    MembershipStore::find_by_org_slug_and_user(
        DB::Conn(&state.db),
        &org_slug,
        &auth_user.claims.sub,
    )
    .await?
    .ok_or_else(|| AppError::Forbidden("You are not a member of this organization".to_string()))?;

    // Get organization
    let org = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    if !PermissionService::check(
        DB::Conn(&state.db),
        &org.id,
        &auth_user.user.id,
        CAP_BILLING_MANAGE,
    )
    .await?
    {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view billing information".to_string(),
        ));
    }

    // Check for billing customer
    let provider_type = state.billing_provider.provider_type();
    if provider_type == crate::billing::BillingProviderType::Disabled {
        return Ok(Json(BillingInfoResponse {
            has_billing_account: false,
            provider: None,
        }));
    }

    let billing_customer = billing_customers::Entity::find()
        .filter(billing_customers::Column::OrgId.eq(&org.id))
        .filter(billing_customers::Column::Provider.eq(provider_type.to_string()))
        .one(&state.db)
        .await?;

    Ok(Json(BillingInfoResponse {
        has_billing_account: billing_customer.is_some(),
        provider: billing_customer.map(|_| provider_type.to_string()),
    }))
}

/// Helper to create a billing customer for an organization
pub async fn create_billing_customer(
    state: &AppState,
    org_id: &str,
    org_name: &str,
) -> Result<billing_customers::Model> {
    use crate::billing::CreateCustomerRequest;
    use sea_orm::{ActiveModelTrait, Set};

    let provider = &state.billing_provider;
    let provider_type = provider.provider_type();
    if provider_type == crate::billing::BillingProviderType::Disabled {
        return Err(AppError::ServiceUnavailable(
            "Billing is disabled for this AuthOS instance.".to_string(),
        ));
    }

    // Check if customer already exists
    let existing = billing_customers::Entity::find()
        .filter(billing_customers::Column::OrgId.eq(org_id))
        .filter(billing_customers::Column::Provider.eq(provider_type.to_string()))
        .one(&state.db)
        .await?;

    if let Some(customer) = existing {
        return Ok(customer);
    }

    // Create customer in the billing provider
    let external_customer_id = provider
        .create_customer(CreateCustomerRequest {
            org_id: org_id.to_string(),
            org_name: org_name.to_string(),
            email: None,
            metadata: std::collections::HashMap::new(),
        })
        .await?;

    // Store in database
    use crate::db::transaction::with_retrying_transaction;

    let org_id = org_id.to_string();
    let provider_str = provider_type.to_string();

    #[cfg(feature = "db_sqlite")]
    let billing_customer = with_retrying_transaction(
        &state.db,
        &state.db_writer,
        "create_billing_customer",
        |db| {
            let org_id = org_id.clone();
            let provider_str = provider_str.clone();
            let external_customer_id = external_customer_id.clone();
            Box::pin(async move {
                let customer = billing_customers::ActiveModel {
                    id: Set(uuid::Uuid::new_v4().to_string()),
                    org_id: Set(org_id),
                    provider: Set(provider_str),
                    external_customer_id: Set(external_customer_id),
                    created_at: Set(chrono::Utc::now().naive_utc()),
                };
                customer.insert(&db).await.map_err(AppError::SeaOrmDatabase)
            })
        },
    )
    .await?;

    #[cfg(not(feature = "db_sqlite"))]
    let billing_customer = with_retrying_transaction(&state.db, "create_billing_customer", |db| {
        let org_id = org_id.clone();
        let provider_str = provider_str.clone();
        let external_customer_id = external_customer_id.clone();
        Box::pin(async move {
            let customer = billing_customers::ActiveModel {
                id: Set(uuid::Uuid::new_v4().to_string()),
                org_id: Set(org_id),
                provider: Set(provider_str),
                external_customer_id: Set(external_customer_id),
                created_at: Set(chrono::Utc::now().naive_utc()),
            };
            customer.insert(&db).await.map_err(AppError::SeaOrmDatabase)
        })
    })
    .await?;

    Ok(billing_customer)
}
