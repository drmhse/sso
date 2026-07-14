//! BYOP (Bring Your Own Payment) billing credentials handlers
//!
//! Allows organizations to configure their own billing provider credentials
//! to charge their end-users directly.

use crate::error::{with_retrying_transaction, AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{PermissionService, CAP_BILLING_MANAGE};
use crate::state::AppState;
use crate::store::{
    organization_billing_credentials::OrganizationBillingCredentialsStore,
    organizations::OrganizationStore, DB,
};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

async fn require_billing_credentials_manager(
    db: &sea_orm::DatabaseConnection,
    user_id: &str,
    org_slug: &str,
) -> Result<crate::entities::organizations::Model> {
    let org = OrganizationStore::find_by_slug(DB::Conn(db), org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;
    let org = crate::handlers::organizations::ensure_organization_active(db, &org.id).await?;
    if !PermissionService::check(DB::Conn(db), &org.id, user_id, CAP_BILLING_MANAGE).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to manage billing credentials".to_string(),
        ));
    }
    Ok(org)
}

/// Request for setting billing credentials
#[derive(Debug, Deserialize)]
pub struct SetBillingCredentialsRequest {
    pub api_key: String,
    pub webhook_secret: String,
    pub mode: String, // "test" or "live"
}

/// Response for billing credentials status
#[derive(Debug, Serialize)]
pub struct BillingCredentialsStatusResponse {
    pub configured: bool,
    pub provider: String,
    pub mode: Option<String>,
    pub enabled: bool,
}

fn validate_billing_credentials_input(request: &SetBillingCredentialsRequest) -> Result<()> {
    if request.api_key.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Billing API key cannot be empty".to_string(),
        ));
    }
    if request.webhook_secret.trim().is_empty() {
        return Err(AppError::BadRequest(
            "Billing webhook secret cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// GET /api/organizations/:org_slug/billing-credentials/:provider
/// Get billing credentials status for a provider
pub async fn get_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
) -> Result<Json<BillingCredentialsStatusResponse>> {
    let org = require_billing_credentials_manager(&state.db, &auth_user.user.id, &org_slug).await?;

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    // Get credentials status
    let status =
        OrganizationBillingCredentialsStore::get_status(DB::Conn(&state.db), &org.id, &provider)
            .await?;

    match status {
        Some(s) => Ok(Json(BillingCredentialsStatusResponse {
            configured: s.configured,
            provider: s.provider,
            mode: Some(s.mode),
            enabled: s.enabled,
        })),
        None => Ok(Json(BillingCredentialsStatusResponse {
            configured: false,
            provider,
            mode: None,
            enabled: false,
        })),
    }
}

/// POST /api/organizations/:org_slug/billing-credentials/:provider
/// Set billing credentials for a provider
pub async fn set_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
    Json(req): Json<SetBillingCredentialsRequest>,
) -> Result<Json<serde_json::Value>> {
    let org = require_billing_credentials_manager(&state.db, &auth_user.user.id, &org_slug).await?;

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    // Validate mode
    if req.mode != "test" && req.mode != "live" {
        return Err(AppError::BadRequest(
            "Invalid mode. Must be test or live".to_string(),
        ));
    }
    validate_billing_credentials_input(&req)?;

    // Get encryption service
    let encryption = crate::encryption::EncryptionService::new().map_err(|e| {
        AppError::InternalServerError(format!("Encryption service unavailable: {}", e))
    })?;

    let existing = OrganizationBillingCredentialsStore::find_by_org_provider_mode(
        DB::Conn(&state.db),
        &org.id,
        &provider,
        &req.mode,
    )
    .await?;
    let credential_id = existing
        .as_ref()
        .map(|credential| credential.id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    // Encrypt API key
    let api_key_encrypted = encryption
        .encrypt_with_context(
            &req.api_key,
            crate::encryption::EncryptionContext::new(
                "organization_billing_credentials",
                &credential_id,
                "api_key_encrypted",
            ),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to encrypt API key: {}", e)))?;

    // Encrypt webhook secret
    let webhook_secret_encrypted = encryption
        .encrypt_with_context(
            &req.webhook_secret,
            crate::encryption::EncryptionContext::new(
                "organization_billing_credentials",
                &credential_id,
                "webhook_secret_encrypted",
            ),
        )
        .map_err(|e| {
            AppError::InternalServerError(format!("Failed to encrypt webhook secret: {}", e))
        })?;

    let encryption_key_id = encryption.key_id().to_string();

    let org_id = org.id.clone();
    let actor_id = auth_user.user.id.clone();
    let mode = req.mode.clone();
    let audit_action = if existing.is_some() {
        "billing_credentials.updated"
    } else {
        "billing_credentials.created"
    };
    let audit_actor = state.audit_actor.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "set_billing_credentials",
        |db| {
            let credential_id = credential_id.clone();
            let org_id = org_id.clone();
            let actor_id = actor_id.clone();
            let provider = provider.clone();
            let mode = mode.clone();
            let api_key_encrypted = api_key_encrypted.clone();
            let webhook_secret_encrypted = webhook_secret_encrypted.clone();
            let encryption_key_id = encryption_key_id.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                OrganizationBillingCredentialsStore::upsert(
                    db.clone(),
                    Some(&credential_id),
                    &org_id,
                    &provider,
                    &mode,
                    api_key_encrypted,
                    webhook_secret_encrypted,
                    &encryption_key_id,
                )
                .await?;
                let event = OrgAuditBuilder::new(&org_id, Some(&actor_id), audit_action)
                    .target("billing_credentials", &credential_id)
                    .success(true)
                    .details_json(Some(json!({ "provider": provider, "mode": mode })))
                    .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(())
            })
        },
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": format!("Billing credentials for {} ({} mode) configured successfully", provider, req.mode)
    })))
}

/// DELETE /api/organizations/:org_slug/billing-credentials/:provider
/// Delete billing credentials for a provider
pub async fn delete_billing_credentials(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path((org_slug, provider)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>> {
    let org = require_billing_credentials_manager(&state.db, &auth_user.user.id, &org_slug).await?;

    // Validate provider
    if provider != "stripe" && provider != "polar" {
        return Err(AppError::BadRequest(
            "Invalid provider. Must be stripe or polar".to_string(),
        ));
    }

    let org_id = org.id.clone();
    let actor_id = auth_user.user.id.clone();
    let audit_actor = state.audit_actor.clone();
    let deleted = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_billing_credentials",
        |db| {
            let org_id = org_id.clone();
            let actor_id = actor_id.clone();
            let provider = provider.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                let deleted =
                    OrganizationBillingCredentialsStore::delete(db.clone(), &org_id, &provider)
                        .await?;
                if deleted == 0 {
                    return Err(AppError::NotFound(
                        "No billing credentials found for this provider".to_string(),
                    ));
                }
                let event =
                    OrgAuditBuilder::new(&org_id, Some(&actor_id), "billing_credentials.deleted")
                        .target("billing_credentials", &provider)
                        .success(true)
                        .details_json(Some(json!({ "provider": provider })))
                        .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(deleted)
            })
        },
    )
    .await?;

    Ok(Json(serde_json::json!({
        "message": format!("Billing credentials for {} deleted successfully", provider),
        "deleted_count": deleted
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{
        memberships::MembershipStore, organization_roles::OrganizationRoleStore, users::UserStore,
    };
    use migration::{Migrator, MigratorTrait};
    use sea_orm::Database;

    #[test]
    fn billing_credentials_require_both_nonempty_secrets() {
        for request in [
            SetBillingCredentialsRequest {
                api_key: String::new(),
                webhook_secret: "webhook-secret".to_string(),
                mode: "test".to_string(),
            },
            SetBillingCredentialsRequest {
                api_key: "api-key".to_string(),
                webhook_secret: "  ".to_string(),
                mode: "live".to_string(),
            },
        ] {
            assert!(matches!(
                validate_billing_credentials_input(&request),
                Err(AppError::BadRequest(_))
            ));
        }
        validate_billing_credentials_input(&SetBillingCredentialsRequest {
            api_key: "api-key".to_string(),
            webhook_secret: "webhook-secret".to_string(),
            mode: "test".to_string(),
        })
        .expect("complete billing credentials");
    }

    #[tokio::test]
    async fn billing_credentials_authority_honors_scoped_capability_and_revocation() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let user = UserStore::create(DB::Conn(&db), "billing-role@example.com", None, false)
            .await
            .expect("create user");
        let outsider =
            UserStore::create(DB::Conn(&db), "billing-outsider@example.com", None, false)
                .await
                .expect("create outsider");
        let org = OrganizationStore::create(
            DB::Conn(&db),
            "billing-role-org",
            "Billing Role Org",
            &user.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");
        let membership =
            MembershipStore::create(DB::Conn(&db), &org.id, &user.id, "billing-manager")
                .await
                .expect("create custom membership");
        OrganizationRoleStore::create(
            DB::Conn(&db),
            "billing-manager-role",
            &org.id,
            "billing-manager",
            "Billing manager",
            None,
            serde_json::json!([CAP_BILLING_MANAGE]),
        )
        .await
        .expect("create billing role");

        require_billing_credentials_manager(&db, &user.id, &org.slug)
            .await
            .expect("custom billing capability is sufficient");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "suspended")
            .await
            .expect("suspend org");
        assert!(matches!(
            require_billing_credentials_manager(&db, &user.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("reactivate org");
        assert!(matches!(
            require_billing_credentials_manager(&db, &outsider.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));
        MembershipStore::update_role(DB::Conn(&db), &membership.id, "member")
            .await
            .expect("revoke billing role");
        assert!(matches!(
            require_billing_credentials_manager(&db, &user.id, &org.slug).await,
            Err(AppError::Forbidden(_))
        ));
    }
}
