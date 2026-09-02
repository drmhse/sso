use crate::crypto::api_key::ApiKeyService;
use crate::db::models::{ApiKey, ApiKeyCreateResponse, ApiKeyResponse};
use crate::db::transaction::with_retrying_transaction;
use crate::db::DB;
use crate::error::{AppError, Result};
use crate::middleware::AuthUser;
use crate::services::audit_builder::OrgAuditBuilder;
use crate::services::permission_service::{PermissionService, CAP_SERVICES_MANAGE};
use crate::state::AppState;
use crate::store::{
    api_keys::ApiKeyStore, memberships::MembershipStore, organizations::OrganizationStore,
    permissions::PermissionsStore, services::ServiceStore,
};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use chrono::{Duration, Utc};
// use sea_orm::TransactionTrait;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub expires_in_days: Option<i64>, // Optional expiration in days
}

#[derive(Debug, Deserialize)]
pub struct ListApiKeysQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    pub api_keys: Vec<ApiKeyResponse>,
    pub total: i64,
}

fn normalize_list_pagination(query: &ListApiKeysQuery) -> (u64, u64) {
    let (limit, offset) =
        crate::utils::pagination::signed_limit_offset(query.limit, query.offset, 50, 100);
    crate::utils::pagination::store_u64(limit, offset, 100)
}

async fn can_manage_service(state: &AppState, user_id: &str, org_id: &str) -> Result<bool> {
    PermissionService::check(DB::Conn(&state.db), org_id, user_id, CAP_SERVICES_MANAGE).await
}

async fn can_manage_specific_service(
    state: &AppState,
    user_id: &str,
    org_id: &str,
    service_id: &str,
) -> Result<bool> {
    if can_manage_service(state, user_id, org_id).await? {
        return Ok(true);
    }

    if MembershipStore::find_by_org_and_user(DB::Conn(&state.db), org_id, user_id)
        .await?
        .is_none()
    {
        return Ok(false);
    }

    PermissionsStore::check(
        DB::Conn(&state.db),
        "service",
        service_id,
        "manager",
        user_id,
    )
    .await
}

async fn can_view_specific_service(
    state: &AppState,
    user_id: &str,
    org_id: &str,
    service_id: &str,
) -> Result<bool> {
    if can_manage_specific_service(state, user_id, org_id, service_id).await? {
        return Ok(true);
    }

    if MembershipStore::find_by_org_and_user(DB::Conn(&state.db), org_id, user_id)
        .await?
        .is_none()
    {
        return Ok(false);
    }

    PermissionsStore::check(
        DB::Conn(&state.db),
        "service",
        service_id,
        "viewer",
        user_id,
    )
    .await
}

pub async fn create_api_key(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<ApiKeyCreateResponse>)> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    let service_model =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    let service_id = &service_model.id;

    if !can_manage_specific_service(&state, &auth_user.user.id, &org.id, service_id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to manage API keys for this service".to_string(),
        ));
    }

    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest(
            "API key name cannot be empty".to_string(),
        ));
    }

    if req.permissions.is_empty() {
        return Err(AppError::BadRequest(
            "API key must have at least one permission".to_string(),
        ));
    }

    let valid_permissions = [
        "read:users",
        "write:users",
        "delete:users",
        "read:subscriptions",
        "write:subscriptions",
        "delete:subscriptions",
        "read:analytics",
        "read:service",
        "write:service",
        "read:provider_tokens",
        "read:provider_tokens:github",
        "read:provider_tokens:google",
        "read:provider_tokens:microsoft",
    ];

    for permission in &req.permissions {
        let is_provider_specific_token_permission = permission
            .strip_prefix("read:provider_tokens:")
            .is_some_and(|provider| {
                !provider.is_empty()
                    && provider
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            });

        if !valid_permissions.contains(&permission.as_str())
            && !is_provider_specific_token_permission
        {
            return Err(AppError::BadRequest(format!(
                "Invalid permission: {}. Valid permissions are: {} or read:provider_tokens:<provider>",
                permission,
                valid_permissions.join(", ")
            )));
        }
    }

    let (full_key, prefix, key_hash) = ApiKeyService::generate();

    let now = Utc::now();
    let expires_at = req.expires_in_days.map(|days| now + Duration::days(days));

    let permissions_json = serde_json::to_string(&req.permissions).map_err(|e| {
        AppError::InternalServerError(format!("Failed to serialize permissions: {}", e))
    })?;

    let expires_at_naive = expires_at.map(|dt| dt.naive_utc());

    let user_id = auth_user.user.id.clone();
    let name = req.name.clone();
    let org_id = org.id.clone();
    let service_slug_for_audit = service_slug.clone();
    let permissions_for_audit = req.permissions.clone();
    let audit_actor = state.audit_actor.clone();

    // Execute transaction with automatic retry on database contention
    let api_key_id = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "create_api_key",
        |db| {
            let service_id = service_id.clone();
            let name = name.clone();
            let prefix = prefix.clone();
            let key_hash = key_hash.clone();
            let permissions_json = permissions_json.clone();
            let user_id = user_id.clone();
            let org_id = org_id.clone();
            let service_slug = service_slug_for_audit.clone();
            let permissions = permissions_for_audit.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                let api_key_entity = ApiKeyStore::create(
                    db.clone(),
                    &service_id,
                    &name,
                    &prefix,
                    &key_hash,
                    &permissions_json,
                    &user_id,
                    expires_at_naive,
                )
                .await?;

                let event = OrgAuditBuilder::new(&org_id, Some(&user_id), "api_key.created")
                    .target("api_key", &api_key_entity.id)
                    .success(true)
                    .details_json(Some(json!({
                        "api_key_id": api_key_entity.id,
                        "service_id": service_id,
                        "service_slug": service_slug,
                        "name": name,
                        "permissions": permissions,
                        "expires_at": expires_at
                    })))
                    .build();
                audit_actor.log_org_with_db(db, event).await?;

                Ok(api_key_entity.id.clone())
            })
        },
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(ApiKeyCreateResponse {
            id: api_key_id,
            service_id: service_id.clone(),
            name: req.name,
            prefix,
            permissions: req.permissions,
            expires_at,
            created_at: now,
            created_by: auth_user.user.id.clone(),
            key: full_key,
        }),
    ))
}

pub async fn list_api_keys(
    State(state): State<AppState>,
    Path((org_slug, service_slug)): Path<(String, String)>,
    auth_user: axum::Extension<AuthUser>,
    Query(query): Query<ListApiKeysQuery>,
) -> Result<Json<ListApiKeysResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let _org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    let _membership = MembershipStore::find_by_org_and_user(
        DB::Conn(&state.db),
        &org_model.id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    let service_model =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org_model.id, &service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    let service_id = &service_model.id;

    if !can_view_specific_service(&state, &auth_user.user.id, &org_model.id, service_id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view API keys for this service".to_string(),
        ));
    }

    let (limit, offset) = normalize_list_pagination(&query);

    let total = ApiKeyStore::count_by_service(DB::Conn(&state.db), service_id).await?;

    let api_key_entities =
        ApiKeyStore::list_by_service(DB::Conn(&state.db), service_id, limit, offset).await?;

    let api_key_responses: Vec<ApiKeyResponse> = api_key_entities
        .into_iter()
        .map(|entity| {
            let api_key: ApiKey = entity.into();
            ApiKeyResponse::from_api_key(api_key)
        })
        .collect();

    Ok(Json(ListApiKeysResponse {
        api_keys: api_key_responses,
        total: total as i64,
    }))
}

pub async fn get_api_key(
    State(state): State<AppState>,
    Path((org_slug, service_slug, api_key_id)): Path<(String, String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<Json<ApiKeyResponse>> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let _org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    let _membership = MembershipStore::find_by_org_and_user(
        DB::Conn(&state.db),
        &org_model.id,
        &auth_user.user.id,
    )
    .await?
    .ok_or_else(|| AppError::Forbidden("Not a member of this organization".to_string()))?;

    let service_model =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org_model.id, &service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    let service_id = &service_model.id;

    if !can_view_specific_service(&state, &auth_user.user.id, &org_model.id, service_id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to view API keys for this service".to_string(),
        ));
    }

    let api_key_entity =
        ApiKeyStore::find_by_id_and_service(DB::Conn(&state.db), &api_key_id, service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("API key not found".to_string()))?;

    let api_key: ApiKey = api_key_entity.into();

    Ok(Json(ApiKeyResponse::from_api_key(api_key)))
}

pub async fn delete_api_key(
    State(state): State<AppState>,
    Path((org_slug, service_slug, api_key_id)): Path<(String, String, String)>,
    auth_user: axum::Extension<AuthUser>,
) -> Result<StatusCode> {
    let org_model = OrganizationStore::find_by_slug(DB::Conn(&state.db), &org_slug)
        .await?
        .ok_or_else(|| AppError::NotFound("Organization not found".to_string()))?;

    let org = crate::handlers::organizations::ensure_organization_active(&state.db, &org_model.id)
        .await?;

    let service_model =
        ServiceStore::find_by_org_and_slug(DB::Conn(&state.db), &org.id, &service_slug)
            .await?
            .ok_or_else(|| AppError::NotFound("Service not found".to_string()))?;

    let service_id = &service_model.id;

    if !can_manage_specific_service(&state, &auth_user.user.id, &org.id, service_id).await? {
        return Err(AppError::Forbidden(
            "Insufficient permissions to delete API keys for this service".to_string(),
        ));
    }

    let api_key_entity =
        ApiKeyStore::find_by_id_and_service(DB::Conn(&state.db), &api_key_id, service_id)
            .await?
            .ok_or_else(|| AppError::NotFound("API key not found".to_string()))?;

    let api_key_name = api_key_entity.name.clone();
    let org_id = org.id.clone();
    let actor_user_id = auth_user.user.id.clone();
    let service_slug_for_audit = service_slug.clone();
    let audit_actor = state.audit_actor.clone();

    // Execute transaction with automatic retry on database contention
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "delete_api_key",
        |db| {
            let api_key_id = api_key_id.clone();
            let service_id = service_id.clone();
            let api_key_name = api_key_name.clone();
            let org_id = org_id.clone();
            let actor_user_id = actor_user_id.clone();
            let service_slug = service_slug_for_audit.clone();
            let audit_actor = audit_actor.clone();
            Box::pin(async move {
                ApiKeyStore::delete_for_service(db.clone(), &api_key_id, &service_id).await?;

                let event = OrgAuditBuilder::new(&org_id, Some(&actor_user_id), "api_key.deleted")
                    .target("api_key", &api_key_id)
                    .success(true)
                    .details_json(Some(json!({
                        "api_key_id": api_key_id,
                        "service_id": service_id,
                        "service_slug": service_slug,
                        "name": api_key_name
                    })))
                    .build();
                audit_actor.log_org_with_db(db, event).await?;
                Ok(())
            })
        },
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_list_pagination_is_bounded_before_unsigned_conversion() {
        assert_eq!(
            normalize_list_pagination(&ListApiKeysQuery {
                limit: None,
                offset: None,
            }),
            (50, 0)
        );
        assert_eq!(
            normalize_list_pagination(&ListApiKeysQuery {
                limit: Some(-1),
                offset: Some(-1),
            }),
            (1, 0)
        );
        assert_eq!(
            normalize_list_pagination(&ListApiKeysQuery {
                limit: Some(0),
                offset: Some(12),
            }),
            (1, 12)
        );
        assert_eq!(
            normalize_list_pagination(&ListApiKeysQuery {
                limit: Some(i64::MAX),
                offset: Some(3),
            }),
            (100, 3)
        );
    }
}

#[cfg(test)]
mod route_tests {

    use super::*;

    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::crypto::sso::OAuthClient;

    use crate::handlers::services::{create_service, CreateServiceRequest};

    use crate::audit::actor::AuditHandle;
    use crate::db::DB;
    use crate::services::{
        events::EventDispatcher, metrics::MfaMetricsService, risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore, users::UserStore,
    };
    use axum::http::StatusCode;

    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    use crate::test_support::test_config;

    use crate::test_support::test_jwt_service;

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        member: AuthUser,
        org_slug: String,
        service_slug: String,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));

        let owner_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "api-key-owner@example.test",
            crate::store::users::UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;

        let (org, _) = OrganizationStore::create_with_owner(
            DB::Conn(&db),
            "acme",
            "Acme",
            &owner_model.id,
            None,
        )
        .await
        .expect("create org");
        OrganizationStore::update_status(DB::Conn(&db), &org.id, "active")
            .await
            .expect("activate org");

        let member_model =
            UserStore::create(DB::Conn(&db), "api-key-member@example.test", None, false)
                .await
                .expect("create member");
        MembershipStore::create(DB::Conn(&db), &org.id, &member_model.id, "member")
            .await
            .expect("create membership");

        let auth_user_for = |user: &crate::entities::users::Model| -> AuthUser {
            let token = jwt_service
                .create_token(&user.id, &user.email, false, Some(&org.slug), None)
                .expect("create token");
            let claims = jwt_service.validate_token(&token).expect("validate token");
            AuthUser {
                claims,
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "api-key-test".to_string(),
                current_session_id: None,
            }
        };
        let owner = auth_user_for(&owner_model);
        let member = auth_user_for(&member_model);

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client,
            jwt_service,
            base_url: config.base_url.clone(),
            web_client_url: config.platform_dashboard_base_url.clone(),
            full_web_client_url: config.full_web_client_base_url.clone(),
            encryption: None,
            email_service: None,
            metrics_service: Arc::new(MfaMetricsService::new(db.clone())),
            event_dispatcher: Arc::new(EventDispatcher::new(db.clone())),
            billing_provider: Arc::new(DisabledBillingProvider::new()),
            risk_engine: Arc::new(RiskEngine::new().expect("create risk engine")),
            webauthn_service: None,
            permission_cache: Cache::new(10_000),
            user_cache: Cache::new(10_000),
            domain_cache: Cache::new(10_000),
            audit_actor: AuditHandle::new(db.clone()),
            config,
        };

        // A service to hang API keys off of.
        let Json(service) = create_service(
            State(state.clone()),
            Path(org.slug.clone()),
            axum::Extension(owner.clone()),
            Json(CreateServiceRequest {
                slug: "portal".to_string(),
                name: "Portal".to_string(),
                service_type: "web".to_string(),
                github_scopes: None,
                microsoft_scopes: None,
                google_scopes: None,
                redirect_uris: None,
                device_activation_uri: None,
                resource_uris: None,
            }),
        )
        .await
        .expect("create service for api keys");

        drop(service);

        Fixture {
            state,
            owner,
            member,
            org_slug: org.slug,
            service_slug: "portal".to_string(),
        }
    }

    fn valid_create(name: &str) -> CreateApiKeyRequest {
        CreateApiKeyRequest {
            name: name.to_string(),
            permissions: vec!["read:service".to_string()],
            expires_in_days: None,
        }
    }

    #[tokio::test]
    async fn create_returns_a_bearer_style_key_once_and_list_hides_it() {
        let f = fixture().await;
        let (StatusCode::CREATED, Json(created)) = create_api_key(
            State(f.state.clone()),
            Path((f.org_slug.clone(), f.service_slug.clone())),
            axum::Extension(f.owner.clone()),
            Json(valid_create("ci-key")),
        )
        .await
        .expect("create api key") else {
            panic!("expected 201 with body");
        };

        assert_eq!(created.name, "ci-key");
        assert!(
            created.key.len() >= 32,
            "the full key is returned exactly once"
        );

        let Json(list) = list_api_keys(
            State(f.state.clone()),
            Path((f.org_slug.clone(), f.service_slug.clone())),
            axum::Extension(f.owner.clone()),
            Query(ListApiKeysQuery {
                limit: None,
                offset: None,
            }),
        )
        .await
        .expect("list api keys");
        assert_eq!(list.total, 1);
        assert_eq!(list.api_keys[0].prefix, created.prefix);
        assert_ne!(
            list.api_keys[0].prefix, created.key,
            "the raw key must never come back on a list"
        );
    }
    #[tokio::test]
    async fn members_are_denied_api_key_management() {
        let f = fixture().await;
        match create_api_key(
            State(f.state.clone()),
            Path((f.org_slug.clone(), f.service_slug.clone())),
            axum::Extension(f.member.clone()),
            Json(valid_create("member-key")),
        )
        .await
        {
            Err(AppError::Forbidden(_)) => {}
            other => panic!("expected forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_and_delete_round_trip_with_unknown_ids() {
        let f = fixture().await;
        let (StatusCode::CREATED, Json(created)) = create_api_key(
            State(f.state.clone()),
            Path((f.org_slug.clone(), f.service_slug.clone())),
            axum::Extension(f.owner.clone()),
            Json(valid_create("round-trip")),
        )
        .await
        .expect("create api key") else {
            panic!("expected 201 with body");
        };

        match get_api_key(
            State(f.state.clone()),
            Path((
                f.org_slug.clone(),
                f.service_slug.clone(),
                "missing".to_string(),
            )),
            axum::Extension(f.owner.clone()),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found, got {other:?}"),
        }

        let Json(got) = get_api_key(
            State(f.state.clone()),
            Path((
                f.org_slug.clone(),
                f.service_slug.clone(),
                created.id.clone(),
            )),
            axum::Extension(f.owner.clone()),
        )
        .await
        .expect("get api key");
        assert_eq!(got.id, created.id);
        assert_eq!(got.permissions, vec!["read:service".to_string()]);

        delete_api_key(
            State(f.state.clone()),
            Path((
                f.org_slug.clone(),
                f.service_slug.clone(),
                created.id.clone(),
            )),
            axum::Extension(f.owner.clone()),
        )
        .await
        .expect("delete api key");

        match get_api_key(
            State(f.state.clone()),
            Path((
                f.org_slug.clone(),
                f.service_slug.clone(),
                created.id.clone(),
            )),
            axum::Extension(f.owner.clone()),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found after delete, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_rejects_blank_names_empty_permissions_and_bad_expiry() {
        let f = fixture().await;

        // Blank name.
        match create_api_key(
            State(f.state.clone()),
            Path((f.org_slug.clone(), f.service_slug.clone())),
            axum::Extension(f.owner.clone()),
            Json(CreateApiKeyRequest {
                name: "  ".to_string(),
                permissions: vec!["read:service".to_string()],
                expires_in_days: None,
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("name")),
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // No permissions.
        match create_api_key(
            State(f.state.clone()),
            Path((f.org_slug.clone(), f.service_slug.clone())),
            axum::Extension(f.owner.clone()),
            Json(CreateApiKeyRequest {
                name: "no-perms".to_string(),
                permissions: vec![],
                expires_in_days: None,
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("at least one permission"))
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // Negative expiry is currently ACCEPTED: the key is born expired.
        // Pinned here so a future fix flips this test deliberately.
        let (_, response) = create_api_key(
            State(f.state.clone()),
            Path((f.org_slug.clone(), f.service_slug.clone())),
            axum::Extension(f.owner.clone()),
            Json(CreateApiKeyRequest {
                name: "expired-yesterday".to_string(),
                permissions: vec!["read:service".to_string()],
                expires_in_days: Some(-3),
            }),
        )
        .await
        .expect("create api key with negative expiry");
        let expires_at = response
            .expires_at
            .expect("negative expiry produces an expiry timestamp");
        assert!(
            expires_at < chrono::Utc::now(),
            "documents current behaviour: the key is created already expired"
        );
    }
}
