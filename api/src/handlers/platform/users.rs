use crate::db::models::User;
use crate::entities::{user_totp_secrets, users};
use crate::error::{with_retrying_transaction, AppError, Result};
use crate::middleware::AuthUser;
use crate::state::AppState;
use crate::store::{totp::TotpStore, users::UserStore, DB};
use axum::{
    extract::{Path, Query, State},
    Extension, Json,
};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{create_audit_log, user_model_to_old};

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct PromoteOwnerRequest {
    pub user_id: String,
}

#[derive(Debug, Deserialize)]
pub struct UserSearchQuery {
    pub q: String, // Search query (email or user ID)
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserSearchResult {
    pub id: String,
    pub email: String,
    pub is_platform_owner: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct UserListParams {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct UserListResponse {
    pub users: Vec<UserSearchResult>,
    pub total: i64,
}

#[derive(Debug, Serialize)]
pub struct MfaStatusResponse {
    pub enabled: bool,
    pub has_backup_codes: bool,
}

// ============================================================================
// User Management Endpoints
// ============================================================================

/// GET /api/platform/users/:user_id - Get a single user by ID
pub async fn get_platform_user(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<UserSearchResult>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    Ok(Json(UserSearchResult {
        id: user.id,
        email: user.email,
        is_platform_owner: user.is_platform_owner,
        created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(user.created_at, Utc)
            .to_rfc3339(),
    }))
}

/// GET /api/platform/users - List all users with pagination
pub async fn list_users(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Query(params): Query<UserListParams>,
) -> Result<Json<UserListResponse>> {
    // Only platform owners can list users
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let (limit_val, offset_val) =
        crate::utils::pagination::signed_limit_offset(params.limit, params.offset, 50, 100);

    // Get users using store
    let (limit_val, offset_val) = crate::utils::pagination::store_u64(limit_val, offset_val, 100);
    let users = UserStore::list_all(DB::Conn(&state.db), limit_val, offset_val).await?;
    let total = UserStore::count_all(DB::Conn(&state.db), false).await? as i64;

    // Convert to response format
    let user_results = users
        .into_iter()
        .map(|u| UserSearchResult {
            id: u.id,
            email: u.email,
            is_platform_owner: u.is_platform_owner,
            created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(u.created_at, Utc)
                .to_rfc3339(),
        })
        .collect();

    Ok(Json(UserListResponse {
        users: user_results,
        total,
    }))
}

/// GET /api/platform/users/search - Search users by email or ID
pub async fn search_users(
    State(state): State<AppState>,
    auth_user: Extension<AuthUser>,
    Query(query): Query<UserSearchQuery>,
) -> Result<Json<Vec<UserSearchResult>>> {
    // Only platform owners can search users
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let (limit_val, _) = crate::utils::pagination::signed_limit_offset(query.limit, None, 10, 50);

    // Search users using store with relevance-based ordering
    let (limit_val, _) = crate::utils::pagination::store_u64(limit_val, 0, 50);
    let store_results =
        UserStore::search_with_relevance(DB::Conn(&state.db), &query.q, limit_val).await?;

    // Convert store results to handler results
    let results = store_results
        .into_iter()
        .map(|r| UserSearchResult {
            id: r.id,
            email: r.email,
            is_platform_owner: r.is_platform_owner,
            created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(r.created_at, Utc)
                .to_rfc3339(),
        })
        .collect();

    Ok(Json(results))
}

/// POST /api/platform/owners
/// Promote a user to platform owner
pub async fn promote_platform_owner(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Json(req): Json<PromoteOwnerRequest>,
) -> Result<Json<User>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    let user_id = req.user_id.clone();
    let owner_id = auth_user.user.id.clone();

    let updated_user = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "promote_platform_owner",
        |db| {
            let user_id = user_id.clone();
            let owner_id = owner_id.clone();
            Box::pin(async move {
                // Fetch user
                let user_model = UserStore::find_by_id(db.clone(), &user_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

                if user_model.is_platform_owner {
                    return Err(AppError::BadRequest(
                        "User is already a platform owner".to_string(),
                    ));
                }

                // Update user
                let mut user_active: users::ActiveModel = user_model.into();
                user_active.is_platform_owner = Set(true);

                let updated_user_model = user_active.update(&db).await?;
                let updated_user = user_model_to_old(updated_user_model.clone());

                // Create audit log
                create_audit_log(
                    &db,
                    &owner_id,
                    "promote_platform_owner",
                    "user",
                    &user_id,
                    Some(json!({
                        "user_email": updated_user_model.email,
                    })),
                )
                .await?;

                Ok(updated_user)
            })
        },
    )
    .await?;

    Ok(Json(updated_user))
}

/// DELETE /api/platform/owners/:user_id
/// Demote a platform owner to regular user
pub async fn demote_platform_owner(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<User>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Prevent self-demotion
    if auth_user.user.id == user_id {
        return Err(AppError::BadRequest("Cannot demote yourself".to_string()));
    }

    let owner_id = auth_user.user.id.clone();

    let updated_user = with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "demote_platform_owner",
        |db| {
            let user_id = user_id.clone();
            let owner_id = owner_id.clone();
            Box::pin(async move {
                // Fetch user to demote
                let user_model = UserStore::find_by_id(db.clone(), &user_id)
                    .await?
                    .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

                if !user_model.is_platform_owner {
                    return Err(AppError::BadRequest(
                        "User is not a platform owner".to_string(),
                    ));
                }

                // Check if this is the last platform owner
                // Check if we can demote this user (must have at least one other platform owner)
                let owner_count = UserStore::count_platform_owners(db.clone()).await? as i64;

                if owner_count <= 1 {
                    return Err(AppError::BadRequest(
                        "Cannot demote the last platform owner".to_string(),
                    ));
                }

                // Update user
                let mut user_active: users::ActiveModel = user_model.into();
                user_active.is_platform_owner = Set(false);

                let updated_user_model = user_active.update(&db).await?;
                let updated_user = user_model_to_old(updated_user_model.clone());

                // Create audit log
                create_audit_log(
                    &db,
                    &owner_id,
                    "demote_platform_owner",
                    "user",
                    &user_id,
                    Some(json!({
                        "user_email": updated_user_model.email,
                    })),
                )
                .await?;

                Ok(updated_user)
            })
        },
    )
    .await?;

    Ok(Json(updated_user))
}

/// GET /api/platform/users/:user_id/mfa/status
/// Get MFA status for a user (Platform Owner only)
pub async fn get_user_mfa_status(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<MfaStatusResponse>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Check if user exists
    let _user = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    // Check MFA status
    let totp_secret = user_totp_secrets::Entity::find()
        .filter(user_totp_secrets::Column::UserId.eq(&user_id))
        .one(&state.db)
        .await?;

    let mfa_enabled = totp_secret.as_ref().map(|t| t.enabled).unwrap_or(false);

    // Check for backup codes (checking any codes, not just unused)
    let has_backup_codes = if mfa_enabled {
        let count = TotpStore::count_backup_codes(DB::Conn(&state.db), &user_id).await?;
        count > 0
    } else {
        false
    };

    Ok(Json(MfaStatusResponse {
        enabled: mfa_enabled,
        has_backup_codes,
    }))
}

/// DELETE /api/platform/users/:user_id/mfa
/// Force disable MFA for a user (Platform Owner only)
pub async fn force_disable_user_mfa(
    State(state): State<AppState>,
    Extension(auth_user): Extension<AuthUser>,
    Path(user_id): Path<String>,
) -> Result<Json<serde_json::Value>> {
    if !auth_user.user.is_platform_owner {
        return Err(AppError::Forbidden(
            "Platform owner access required".to_string(),
        ));
    }

    // Check if user exists
    let user_model = UserStore::find_by_id(DB::Conn(&state.db), &user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))?;

    let owner_id = auth_user.user.id.clone();
    let owner_email = auth_user.user.email.clone();
    with_retrying_transaction(
        &state.db,
        #[cfg(feature = "db_sqlite")]
        &state.db_writer,
        "force_disable_user_mfa_with_audit",
        |db| {
            let user_id = user_id.clone();
            let user_email = user_model.email.clone();
            let owner_id = owner_id.clone();
            let owner_email = owner_email.clone();
            Box::pin(async move {
                TotpStore::delete_totp_secret(db.clone(), &user_id).await?;
                TotpStore::delete_backup_codes(db.clone(), &user_id).await?;
                create_audit_log(
                    &db,
                    &owner_id,
                    "force_disable_mfa",
                    "user",
                    &user_id,
                    Some(json!({
                        "user_email": user_email,
                        "admin_id": owner_id,
                        "admin_email": owner_email,
                    })),
                )
                .await?;
                Ok(())
            })
        },
    )
    .await?;

    Ok(Json(json!({
        "success": true,
        "message": "MFA has been force-disabled for the user"
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::jwt::JwtService;
    use crate::auth::sso::OAuthClient;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::entities::users;
    use crate::rsa_keys::GeneratedKey;
    use crate::services::{
        audit_actor::AuditHandle, events::EventDispatcher, metrics::MfaMetricsService,
        risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{memberships::MembershipStore, users::UserStore, DB};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use sea_orm::Database;
    use std::sync::Arc;

    fn test_config() -> Config {
        Config {
            database_url: "sqlite::memory:".to_string(),
            jwt_expiration_hours: 24,
            db_max_connections: 5,
            db_min_connections: 1,
            db_acquire_timeout_secs: 30,
            db_idle_timeout_secs: 600,
            db_max_lifetime_secs: 1800,
            platform_github_client_id: None,
            platform_github_client_secret: None,
            platform_github_redirect_uri: None,
            platform_google_client_id: None,
            platform_google_client_secret: None,
            platform_google_redirect_uri: None,
            platform_microsoft_client_id: None,
            platform_microsoft_client_secret: None,
            platform_microsoft_redirect_uri: None,
            platform_github_auth_url: None,
            platform_github_token_url: None,
            platform_github_user_api_url: None,
            platform_google_auth_url: None,
            platform_google_token_url: None,
            platform_google_user_api_url: None,
            platform_microsoft_auth_url: None,
            platform_microsoft_token_url: None,
            platform_microsoft_user_api_url: None,
            stripe_secret_key: None,
            stripe_webhook_secret: None,
            stripe_api_base_url: None,
            server_host: "127.0.0.1".to_string(),
            server_port: 3001,
            base_url: "http://localhost:3001".to_string(),
            platform_dashboard_base_url: "http://localhost:3001".to_string(),
            full_web_client_base_url: None,
            platform_owner_email: None,
            platform_owner_password: None,
            managed_config_path: None,
            managed_state_path: None,
            managed_status_path: None,
            managed_request_path: None,
            disable_rate_limiting: true,
            job_processor_interval_secs: 10,
            job_processor_batch_size: 10,
        }
    }

    fn test_jwt_service(config: &Config) -> JwtService {
        let rsa = GeneratedKey::generate().expect("generate test rsa key");
        JwtService::new(
            &STANDARD.encode(rsa.private_key_pem().expect("private pem")),
            &STANDARD.encode(rsa.public_key_pem().expect("public pem")),
            config.jwt_expiration_hours,
            "test-key",
            &config.base_url,
        )
        .expect("create jwt service")
    }

    struct Fixture {
        state: AppState,
        owner: AuthUser,
        plain_user_model: users::Model,
        plain: AuthUser,
    }

    async fn fixture() -> Fixture {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        let config = test_config();
        let jwt_service = Arc::new(test_jwt_service(&config));

        let owner_model = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "platform-owner@example.test",
            crate::store::users::UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create platform owner")
        .0;
        let plain_model = UserStore::create(DB::Conn(&db), "plain@example.test", None, false)
            .await
            .expect("create plain user");
        let _ = MembershipStore::create(
            DB::Conn(&db),
            "org-placeholder",
            &plain_model.id,
            "member",
        )
        .await;

        let state = AppState {
            db: db.clone(),
            #[cfg(feature = "db_sqlite")]
            db_writer: db.clone(),
            oauth_client: Arc::new(OAuthClient::new(&config).expect("create oauth client")),
            jwt_service: jwt_service.clone(),
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

        let auth_user_for = |user: &users::Model| -> AuthUser {
            let token = jwt_service
                .create_token(&user.id, &user.email, user.is_platform_owner, None, None)
                .expect("create token");
            let claims = jwt_service.validate_token(&token).expect("validate token");
            AuthUser {
                claims,
                user: user.clone(),
                permissions: vec![],
                ip_address: "127.0.0.1".to_string(),
                user_agent: "platform-user-test".to_string(),
                current_session_id: None,
            }
        };

        Fixture {
            state,
            owner: auth_user_for(&owner_model),
            plain_user_model: plain_model.clone(),
            plain: auth_user_for(&plain_model),
        }
    }

    #[tokio::test]
    async fn non_owners_are_denied_every_platform_endpoint() {
        let f = fixture().await;
        let results = (
            get_platform_user(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Path(f.plain_user_model.id.clone()),
            )
            .await
            .err(),
            list_users(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Query(UserListParams {
                    limit: None,
                    offset: None,
                }),
            )
            .await
            .err(),
            search_users(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Query(UserSearchQuery {
                    q: "x".to_string(),
                    limit: None,
                }),
            )
            .await
            .err(),
            promote_platform_owner(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Json(PromoteOwnerRequest {
                    user_id: f.plain_user_model.id.clone(),
                }),
            )
            .await
            .err(),
            demote_platform_owner(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Path(f.owner.user.id.clone()),
            )
            .await
            .err(),
            get_user_mfa_status(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Path(f.plain_user_model.id.clone()),
            )
            .await
            .err(),
            force_disable_user_mfa(
                State(f.state.clone()),
                Extension(f.plain.clone()),
                Path(f.plain_user_model.id.clone()),
            )
            .await
            .err(),
        );
        match results {
            (
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
                Some(AppError::Forbidden(_)),
            ) => {}
            other => panic!("expected all-forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn owners_can_list_search_and_fetch_users() {
        let f = fixture().await;
        let Json(list) = list_users(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Query(UserListParams {
                limit: None,
                offset: None,
            }),
        )
        .await
        .expect("list users");
        assert!(list.total >= 2);
        assert!(list.users.iter().any(|u| u.is_platform_owner));

        let Json(found) = search_users(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Query(UserSearchQuery {
                q: "plain@example.test".to_string(),
                limit: None,
            }),
        )
        .await
        .expect("search users");
        assert!(found.iter().any(|u| u.email == "plain@example.test"));

        let Json(got) = get_platform_user(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path(f.plain_user_model.id.clone()),
        )
        .await
        .expect("get platform user");
        assert_eq!(got.email, "plain@example.test");

        match get_platform_user(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path("missing".to_string()),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn promotion_and_demotion_guard_against_duplicates_self_and_non_owners() {
        let f = fixture().await;

        // Promoting the already-owner fails.
        match promote_platform_owner(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Json(PromoteOwnerRequest {
                user_id: f.owner.user.id.clone(),
            }),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => {
                assert!(message.contains("already a platform owner"))
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }

        // Promote the plain user.
        let Json(promoted) = promote_platform_owner(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Json(PromoteOwnerRequest {
                user_id: f.plain_user_model.id.clone(),
            }),
        )
        .await
        .expect("promote user");
        assert!(promoted.is_platform_owner);

        // Promoting again now conflicts.
        match promote_platform_owner(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Json(PromoteOwnerRequest {
                user_id: f.plain_user_model.id.clone(),
            }),
        )
        .await
        {
            Err(AppError::BadRequest(_)) => {}
            other => panic!("expected BadRequest on double promote, got {other:?}"),
        }

        // Demoting yourself is refused.
        match demote_platform_owner(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path(f.owner.user.id.clone()),
        )
        .await
        {
            Err(AppError::BadRequest(message)) => assert!(message.contains("yourself")),
            other => panic!("expected self-demote refusal, got {other:?}"),
        }

        // Demoting a non-owner is refused.
        match demote_platform_owner(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path("missing".to_string()),
        )
        .await
        {
            Err(AppError::NotFound(_)) | Err(AppError::BadRequest(_)) => {}
            other => panic!("expected refusal, got {other:?}"),
        }

        // Demoting the newly promoted owner works.
        let Json(demoted) = demote_platform_owner(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path(f.plain_user_model.id.clone()),
        )
        .await
        .expect("demote user");
        assert!(!demoted.is_platform_owner);
    }

    #[tokio::test]
    async fn mfa_status_reads_and_unknown_users() {
        let f = fixture().await;
        let Json(status) = get_user_mfa_status(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path(f.plain_user_model.id.clone()),
        )
        .await
        .expect("mfa status");
        assert!(!status.enabled, "fresh user has no mfa");

        match get_user_mfa_status(
            State(f.state.clone()),
            Extension(f.owner.clone()),
            Path("missing".to_string()),
        )
        .await
        {
            Err(AppError::NotFound(_)) => {}
            other => panic!("expected not found, got {other:?}"),
        }
    }
}
