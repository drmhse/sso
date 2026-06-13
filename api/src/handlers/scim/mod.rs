pub mod groups;
pub mod schemas;
pub mod users;

pub use groups::*;
pub use users::*;

#[cfg(test)]
mod tests {
    use crate::auth::jwt::JwtService;
    use crate::auth::sso::OAuthClient;
    use crate::billing::providers::disabled::DisabledBillingProvider;
    use crate::config::Config;
    use crate::entities::{prelude::Users, users};
    use crate::handlers::scim::schemas;
    use crate::router;
    use crate::services::{
        audit_actor::AuditHandle, events::EventDispatcher, metrics::MfaMetricsService,
        risk_engine::RiskEngine,
    };
    use crate::state::AppState;
    use crate::store::{
        memberships::MembershipStore, organizations::OrganizationStore,
        permissions::PermissionsStore, scim_tokens::ScimTokenStore, users::UserStore, DB,
    };
    use axum::body::{to_bytes, Body};
    use axum::http::{header, Method, Request, StatusCode};
    use base64::{engine::general_purpose::STANDARD, Engine};
    use chrono::Utc;
    use migration::{Migrator, MigratorTrait};
    use moka::future::Cache;
    use openssl::rsa::Rsa;
    use sea_orm::{
        ActiveModelTrait, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter, Set,
    };
    use serde_json::Value;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    struct ScimRouteFixture {
        state: AppState,
        bearer_token: String,
        org_id: String,
        owner_id: String,
        user_id: String,
    }

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
        let rsa = Rsa::generate(2048).expect("generate test rsa key");
        let private_key = STANDARD.encode(
            rsa.private_key_to_pem()
                .expect("encode private key pem for tests"),
        );
        let public_key = STANDARD.encode(
            rsa.public_key_to_pem()
                .expect("encode public key pem for tests"),
        );

        JwtService::new(
            &private_key,
            &public_key,
            config.jwt_expiration_hours,
            "test-key",
            &config.base_url,
        )
        .expect("create test jwt service")
    }

    async fn setup_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("connect in-memory sqlite");
        Migrator::up(&db, None).await.expect("run migrations");
        db
    }

    async fn setup_fixture() -> ScimRouteFixture {
        let db = setup_db().await;
        let config = test_config();
        let owner = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "owner@example.com",
            crate::store::users::UserCreationOptions {
                is_platform_owner: true,
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create owner")
        .0;
        let invitee = UserStore::find_or_create_with_options(
            DB::Conn(&db),
            "scim-user@example.com",
            crate::store::users::UserCreationOptions {
                mark_email_verified: true,
                ..Default::default()
            },
        )
        .await
        .expect("create scim user")
        .0;
        let (org, _) =
            OrganizationStore::create_with_owner(DB::Conn(&db), "acme", "Acme", &owner.id, None)
                .await
                .expect("create org");
        MembershipStore::create(DB::Conn(&db), &org.id, &invitee.id, "member")
            .await
            .expect("create member");

        let (bearer_token, prefix, token_hash) = ScimTokenStore::generate();
        ScimTokenStore::create(
            DB::Conn(&db),
            &org.id,
            "route-test",
            &token_hash,
            &prefix,
            &owner.id,
            None,
        )
        .await
        .expect("create scim token");

        let jwt_service = Arc::new(test_jwt_service(&config));
        let oauth_client = Arc::new(OAuthClient::new(&config).expect("create oauth client"));
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

        ScimRouteFixture {
            state,
            bearer_token,
            org_id: org.id,
            owner_id: owner.id,
            user_id: invitee.id,
        }
    }

    async fn scim_request(
        fixture: &ScimRouteFixture,
        method: Method,
        uri: String,
        body: Value,
    ) -> (StatusCode, Value) {
        let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", fixture.bearer_token),
            )
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(body.to_string()))
            .expect("build scim request");

        let response = app.oneshot(request).await.expect("send scim request");
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read scim response body");
        let body = serde_json::from_slice(&body_bytes).expect("parse scim response body");
        (status, body)
    }

    async fn scim_status_request(
        fixture: &ScimRouteFixture,
        method: Method,
        uri: String,
        body: Value,
    ) -> StatusCode {
        let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", fixture.bearer_token),
            )
            .header(header::CONTENT_TYPE, "application/scim+json")
            .body(Body::from(body.to_string()))
            .expect("build scim request");

        app.oneshot(request)
            .await
            .expect("send scim request")
            .status()
    }

    async fn scim_empty_request(
        fixture: &ScimRouteFixture,
        method: Method,
        uri: String,
    ) -> (StatusCode, Value) {
        let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", fixture.bearer_token),
            )
            .body(Body::empty())
            .expect("build scim request");

        let response = app.oneshot(request).await.expect("send scim request");
        let status = response.status();
        let body_bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read scim response body");
        let body = serde_json::from_slice(&body_bytes).expect("parse scim response body");
        (status, body)
    }

    async fn scim_empty_status_request(
        fixture: &ScimRouteFixture,
        method: Method,
        uri: String,
    ) -> StatusCode {
        let app = router::scim_routes(&fixture.state).with_state(fixture.state.clone());
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .header(
                header::AUTHORIZATION,
                format!("Bearer {}", fixture.bearer_token),
            )
            .body(Body::empty())
            .expect("build scim request");

        app.oneshot(request)
            .await
            .expect("send scim request")
            .status()
    }

    async fn user_email(db: &DatabaseConnection, user_id: &str) -> String {
        Users::find()
            .filter(users::Column::Id.eq(user_id))
            .one(db)
            .await
            .expect("query user")
            .expect("user exists")
            .email
    }

    async fn user_deleted_at_is_some(db: &DatabaseConnection, user_id: &str) -> bool {
        Users::find()
            .filter(users::Column::Id.eq(user_id))
            .one(db)
            .await
            .expect("query user")
            .expect("user exists")
            .deleted_at
            .is_some()
    }

    async fn membership_exists(db: &DatabaseConnection, org_id: &str, user_id: &str) -> bool {
        MembershipStore::find_by_org_and_user(DB::Conn(db), org_id, user_id)
            .await
            .expect("query membership")
            .is_some()
    }

    async fn create_org_scoped_user(
        db: &DatabaseConnection,
        org_id: &str,
        email: &str,
    ) -> users::Model {
        users::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            email: Set(email.to_string()),
            org_id: Set(Some(org_id.to_string())),
            password_hash: Set(None),
            is_platform_owner: Set(false),
            email_verified_at: Set(Some(Utc::now().naive_utc())),
            created_at: Set(Utc::now().naive_utc()),
            updated_at: Set(None),
            deleted_at: Set(None),
        }
        .insert(db)
        .await
        .expect("create org-scoped user")
    }

    #[tokio::test]
    async fn user_get_route_returns_org_member_as_scim_user() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_empty_request(
            &fixture,
            Method::GET,
            format!("/scim/v2/Users/{}", fixture.user_id),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schemas"][0], schemas::SCIM_USER_SCHEMA);
        assert_eq!(body["id"], fixture.user_id);
        assert_eq!(body["userName"], "scim-user@example.com");
        assert_eq!(body["active"], true);
    }

    #[tokio::test]
    async fn user_put_rejects_body_id_mismatch_and_preserves_user() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "id": "different-user",
                "userName": "changed@example.com"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "scim-user@example.com"
        );
    }

    #[tokio::test]
    async fn user_put_updates_email_when_body_id_matches() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "id": fixture.user_id,
                "userName": "updated@example.com",
                "emails": [{
                    "value": "updated@example.com",
                    "type": "work",
                    "primary": true
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.user_id);
        assert_eq!(body["userName"], "updated@example.com");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "updated@example.com"
        );
    }

    #[tokio::test]
    async fn group_put_rejects_body_id_mismatch() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_GROUP_SCHEMA],
                "id": "different-group",
                "displayName": "Changed"
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
    }

    #[tokio::test]
    async fn group_get_route_returns_scim_group_with_members() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_empty_request(
            &fixture,
            Method::GET,
            format!("/scim/v2/Groups/{}", fixture.org_id),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["schemas"][0], schemas::SCIM_GROUP_SCHEMA);
        assert_eq!(body["id"], fixture.org_id);
        assert_eq!(body["displayName"], "Acme");
        let members = body["members"].as_array().expect("group members");
        assert!(members
            .iter()
            .any(|member| member["value"] == fixture.user_id));
        assert!(members
            .iter()
            .any(|member| member["value"] == fixture.owner_id));
    }

    #[tokio::test]
    async fn group_put_replaces_members_without_removing_owner() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PUT,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_GROUP_SCHEMA],
                "id": fixture.org_id,
                "displayName": "Acme",
                "members": [{
                    "value": fixture.owner_id,
                    "$ref": format!("http://localhost:3001/scim/v2/Users/{}", fixture.owner_id),
                    "type": "User"
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.org_id);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
        assert!(!membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
    }

    #[tokio::test]
    async fn user_patch_rejects_missing_patch_schema_and_preserves_user() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "userName",
                    "value": "changed@example.com"
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "scim-user@example.com"
        );
    }

    #[tokio::test]
    async fn user_patch_updates_email_with_valid_patch_schema() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "userName",
                    "value": "patched@example.com"
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.user_id);
        assert_eq!(body["userName"], "patched@example.com");
        assert_eq!(
            user_email(&fixture.state.db, &fixture.user_id).await,
            "patched@example.com"
        );
    }

    #[tokio::test]
    async fn user_patch_deactivates_member_with_valid_patch_schema() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Users/{}", fixture.user_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "replace",
                    "path": "active",
                    "value": false
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.user_id);
        assert_eq!(body["active"], false);
        assert!(user_deleted_at_is_some(&fixture.state.db, &fixture.user_id).await);
    }

    #[tokio::test]
    async fn group_patch_rejects_missing_patch_schema() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_GROUP_SCHEMA],
                "Operations": [{
                    "op": "remove",
                    "path": format!("members[value eq \"{}\"]", fixture.user_id)
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["scimType"], "invalidValue");
    }

    #[tokio::test]
    async fn group_patch_removes_regular_member_with_valid_patch_schema() {
        let fixture = setup_fixture().await;
        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "remove",
                    "path": format!("members[value eq \"{}\"]", fixture.user_id)
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.org_id);
        assert!(!membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
    }

    #[tokio::test]
    async fn group_patch_add_maps_user_to_member_role_and_permission() {
        let fixture = setup_fixture().await;
        let user =
            create_org_scoped_user(&fixture.state.db, &fixture.org_id, "scim-add@example.com")
                .await;

        let (status, body) = scim_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "add",
                    "value": {
                        "members": [{
                            "value": user.id,
                            "$ref": format!("http://localhost:3001/scim/v2/Users/{}", user.id),
                            "type": "User"
                        }]
                    }
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["id"], fixture.org_id);
        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &user.id,
        )
        .await
        .expect("query added scim group member")
        .expect("scim group add creates membership");
        assert_eq!(membership.role, "member");
        assert!(PermissionsStore::check(
            DB::Conn(&fixture.state.db),
            "organization",
            &fixture.org_id,
            "member",
            &user.id,
        )
        .await
        .expect("check scim-added member permission"));
    }

    #[tokio::test]
    async fn group_patch_rejects_owner_removal() {
        let fixture = setup_fixture().await;
        let status = scim_status_request(
            &fixture,
            Method::PATCH,
            format!("/scim/v2/Groups/{}", fixture.org_id),
            serde_json::json!({
                "schemas": [schemas::SCIM_PATCH_SCHEMA],
                "Operations": [{
                    "op": "remove",
                    "path": format!("members[value eq \"{}\"]", fixture.owner_id)
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
    }

    #[tokio::test]
    async fn user_create_and_list_routes_provision_org_member() {
        let fixture = setup_fixture().await;
        let (status, created) = scim_request(
            &fixture,
            Method::POST,
            "/scim/v2/Users".to_string(),
            serde_json::json!({
                "schemas": [schemas::SCIM_USER_SCHEMA],
                "userName": "provisioned@example.com",
                "emails": [{
                    "value": "provisioned@example.com",
                    "type": "work",
                    "primary": true
                }]
            }),
        )
        .await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created["userName"], "provisioned@example.com");
        assert_eq!(created["active"], true);
        let created_user_id = created["id"]
            .as_str()
            .expect("created scim user id")
            .to_string();

        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &created_user_id,
        )
        .await
        .expect("query created scim user membership")
        .expect("created user has org membership");
        assert_eq!(membership.role, "member");

        let (list_status, list_body) =
            scim_empty_request(&fixture, Method::GET, "/scim/v2/Users".to_string()).await;
        assert_eq!(list_status, StatusCode::OK);
        assert!(list_body["totalResults"].as_u64().unwrap_or_default() >= 3);
        let listed_users = list_body["Resources"]
            .as_array()
            .expect("list response resources");
        assert!(listed_users
            .iter()
            .any(|resource| resource["userName"] == "provisioned@example.com"));
    }

    #[tokio::test]
    async fn user_delete_removes_member_membership() {
        let fixture = setup_fixture().await;
        let status = scim_empty_status_request(
            &fixture,
            Method::DELETE,
            format!("/scim/v2/Users/{}", fixture.user_id),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &fixture.user_id,
        )
        .await
        .expect("query deleted user membership");
        assert!(membership.is_none());
    }

    #[tokio::test]
    async fn user_delete_rejects_owner_deprovisioning() {
        let fixture = setup_fixture().await;
        let status = scim_empty_status_request(
            &fixture,
            Method::DELETE,
            format!("/scim/v2/Users/{}", fixture.owner_id),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        let membership = MembershipStore::find_by_org_and_user(
            DB::Conn(&fixture.state.db),
            &fixture.org_id,
            &fixture.owner_id,
        )
        .await
        .expect("query owner membership");
        assert!(membership.is_some());
    }

    #[tokio::test]
    async fn group_delete_rejects_org_deletion() {
        let fixture = setup_fixture().await;
        let status = scim_empty_status_request(
            &fixture,
            Method::DELETE,
            format!("/scim/v2/Groups/{}", fixture.org_id),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.owner_id).await);
        assert!(membership_exists(&fixture.state.db, &fixture.org_id, &fixture.user_id).await);
    }
}
