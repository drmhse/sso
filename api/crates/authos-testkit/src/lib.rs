//! Shared test fixtures. Pulled in as a dev-dependency only, so none of
//! this reaches a production build.

use authos_core::config::Config;
use authos_core::rsa_keys::GeneratedKey;
use authos_crypto::crypto::jwt::JwtService;
use authos_entities::entities::{memberships, organizations, users};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use migration::{Migrator, MigratorTrait};
use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Set};
use uuid::Uuid;

pub fn test_config() -> Config {
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

pub fn test_jwt_service(config: &Config) -> JwtService {
    let rsa = GeneratedKey::generate().expect("generate test rsa key");
    JwtService::new(
        &STANDARD.encode(rsa.private_key_pem().expect("encode private key pem")),
        &STANDARD.encode(rsa.public_key_pem().expect("encode public key pem")),
        config.jwt_expiration_hours,
        "test-key",
        &config.base_url,
    )
    .expect("create test jwt service")
}

pub async fn setup_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("connect in-memory sqlite");
    Migrator::up(&db, None).await.expect("run migrations");
    db
}

/// Insert a user directly through the entity layer. `email` defaults to one
/// derived from the generated id.
pub async fn insert_user(db: &DatabaseConnection, email: Option<&str>) -> String {
    let user_id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    users::ActiveModel {
        id: Set(user_id.clone()),
        email: Set(email.map_or_else(|| format!("{user_id}@example.com"), str::to_string)),
        org_id: Set(None),
        is_platform_owner: Set(false),
        password_hash: Set(None),
        email_verified_at: Set(None),
        created_at: Set(now),
        updated_at: Set(None),
        deleted_at: Set(None),
    }
    .insert(db)
    .await
    .expect("insert user");

    user_id
}

pub async fn insert_org(db: &DatabaseConnection, owner_user_id: &str) -> String {
    let org_id = Uuid::new_v4().to_string();
    let now = Utc::now().naive_utc();
    organizations::ActiveModel {
        id: Set(org_id.clone()),
        slug: Set(format!("org-{}", &org_id[..8])),
        name: Set("Test Org".to_string()),
        owner_user_id: Set(owner_user_id.to_string()),
        status: Set("active".to_string()),
        tier_id: Set(None),
        max_services: Set(None),
        max_users: Set(None),
        approved_by: Set(None),
        approved_at: Set(None),
        rejected_by: Set(None),
        rejected_at: Set(None),
        rejection_reason: Set(None),
        smtp_host: Set(None),
        smtp_port: Set(None),
        smtp_username: Set(None),
        smtp_password_encrypted: Set(None),
        smtp_from_email: Set(None),
        smtp_from_name: Set(None),
        smtp_encryption_key_id: Set(None),
        custom_domain: Set(None),
        domain_verified: Set(false),
        domain_verification_token: Set(None),
        brand_logo_url: Set(None),
        brand_primary_color: Set(None),
        feature_overrides: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(db)
    .await
    .expect("insert org");

    org_id
}

pub async fn insert_membership(db: &DatabaseConnection, org_id: &str, user_id: &str) {
    memberships::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        org_id: Set(org_id.to_string()),
        user_id: Set(user_id.to_string()),
        role: Set("member".to_string()),
        created_at: Set(Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .expect("insert membership");
}
