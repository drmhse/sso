use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_expiration_hours: i64,

    // Database connection pool settings
    /// Maximum number of connections in the pool (default: 200)
    pub db_max_connections: u32,
    /// Minimum number of connections to keep alive (default: 5)
    pub db_min_connections: u32,
    /// Timeout in seconds for acquiring a connection from the pool (default: 30)
    pub db_acquire_timeout_secs: u64,
    /// Idle timeout in seconds before a connection is closed (default: 600)
    pub db_idle_timeout_secs: u64,
    /// Maximum lifetime of a connection in seconds (default: 1800)
    pub db_max_lifetime_secs: u64,

    // Platform OAuth (used for admin dashboard and platform-level operations)
    // These are now optional to allow developers to configure only the providers they need
    pub platform_github_client_id: Option<String>,
    pub platform_github_client_secret: Option<String>,
    pub platform_github_redirect_uri: Option<String>,
    pub platform_google_client_id: Option<String>,
    pub platform_google_client_secret: Option<String>,
    pub platform_google_redirect_uri: Option<String>,
    pub platform_microsoft_client_id: Option<String>,
    pub platform_microsoft_client_secret: Option<String>,
    pub platform_microsoft_redirect_uri: Option<String>,

    // External OAuth URLs (configurable for testing)
    pub platform_github_auth_url: Option<String>,
    pub platform_github_token_url: Option<String>,
    pub platform_github_user_api_url: Option<String>,
    pub platform_google_auth_url: Option<String>,
    pub platform_google_token_url: Option<String>,
    pub platform_google_user_api_url: Option<String>,
    pub platform_microsoft_auth_url: Option<String>,
    pub platform_microsoft_token_url: Option<String>,
    pub platform_microsoft_user_api_url: Option<String>,

    // Stripe
    pub stripe_secret_key: Option<String>,
    pub stripe_webhook_secret: Option<String>,
    pub stripe_api_base_url: Option<String>,

    // Server
    pub server_host: String,
    pub server_port: u16,
    pub base_url: String,
    pub platform_dashboard_base_url: String,
    pub full_web_client_base_url: Option<String>,
    pub platform_owner_email: Option<String>,
    pub platform_owner_password: Option<String>,
    pub managed_config_path: Option<String>,
    pub managed_state_path: Option<String>,
    pub managed_status_path: Option<String>,
    pub managed_request_path: Option<String>,
    pub disable_rate_limiting: bool,

    // Job Processing
    /// Interval in seconds between job processing runs (default: 10)
    /// Set to a lower value (e.g., 1) in test environments for faster email delivery
    pub job_processor_interval_secs: u64,

    /// Batch size for concurrent job processing (default: 10)
    /// Set to a lower value (e.g., 2) in test environments to avoid overwhelming SMTP servers
    pub job_processor_batch_size: usize,
}

/// Helper to get an optional env var, treating empty strings as None
fn env_var_optional(key: &str) -> Option<String> {
    env::var(key).ok().filter(|s| !s.is_empty())
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:./data.db".to_string()),
            jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .map_err(|_| "JWT_EXPIRATION_HOURS must be a valid number")?,

            // Database connection pool settings
            db_max_connections: env::var("DB_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "200".to_string())
                .parse()
                .map_err(|_| "DB_MAX_CONNECTIONS must be a valid number")?,
            db_min_connections: env::var("DB_MIN_CONNECTIONS")
                .unwrap_or_else(|_| "5".to_string())
                .parse()
                .map_err(|_| "DB_MIN_CONNECTIONS must be a valid number")?,
            db_acquire_timeout_secs: env::var("DB_ACQUIRE_TIMEOUT_SECS")
                .unwrap_or_else(|_| "30".to_string())
                .parse()
                .map_err(|_| "DB_ACQUIRE_TIMEOUT_SECS must be a valid number")?,
            db_idle_timeout_secs: env::var("DB_IDLE_TIMEOUT_SECS")
                .unwrap_or_else(|_| "600".to_string())
                .parse()
                .map_err(|_| "DB_IDLE_TIMEOUT_SECS must be a valid number")?,
            db_max_lifetime_secs: env::var("DB_MAX_LIFETIME_SECS")
                .unwrap_or_else(|_| "1800".to_string())
                .parse()
                .map_err(|_| "DB_MAX_LIFETIME_SECS must be a valid number")?,

            platform_github_client_id: env_var_optional("PLATFORM_GITHUB_CLIENT_ID"),
            platform_github_client_secret: env_var_optional("PLATFORM_GITHUB_CLIENT_SECRET"),
            platform_github_redirect_uri: env_var_optional("PLATFORM_GITHUB_REDIRECT_URI"),
            platform_google_client_id: env_var_optional("PLATFORM_GOOGLE_CLIENT_ID"),
            platform_google_client_secret: env_var_optional("PLATFORM_GOOGLE_CLIENT_SECRET"),
            platform_google_redirect_uri: env_var_optional("PLATFORM_GOOGLE_REDIRECT_URI"),
            platform_microsoft_client_id: env_var_optional("PLATFORM_MICROSOFT_CLIENT_ID"),
            platform_microsoft_client_secret: env_var_optional("PLATFORM_MICROSOFT_CLIENT_SECRET"),
            platform_microsoft_redirect_uri: env_var_optional("PLATFORM_MICROSOFT_REDIRECT_URI"),

            // External OAuth URLs (optional for testing)
            platform_github_auth_url: env_var_optional("PLATFORM_GITHUB_AUTH_URL"),
            platform_github_token_url: env_var_optional("PLATFORM_GITHUB_TOKEN_URL"),
            platform_github_user_api_url: env_var_optional("PLATFORM_GITHUB_USER_API_URL"),
            platform_google_auth_url: env_var_optional("PLATFORM_GOOGLE_AUTH_URL"),
            platform_google_token_url: env_var_optional("PLATFORM_GOOGLE_TOKEN_URL"),
            platform_google_user_api_url: env_var_optional("PLATFORM_GOOGLE_USER_API_URL"),
            platform_microsoft_auth_url: env_var_optional("PLATFORM_MICROSOFT_AUTH_URL"),
            platform_microsoft_token_url: env_var_optional("PLATFORM_MICROSOFT_TOKEN_URL"),
            platform_microsoft_user_api_url: env_var_optional("PLATFORM_MICROSOFT_USER_API_URL"),

            stripe_secret_key: env_var_optional("STRIPE_SECRET_KEY"),
            stripe_webhook_secret: env_var_optional("STRIPE_WEBHOOK_SECRET"),
            stripe_api_base_url: env_var_optional("STRIPE_API_BASE_URL"),

            server_host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .map_err(|_| "SERVER_PORT must be a valid number")?,
            base_url: env::var("BASE_URL")
                .map_err(|_| "BASE_URL must be set")?
                .trim_end_matches('/')
                .to_string(),
            platform_dashboard_base_url: env::var("PLATFORM_BASE_URL")
                .or_else(|_| env::var("PLATFORM_DASHBOARD_BASE_URL"))
                .map_err(|_| "PLATFORM_BASE_URL must be set")?
                .trim_end_matches('/')
                .to_string(),
            full_web_client_base_url: env_var_optional("FULL_WEB_CLIENT_BASE_URL")
                .map(|value| value.trim_end_matches('/').to_string()),
            platform_owner_email: env_var_optional("PLATFORM_OWNER_EMAIL"),
            platform_owner_password: env_var_optional("PLATFORM_OWNER_PASSWORD"),
            managed_config_path: env_var_optional("AUTHOS_MANAGED_CONFIG_PATH"),
            managed_state_path: env_var_optional("AUTHOS_MANAGED_STATE_PATH"),
            managed_status_path: env_var_optional("AUTHOS_MANAGED_STATUS_PATH"),
            managed_request_path: env_var_optional("AUTHOS_MANAGED_REQUEST_PATH"),
            disable_rate_limiting: env::var("DISABLE_RATE_LIMITING")
                .unwrap_or_default()
                .to_lowercase()
                == "true",
            job_processor_interval_secs: env::var("JOB_PROCESSOR_INTERVAL_SECS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .map_err(|_| "JOB_PROCESSOR_INTERVAL_SECS must be a valid number")?,
            job_processor_batch_size: env::var("JOB_PROCESSOR_BATCH_SIZE")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .map_err(|_| "JOB_PROCESSOR_BATCH_SIZE must be a valid number")?,
        })
    }

    // Helper methods to get OAuth URLs with fallbacks to real URLs
    pub fn get_github_user_api_url(&self) -> String {
        self.platform_github_user_api_url
            .clone()
            .unwrap_or_else(|| "https://api.github.com/user".to_string())
    }

    pub fn get_github_user_emails_api_url(&self) -> String {
        // GitHub uses the same base URL for user emails API
        let base_url = self
            .platform_github_user_api_url
            .clone()
            .unwrap_or_else(|| "https://api.github.com".to_string());
        format!("{}/user/emails", base_url.trim_end_matches('/'))
    }

    pub fn get_google_user_api_url(&self) -> String {
        self.platform_google_user_api_url
            .clone()
            .unwrap_or_else(|| "https://www.googleapis.com/oauth2/v2/userinfo".to_string())
    }

    pub fn get_microsoft_user_api_url(&self) -> String {
        self.platform_microsoft_user_api_url
            .clone()
            .unwrap_or_else(|| "https://graph.microsoft.com/v1.0/me".to_string())
    }
}
