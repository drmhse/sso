use std::env;

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub jwt_secret: String,
    pub jwt_expiration_hours: i64,

    // OAuth providers
    pub github_client_id: String,
    pub github_client_secret: String,
    pub github_redirect_uri: String,

    pub google_client_id: String,
    pub google_client_secret: String,
    pub google_redirect_uri: String,

    pub microsoft_client_id: String,
    pub microsoft_client_secret: String,
    pub microsoft_redirect_uri: String,

    // Platform Admin OAuth
    pub platform_github_client_id: String,
    pub platform_github_client_secret: String,
    pub platform_google_client_id: String,
    pub platform_google_client_secret: String,
    pub platform_microsoft_client_id: String,
    pub platform_microsoft_client_secret: String,

    // Stripe
    pub stripe_secret_key: String,
    pub stripe_webhook_secret: String,

    // Server
    pub server_host: String,
    pub server_port: u16,
    pub base_url: String,
    pub platform_admin_redirect_uri: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Config {
            database_url: env::var("DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:./data.db".to_string()),
            jwt_secret: env::var("JWT_SECRET").map_err(|_| "JWT_SECRET must be set")?,
            jwt_expiration_hours: env::var("JWT_EXPIRATION_HOURS")
                .unwrap_or_else(|_| "24".to_string())
                .parse()
                .map_err(|_| "JWT_EXPIRATION_HOURS must be a valid number")?,

            github_client_id: env::var("GITHUB_CLIENT_ID")
                .map_err(|_| "GITHUB_CLIENT_ID must be set")?,
            github_client_secret: env::var("GITHUB_CLIENT_SECRET")
                .map_err(|_| "GITHUB_CLIENT_SECRET must be set")?,
            github_redirect_uri: env::var("GITHUB_REDIRECT_URI")
                .map_err(|_| "GITHUB_REDIRECT_URI must be set")?,

            google_client_id: env::var("GOOGLE_CLIENT_ID")
                .map_err(|_| "GOOGLE_CLIENT_ID must be set")?,
            google_client_secret: env::var("GOOGLE_CLIENT_SECRET")
                .map_err(|_| "GOOGLE_CLIENT_SECRET must be set")?,
            google_redirect_uri: env::var("GOOGLE_REDIRECT_URI")
                .map_err(|_| "GOOGLE_REDIRECT_URI must be set")?,

            microsoft_client_id: env::var("MICROSOFT_CLIENT_ID")
                .map_err(|_| "MICROSOFT_CLIENT_ID must be set")?,
            microsoft_client_secret: env::var("MICROSOFT_CLIENT_SECRET")
                .map_err(|_| "MICROSOFT_CLIENT_SECRET must be set")?,
            microsoft_redirect_uri: env::var("MICROSOFT_REDIRECT_URI")
                .map_err(|_| "MICROSOFT_REDIRECT_URI must be set")?,

            platform_github_client_id: env::var("PLATFORM_GITHUB_CLIENT_ID")
                .map_err(|_| "PLATFORM_GITHUB_CLIENT_ID must be set")?,
            platform_github_client_secret: env::var("PLATFORM_GITHUB_CLIENT_SECRET")
                .map_err(|_| "PLATFORM_GITHUB_CLIENT_SECRET must be set")?,
            platform_google_client_id: env::var("PLATFORM_GOOGLE_CLIENT_ID")
                .map_err(|_| "PLATFORM_GOOGLE_CLIENT_ID must be set")?,
            platform_google_client_secret: env::var("PLATFORM_GOOGLE_CLIENT_SECRET")
                .map_err(|_| "PLATFORM_GOOGLE_CLIENT_SECRET must be set")?,
            platform_microsoft_client_id: env::var("PLATFORM_MICROSOFT_CLIENT_ID")
                .map_err(|_| "PLATFORM_MICROSOFT_CLIENT_ID must be set")?,
            platform_microsoft_client_secret: env::var("PLATFORM_MICROSOFT_CLIENT_SECRET")
                .map_err(|_| "PLATFORM_MICROSOFT_CLIENT_SECRET must be set")?,

            stripe_secret_key: env::var("STRIPE_SECRET_KEY")
                .map_err(|_| "STRIPE_SECRET_KEY must be set")?,
            stripe_webhook_secret: env::var("STRIPE_WEBHOOK_SECRET")
                .map_err(|_| "STRIPE_WEBHOOK_SECRET must be set")?,

            server_host: env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            server_port: env::var("SERVER_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .map_err(|_| "SERVER_PORT must be a valid number")?,
            base_url: env::var("BASE_URL").map_err(|_| "BASE_URL must be set")?,
            platform_admin_redirect_uri: env::var("PLATFORM_ADMIN_REDIRECT_URI")
                .map_err(|_| "PLATFORM_ADMIN_REDIRECT_URI must be set")?,
        })
    }
}
