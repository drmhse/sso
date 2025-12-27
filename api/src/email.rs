use anyhow::{Context, Result};
use lettre::message::{header::ContentType, Mailbox};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use std::env;
use std::sync::Arc;

#[derive(Clone)]
pub struct EmailService {
    smtp_transport: Arc<AsyncSmtpTransport<Tokio1Executor>>,
    from_address: Mailbox,
}

/// SMTP configuration for creating an email service
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_email: String,
    pub from_name: String,
}

impl EmailService {
    /// Creates a new email service from environment variables.
    ///
    /// Required environment variables:
    /// - SMTP_HOST: SMTP server host
    /// - SMTP_PORT: SMTP server port
    /// - SMTP_FROM_EMAIL: From email address
    ///
    /// Optional environment variables:
    /// - SMTP_USERNAME: SMTP authentication username (optional for dev servers)
    /// - SMTP_PASSWORD: SMTP authentication password (optional for dev servers)
    /// - SMTP_FROM_NAME: From name (optional, defaults to "SSO Platform")
    pub fn from_env() -> Result<Self> {
        let config = SmtpConfig {
            host: env::var("SMTP_HOST").context("SMTP_HOST must be set")?,
            port: env::var("SMTP_PORT")
                .context("SMTP_PORT must be set")?
                .parse()
                .context("SMTP_PORT must be a valid number")?,
            username: env::var("SMTP_USERNAME").unwrap_or_else(|_| "".to_string()),
            password: env::var("SMTP_PASSWORD").unwrap_or_else(|_| "".to_string()),
            from_email: env::var("SMTP_FROM_EMAIL").context("SMTP_FROM_EMAIL must be set")?,
            from_name: env::var("SMTP_FROM_NAME").unwrap_or_else(|_| "SSO Platform".to_string()),
        };

        Self::from_config(config)
    }

    /// Creates a new email service from a configuration struct.
    /// This allows for dynamic SMTP configuration per organization.
    pub fn from_config(config: SmtpConfig) -> Result<Self> {
        use std::time::Duration;

        // Check if auth is required before potentially moving username/password
        let has_auth = !config.username.is_empty() && !config.password.is_empty();

        // Use different transport configurations based on whether authentication is provided
        let smtp_transport = if !has_auth {
            // For development SMTP servers like Mailpit that don't require authentication
            AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
                .port(config.port)
                .timeout(Some(Duration::from_secs(10)))
                .build()
        } else {
            // For production SMTP servers with authentication
            let credentials = Credentials::new(config.username, config.password);
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.host)
                .context("Failed to create SMTP transport")?
                .port(config.port)
                .timeout(Some(Duration::from_secs(30)))
                .credentials(credentials)
                .build()
        };

        let from_address: Mailbox = format!("{} <{}>", config.from_name, config.from_email)
            .parse()
            .context("Invalid from email address")?;

        tracing::info!(
            host = %config.host,
            port = %config.port,
            from = %config.from_email,
            has_auth = has_auth,
            "Email service initialized"
        );

        Ok(Self {
            smtp_transport: Arc::new(smtp_transport),
            from_address,
        })
    }

    /// Test the SMTP connection to verify connectivity.
    /// This should be called during startup to catch configuration issues early.
    pub async fn test_connection(&self) -> Result<()> {
        self.smtp_transport
            .test_connection()
            .await
            .map_err(|e| anyhow::anyhow!("SMTP connection test failed: {}", e))?;
        tracing::info!("SMTP connection test successful");
        Ok(())
    }

    /// Sends an email verification email with a verification link.
    pub async fn send_verification_email(
        &self,
        to_email: &str,
        token: &str,
        base_url: &str,
    ) -> Result<()> {
        let verification_url = format!("{}/auth/verify-email?token={}", base_url, token);

        let subject = "Verify Your Email Address";
        let body = format!(
            "Welcome to our platform!\n\n\
            Please verify your email address by clicking the link below:\n\n\
            {}\n\n\
            This link will expire in 24 hours.\n\n\
            If you didn't create an account, you can safely ignore this email.",
            verification_url
        );

        self.send_email(to_email, subject, &body).await
    }

    /// Sends a password reset email with a reset link.
    pub async fn send_password_reset_email(
        &self,
        to_email: &str,
        token: &str,
        base_url: &str,
    ) -> Result<()> {
        let reset_url = format!("{}/auth/reset-password?token={}", base_url, token);

        let subject = "Reset Your Password";
        let body = format!(
            "We received a request to reset your password.\n\n\
            Click the link below to reset your password:\n\n\
            {}\n\n\
            This link will expire in 1 hour.\n\n\
            If you didn't request a password reset, you can safely ignore this email.",
            reset_url
        );

        self.send_email(to_email, subject, &body).await
    }

    /// Sends an organization invitation email with an invitation link.
    pub async fn send_invitation_email(
        &self,
        to_email: &str,
        token: &str,
        base_url: &str,
        organization_name: &str,
        inviter_email: &str,
        role: &str,
    ) -> Result<()> {
        let invitation_url = format!("{}/invitations/accept/{}", base_url, token);

        let subject = format!("You've been invited to join {}", organization_name);
        let body = format!(
            "{} ({}) has invited you to join {} as a {}.\n\n\
            Click the link below to accept or decline this invitation:\n\n\
            {}\n\n\
            This invitation will expire in 7 days.\n\n\
            If you don't recognize this invitation, you can safely ignore this email.",
            inviter_email, inviter_email, organization_name, role, invitation_url
        );

        self.send_email(to_email, &subject, &body).await
    }

    /// Low-level method to send an email.
    pub async fn send_email(&self, to_email: &str, subject: &str, body: &str) -> Result<()> {
        let to_address: Mailbox = to_email
            .parse()
            .context("Invalid recipient email address")?;

        let email = Message::builder()
            .from(self.from_address.clone())
            .to(to_address)
            .subject(subject)
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .context("Failed to build email message")?;

        // Send email using async SMTP transport with connection pooling
        match self.smtp_transport.send(email).await {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::error!(
                    to = %to_email,
                    subject = %subject,
                    error = ?e,
                    "SMTP send failed"
                );
                Err(anyhow::Error::new(e).context("SMTP error"))
            }
        }
    }
}

/// Helper function to get an email service for a specific organization.
/// Falls back to platform-level SMTP if organization hasn't configured their own.
pub async fn get_email_service_for_org(
    db: &sea_orm::DatabaseConnection,
    org_id: &str,
    encryption: Option<&crate::encryption::EncryptionService>,
) -> Result<Option<EmailService>> {
    use sea_orm::FromQueryResult;

    // Try to fetch organization's SMTP settings
    use crate::entities::organizations;
    use crate::entities::prelude::Organizations;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect};

    #[derive(FromQueryResult)]
    struct OrgSmtpSettings {
        smtp_host: Option<String>,
        smtp_port: Option<i32>,
        smtp_username: Option<String>,
        smtp_password_encrypted: Option<Vec<u8>>,
        smtp_from_email: Option<String>,
        smtp_from_name: Option<String>,
    }

    let org_smtp = Organizations::find()
        .filter(organizations::Column::Id.eq(org_id))
        .select_only()
        .column(organizations::Column::SmtpHost)
        .column(organizations::Column::SmtpPort)
        .column(organizations::Column::SmtpUsername)
        .column(organizations::Column::SmtpPasswordEncrypted)
        .column(organizations::Column::SmtpFromEmail)
        .column(organizations::Column::SmtpFromName)
        .into_model::<OrgSmtpSettings>()
        .one(db)
        .await?;

    // If organization has SMTP configured, use it
    if let Some(settings) = org_smtp {
        if let (
            Some(host),
            Some(port),
            Some(username),
            Some(password_encrypted),
            Some(from_email),
        ) = (
            settings.smtp_host,
            settings.smtp_port,
            settings.smtp_username,
            settings.smtp_password_encrypted,
            settings.smtp_from_email,
        ) {
            // Decrypt the password
            if let Some(enc) = encryption {
                let password = enc
                    .decrypt(&password_encrypted)
                    .map_err(|e| anyhow::anyhow!("Failed to decrypt SMTP password: {}", e))?;

                let config = SmtpConfig {
                    host,
                    port: port as u16,
                    username,
                    password,
                    from_email,
                    from_name: settings
                        .smtp_from_name
                        .unwrap_or_else(|| "SSO Platform".to_string()),
                };

                return Ok(Some(EmailService::from_config(config)?));
            }
        }
    }

    // Fall back to platform-level SMTP
    Ok(EmailService::from_env().ok())
}
