#![allow(dead_code)]

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
        let reset_url = format!("{}/reset-password?token={}", base_url, token);

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
        let invitation_url = format!("{}/invitations/accept?token={}", base_url, token);

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
                tracing::error!("SMTP send failed");
                Err(anyhow::Error::new(e).context("SMTP error"))
            }
        }
    }
}

/// Helper function to get an email service for a specific organization.
/// Security Audit Item 10: Does NOT fall back to platform SMTP if org has their own configured.
/// This prevents platform branding from leaking to white-label customers.
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

    // If organization has SMTP configured, use it (no fallback!)
    if let Some(settings) = org_smtp {
        // Check if org has any SMTP configuration at all
        let has_smtp_config = settings.smtp_host.is_some() || settings.smtp_from_email.is_some();

        if has_smtp_config {
            // Org has SMTP configured - try to use it, fail if incomplete/broken
            let (host, port, username, password_encrypted, from_email) = match (
                settings.smtp_host,
                settings.smtp_port,
                settings.smtp_username,
                settings.smtp_password_encrypted,
                settings.smtp_from_email,
            ) {
                (Some(h), Some(p), Some(u), Some(pwd), Some(from)) => (h, p, u, pwd, from),
                _ => {
                    // Security Audit Item 10: Fail immediately, don't fall back
                    return Err(anyhow::anyhow!(
                        "Organization SMTP configuration is incomplete. \
                        All fields (host, port, username, password, from_email) are required."
                    ));
                }
            };

            // Decrypt the password
            let encryption = encryption.ok_or_else(|| {
                anyhow::anyhow!("Encryption service required to decrypt org SMTP password")
            })?;

            let password = encryption
                .decrypt_with_context(
                    &password_encrypted,
                    crate::encryption::EncryptionContext::new(
                        "organizations",
                        org_id,
                        "smtp_password_encrypted",
                    ),
                )
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

            // Security Audit Item 10: If org SMTP is configured but fails, DON'T fall back
            return Ok(Some(EmailService::from_config(config)?));
        }
    }

    // Only fall back to platform-level SMTP if org has NO SMTP config at all
    Ok(EmailService::from_env().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smtp_config(username: String, password: String) -> SmtpConfig {
        SmtpConfig {
            host: "smtp.example.test".to_string(),
            port: 587,
            username,
            password,
            from_email: "auth@example.test".to_string(),
            from_name: "AuthOS Tests".to_string(),
        }
    }

    #[test]
    fn from_config_builds_authenticated_and_unauthenticated_transports() {
        // Credentials path.
        assert!(
            EmailService::from_config(smtp_config("user".to_string(), "pass".to_string())).is_ok()
        );
        // No-auth path (development relays like Mailpit).
        assert!(EmailService::from_config(smtp_config(String::new(), String::new())).is_ok());
    }

    #[test]
    fn from_env_requires_the_mandatory_variables() {
        // SAFETY: single-threaded test mutating process env for this assertion.
        unsafe { std::env::remove_var("SMTP_HOST") };
        assert!(EmailService::from_env().is_err(), "missing SMTP_HOST fails");

        unsafe { std::env::set_var("SMTP_HOST", "smtp.example.test") };
        unsafe { std::env::set_var("SMTP_PORT", "not-a-number") };
        assert!(
            EmailService::from_env().is_err(),
            "a non-numeric SMTP_PORT fails"
        );

        unsafe { std::env::set_var("SMTP_PORT", "587") };
        unsafe { std::env::remove_var("SMTP_FROM_EMAIL") };
        assert!(
            EmailService::from_env().is_err(),
            "missing SMTP_FROM_EMAIL fails"
        );
        unsafe { std::env::set_var("SMTP_FROM_EMAIL", "auth@example.test") };

        // With everything set, construction succeeds.
        assert!(EmailService::from_env().is_ok());
        unsafe { std::env::remove_var("SMTP_HOST") };
        unsafe { std::env::remove_var("SMTP_PORT") };
        unsafe { std::env::remove_var("SMTP_FROM_EMAIL") };
    }

    #[tokio::test]
    async fn test_connection_fails_fast_against_an_unroutable_relay() {
        let service =
            EmailService::from_config(smtp_config("user".to_string(), "pass".to_string()))
                .expect("build service");
        // The configured host does not resolve; connection must error, not hang.
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(35),
                service.test_connection()
            )
            .await
            .expect("test_connection should not hang")
            .is_err(),
            "an unroutable relay must surface a connection error"
        );
    }
}
