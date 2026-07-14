use anyhow::Result;
use qrcode::{render::svg, QrCode};
use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};

const TOTP_ISSUER: &str = "SSO Platform";
const BACKUP_CODE_LENGTH: usize = 8;
const BACKUP_CODE_COUNT: usize = 10;

pub struct MfaService;

impl MfaService {
    pub fn new() -> Self {
        Self
    }

    /// Generate a new TOTP secret for a user
    pub fn generate_totp_secret(&self) -> Result<String> {
        let secret = Secret::generate_secret();
        Ok(secret.to_encoded().to_string())
    }

    /// Create a TOTP instance from a secret
    pub fn create_totp(&self, secret: &str, account_name: &str) -> Result<TOTP> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret.to_string()).to_bytes()?,
            Some(TOTP_ISSUER.to_string()),
            account_name.to_string(),
        )?;
        Ok(totp)
    }

    /// Generate a QR code URI for TOTP setup
    #[allow(dead_code)]
    pub fn generate_qr_code_uri(&self, secret: &str, account_name: &str) -> Result<String> {
        let totp = self.create_totp(secret, account_name)?;
        totp.get_qr_base64()
            .map_err(|e| anyhow::anyhow!("Failed to generate QR code: {}", e))
    }

    /// Generate a QR code as SVG for TOTP setup
    pub fn generate_qr_code_svg(&self, secret: &str, account_name: &str) -> Result<String> {
        let totp = self.create_totp(secret, account_name)?;
        let uri = totp.get_url();

        let code = QrCode::new(uri)?;
        let svg = code
            .render()
            .min_dimensions(200, 200)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();

        Ok(svg)
    }

    /// Verify a TOTP code
    pub fn verify_totp(&self, secret: &str, code: &str, account_name: &str) -> Result<bool> {
        let totp = self.create_totp(secret, account_name)?;
        Ok(totp.check_current(code)?)
    }

    /// Generate backup codes for recovery
    pub fn generate_backup_codes(&self) -> Vec<String> {
        let mut codes = Vec::with_capacity(BACKUP_CODE_COUNT);
        let mut rng = rand::thread_rng();

        for _ in 0..BACKUP_CODE_COUNT {
            let code: String = (0..BACKUP_CODE_LENGTH)
                .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
                .collect();
            codes.push(code.to_uppercase());
        }

        codes
    }

    /// Format backup codes for display (groups of 4)
    pub fn format_backup_codes(codes: &[String]) -> Vec<String> {
        codes
            .iter()
            .map(|code| {
                code.chars()
                    .collect::<Vec<_>>()
                    .chunks(4)
                    .map(|chunk| chunk.iter().collect::<String>())
                    .collect::<Vec<_>>()
                    .join("-")
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp_secret() {
        let service = MfaService::new();
        let secret = service.generate_totp_secret().unwrap();
        assert!(!secret.is_empty());
    }

    #[test]
    fn test_verify_totp() {
        let service = MfaService::new();
        let secret = service.generate_totp_secret().unwrap();
        let totp = service.create_totp(&secret, "test@example.com").unwrap();
        let code = totp.generate_current().unwrap();

        let is_valid = service
            .verify_totp(&secret, &code, "test@example.com")
            .unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_generate_backup_codes() {
        let service = MfaService::new();
        let codes = service.generate_backup_codes();

        assert_eq!(codes.len(), BACKUP_CODE_COUNT);
        for code in &codes {
            assert_eq!(code.len(), BACKUP_CODE_LENGTH);
            assert!(code.chars().all(|c| c.is_alphanumeric()));
        }
    }

    #[test]
    fn test_format_backup_codes() {
        let codes = vec!["ABCD1234".to_string(), "EFGH5678".to_string()];

        let formatted = MfaService::format_backup_codes(&codes);
        assert_eq!(formatted[0], "ABCD-1234");
        assert_eq!(formatted[1], "EFGH-5678");
    }
}
