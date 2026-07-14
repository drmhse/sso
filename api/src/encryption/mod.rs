use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use thiserror::Error;

pub const ALLOW_UNENCRYPTED_DEVELOPMENT_ENV: &str = "AUTHOS_ALLOW_UNENCRYPTED_DEVELOPMENT";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptionConfigurationError {
    #[error("ENCRYPTION_KEY is required; configure a 64-character hexadecimal key (32 bytes)")]
    MissingKey,
    #[error("ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes)")]
    InvalidKey,
}

#[derive(Clone)]
pub struct EncryptionService {
    cipher: Aes256Gcm,
    key_id: String,
}

impl EncryptionService {
    pub fn new() -> Result<Self, EncryptionConfigurationError> {
        let key_hex = match std::env::var("ENCRYPTION_KEY") {
            Ok(key) => key,
            Err(std::env::VarError::NotPresent) => {
                return Err(EncryptionConfigurationError::MissingKey)
            }
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(EncryptionConfigurationError::InvalidKey)
            }
        };
        Self::from_key_hex(&key_hex)
    }

    /// Load the encryption service for normal API startup.
    ///
    /// A missing key fails closed unless the deliberately verbose development
    /// escape hatch is set to `true`. An invalid configured key always fails.
    pub fn for_server_startup() -> Result<Option<Self>, EncryptionConfigurationError> {
        let allow_unencrypted_development = std::env::var(ALLOW_UNENCRYPTED_DEVELOPMENT_ENV)
            .is_ok_and(|value| value.eq_ignore_ascii_case("true"));
        let key = match std::env::var("ENCRYPTION_KEY") {
            Ok(key) => Some(key),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(EncryptionConfigurationError::InvalidKey)
            }
        };

        Self::from_startup_values(key.as_deref(), allow_unencrypted_development)
    }

    fn from_startup_values(
        key_hex: Option<&str>,
        allow_unencrypted_development: bool,
    ) -> Result<Option<Self>, EncryptionConfigurationError> {
        match key_hex {
            Some(key_hex) => Self::from_key_hex(key_hex).map(Some),
            None if allow_unencrypted_development => Ok(None),
            None => Err(EncryptionConfigurationError::MissingKey),
        }
    }

    fn from_key_hex(key_hex: &str) -> Result<Self, EncryptionConfigurationError> {
        if key_hex.len() != 64 || !key_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(EncryptionConfigurationError::InvalidKey);
        }

        let key_bytes =
            hex::decode(key_hex).map_err(|_| EncryptionConfigurationError::InvalidKey)?;

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)
            .map_err(|_| EncryptionConfigurationError::InvalidKey)?;

        Ok(Self {
            cipher,
            key_id: "default".to_string(),
        })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext for storage
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, encrypted: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        if encrypted.len() < 12 {
            return Err("Invalid encrypted data".into());
        }

        let (nonce_bytes, ciphertext) = encrypted.split_at(12);

        // Convert slice to array for Nonce::from
        let nonce_array: [u8; 12] = nonce_bytes.try_into().map_err(|_| "Invalid nonce length")?;
        let nonce = Nonce::from(nonce_array);

        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(String::from_utf8(plaintext)?)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

#[cfg(test)]
mod tests {
    use super::{EncryptionConfigurationError, EncryptionService};

    const VALID_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn accepts_exactly_32_bytes_of_hexadecimal_key_material() {
        let service = EncryptionService::from_startup_values(Some(VALID_KEY), false)
            .expect("valid key should initialize")
            .expect("valid key should enable encryption");

        assert_eq!(service.key_id(), "default");
    }

    #[test]
    fn rejects_incorrect_length_without_echoing_key_material() {
        let error = EncryptionService::from_startup_values(Some(&VALID_KEY[..63]), false)
            .err()
            .expect("short key should fail");

        assert_eq!(error, EncryptionConfigurationError::InvalidKey);
        assert!(!error.to_string().contains(&VALID_KEY[..16]));
    }

    #[test]
    fn rejects_non_hexadecimal_key_without_echoing_key_material() {
        let invalid_key = "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let error = EncryptionService::from_startup_values(Some(invalid_key), false)
            .err()
            .expect("non-hex key should fail");

        assert_eq!(error, EncryptionConfigurationError::InvalidKey);
        assert!(!error.to_string().contains(invalid_key));
    }

    #[test]
    fn missing_key_fails_closed_by_default() {
        let error = EncryptionService::from_startup_values(None, false)
            .err()
            .expect("missing key should fail");

        assert_eq!(error, EncryptionConfigurationError::MissingKey);
    }

    #[test]
    fn development_escape_hatch_only_allows_a_missing_key() {
        assert!(EncryptionService::from_startup_values(None, true)
            .expect("escape hatch should permit a missing key")
            .is_none());

        let error = EncryptionService::from_startup_values(Some("invalid"), true)
            .err()
            .expect("escape hatch must not permit an invalid configured key");
        assert_eq!(error, EncryptionConfigurationError::InvalidKey);
    }
}
