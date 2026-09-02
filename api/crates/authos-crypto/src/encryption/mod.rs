use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use std::{collections::HashMap, sync::Arc};
use thiserror::Error;

pub const ALLOW_UNENCRYPTED_DEVELOPMENT_ENV: &str = "AUTHOS_ALLOW_UNENCRYPTED_DEVELOPMENT";
pub const ENCRYPTION_KEY_ID_ENV: &str = "ENCRYPTION_KEY_ID";
pub const ENCRYPTION_PREVIOUS_KEYS_ENV: &str = "ENCRYPTION_PREVIOUS_KEYS";

const DEFAULT_KEY_ID: &str = "default";
const ENVELOPE_MAGIC: &[u8; 8] = b"AUTHOSCE";
const ENVELOPE_VERSION_V1: u8 = 1;
const ENVELOPE_VERSION_V2: u8 = 2;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const MAX_KEY_ID_LENGTH: usize = 64;

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum EncryptionConfigurationError {
    #[error("ENCRYPTION_KEY is required; configure a 64-character hexadecimal key (32 bytes)")]
    MissingKey,
    #[error("ENCRYPTION_KEY must be exactly 64 hexadecimal characters (32 bytes)")]
    InvalidKey,
    #[error("ENCRYPTION_KEY_ID must be 1-64 ASCII letters, digits, '.', '_', or '-'")]
    InvalidKeyId,
    #[error(
        "ENCRYPTION_PREVIOUS_KEYS must be comma-separated key-id=64-character-hex-key entries"
    )]
    InvalidPreviousKeys,
    #[error("encryption key IDs must be unique across the active and previous key configuration")]
    DuplicateKeyId,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EncryptionError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("encrypted data is malformed")]
    MalformedCiphertext,
    #[error("encrypted data uses an unsupported envelope version")]
    UnsupportedEnvelopeVersion,
    #[error("encrypted data references a key that is not configured")]
    UnknownKey,
    #[error("encrypted data is bound to a storage context that was not supplied")]
    MissingContext,
    #[error("encrypted data authentication failed for every eligible key")]
    DecryptionFailed,
    #[error("decrypted data is not valid UTF-8")]
    InvalidPlaintext,
}

struct EncryptionKeyring {
    active_key_id: String,
    keys: HashMap<String, Aes256Gcm>,
    legacy_decryption_order: Vec<String>,
}

struct ParsedEnvelope<'a> {
    header: &'a [u8],
    version: u8,
    key_id: &'a str,
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

/// Stable storage identity authenticated by version 2 ciphertext envelopes.
///
/// Record IDs must remain stable for the lifetime of the row. Callers must use
/// the physical table and column names so ciphertext cannot be transplanted to
/// another row or field without authentication failing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncryptionContext<'a> {
    pub table: &'a str,
    pub record_id: &'a str,
    pub field: &'a str,
}

impl<'a> EncryptionContext<'a> {
    pub const fn new(table: &'a str, record_id: &'a str, field: &'a str) -> Self {
        Self {
            table,
            record_id,
            field,
        }
    }

    fn aad(self, header: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(
            header.len() + self.table.len() + self.record_id.len() + self.field.len() + 12,
        );
        aad.extend_from_slice(header);
        for component in [self.table, self.record_id, self.field] {
            let length = u32::try_from(component.len()).unwrap_or(u32::MAX);
            aad.extend_from_slice(&length.to_be_bytes());
            aad.extend_from_slice(component.as_bytes());
        }
        aad
    }
}

#[derive(Clone)]
pub struct EncryptionService {
    keyring: Arc<EncryptionKeyring>,
}

impl EncryptionService {
    pub fn new() -> Result<Self, EncryptionConfigurationError> {
        let key_hex = required_environment_key()?;
        let key_id = optional_environment_value(ENCRYPTION_KEY_ID_ENV)?
            .unwrap_or_else(|| DEFAULT_KEY_ID.to_string());
        let previous_keys = optional_environment_value(ENCRYPTION_PREVIOUS_KEYS_ENV)?;

        Self::from_keyring_values(&key_id, &key_hex, previous_keys.as_deref())
    }

    /// Load the encryption service for normal API startup.
    ///
    /// A missing active key fails closed unless the deliberately verbose
    /// development escape hatch is set to `true`. Any malformed active or
    /// previous key configuration always fails.
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
        let key_id = optional_environment_value(ENCRYPTION_KEY_ID_ENV)?;
        let previous_keys = optional_environment_value(ENCRYPTION_PREVIOUS_KEYS_ENV)?;

        Self::from_startup_values(
            key.as_deref(),
            key_id.as_deref(),
            previous_keys.as_deref(),
            allow_unencrypted_development,
        )
    }

    fn from_startup_values(
        key_hex: Option<&str>,
        key_id: Option<&str>,
        previous_keys: Option<&str>,
        allow_unencrypted_development: bool,
    ) -> Result<Option<Self>, EncryptionConfigurationError> {
        match key_hex {
            Some(key_hex) => {
                Self::from_keyring_values(key_id.unwrap_or(DEFAULT_KEY_ID), key_hex, previous_keys)
                    .map(Some)
            }
            None if allow_unencrypted_development
                && key_id.is_none()
                && previous_keys.is_none() =>
            {
                Ok(None)
            }
            None => Err(EncryptionConfigurationError::MissingKey),
        }
    }

    pub fn from_keyring_values(
        active_key_id: &str,
        active_key_hex: &str,
        previous_keys: Option<&str>,
    ) -> Result<Self, EncryptionConfigurationError> {
        validate_key_id(active_key_id)?;

        let mut keys = HashMap::new();
        keys.insert(
            active_key_id.to_string(),
            cipher_from_hex(active_key_hex, EncryptionConfigurationError::InvalidKey)?,
        );
        let mut legacy_decryption_order = vec![active_key_id.to_string()];

        if let Some(previous_keys) = previous_keys.filter(|value| !value.trim().is_empty()) {
            for entry in previous_keys.split(',') {
                let (key_id, key_hex) = entry
                    .trim()
                    .split_once('=')
                    .ok_or(EncryptionConfigurationError::InvalidPreviousKeys)?;
                let key_id = key_id.trim();
                let key_hex = key_hex.trim();
                validate_key_id(key_id)
                    .map_err(|_| EncryptionConfigurationError::InvalidPreviousKeys)?;
                if keys.contains_key(key_id) {
                    return Err(EncryptionConfigurationError::DuplicateKeyId);
                }

                let cipher =
                    cipher_from_hex(key_hex, EncryptionConfigurationError::InvalidPreviousKeys)?;
                keys.insert(key_id.to_string(), cipher);
                legacy_decryption_order.push(key_id.to_string());
            }
        }

        Ok(Self {
            keyring: Arc::new(EncryptionKeyring {
                active_key_id: active_key_id.to_string(),
                keys,
                legacy_decryption_order,
            }),
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, EncryptionError> {
        self.encrypt_envelope(plaintext, ENVELOPE_VERSION_V1, None)
    }

    /// Encrypt a value and bind it to its database table, row, and field.
    pub fn encrypt_with_context(
        &self,
        plaintext: &str,
        context: EncryptionContext<'_>,
    ) -> Result<Vec<u8>, EncryptionError> {
        self.encrypt_envelope(plaintext, ENVELOPE_VERSION_V2, Some(context))
    }

    fn encrypt_envelope(
        &self,
        plaintext: &str,
        version: u8,
        context: Option<EncryptionContext<'_>>,
    ) -> Result<Vec<u8>, EncryptionError> {
        let key_id = self.key_id().as_bytes();
        let key_id_length =
            u8::try_from(key_id.len()).expect("validated encryption key IDs are at most 64 bytes");
        let mut header = Vec::with_capacity(ENVELOPE_MAGIC.len() + 2 + key_id.len());
        header.extend_from_slice(ENVELOPE_MAGIC);
        header.push(version);
        header.push(key_id_length);
        header.extend_from_slice(key_id);

        let nonce_bytes: [u8; NONCE_LENGTH] = rand::random();
        let nonce = Nonce::from(nonce_bytes);
        let cipher = self
            .keyring
            .keys
            .get(self.key_id())
            .expect("active encryption key must exist in its keyring");
        let context_aad;
        let aad = if let Some(context) = context {
            context_aad = context.aad(&header);
            context_aad.as_slice()
        } else {
            &header
        };
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad,
                },
            )
            .map_err(|_| EncryptionError::EncryptionFailed)?;

        let mut result = header;
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<String, EncryptionError> {
        if encrypted.starts_with(ENVELOPE_MAGIC) {
            let envelope = parse_envelope(encrypted)?;
            if envelope.version == ENVELOPE_VERSION_V2 {
                return Err(EncryptionError::MissingContext);
            }
            self.decrypt_parsed_envelope(envelope, None)
        } else {
            self.decrypt_legacy(encrypted)
        }
    }

    /// Decrypt a context-bound value. Version 1 and legacy values remain
    /// readable so an online upgrade can be followed by `rewrap-secrets`.
    pub fn decrypt_with_context(
        &self,
        encrypted: &[u8],
        context: EncryptionContext<'_>,
    ) -> Result<String, EncryptionError> {
        if encrypted.starts_with(ENVELOPE_MAGIC) {
            self.decrypt_parsed_envelope(parse_envelope(encrypted)?, Some(context))
        } else {
            self.decrypt_legacy(encrypted)
        }
    }

    /// Verify ciphertext and re-encrypt it with the active key when it is
    /// legacy or references a previous key. Already-active ciphertext is
    /// authenticated and returned unchanged.
    #[cfg(any(test, feature = "test-support"))]
    pub fn rewrap(&self, encrypted: &[u8]) -> Result<Vec<u8>, EncryptionError> {
        let plaintext = self.decrypt(encrypted)?;
        if self.ciphertext_key_id(encrypted)? == Some(self.key_id()) {
            return Ok(encrypted.to_vec());
        }

        self.encrypt(&plaintext)
    }

    /// Authenticate a legacy/V1/V2 value in its storage context and return a
    /// V2 envelope under the active key. Already-current V2 values are returned
    /// byte-for-byte after authentication.
    pub fn rewrap_with_context(
        &self,
        encrypted: &[u8],
        context: EncryptionContext<'_>,
    ) -> Result<Vec<u8>, EncryptionError> {
        let plaintext = self.decrypt_with_context(encrypted, context)?;
        let current = if encrypted.starts_with(ENVELOPE_MAGIC) {
            let envelope = parse_envelope(encrypted)?;
            envelope.version == ENVELOPE_VERSION_V2 && envelope.key_id == self.key_id()
        } else {
            false
        };
        if current {
            Ok(encrypted.to_vec())
        } else {
            self.encrypt_with_context(&plaintext, context)
        }
    }

    pub fn needs_rewrap_with_context(
        &self,
        encrypted: &[u8],
        context: EncryptionContext<'_>,
    ) -> Result<bool, EncryptionError> {
        self.decrypt_with_context(encrypted, context)?;
        if !encrypted.starts_with(ENVELOPE_MAGIC) {
            return Ok(true);
        }
        let envelope = parse_envelope(encrypted)?;
        Ok(envelope.version != ENVELOPE_VERSION_V2 || envelope.key_id != self.key_id())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn needs_rewrap(&self, encrypted: &[u8]) -> Result<bool, EncryptionError> {
        Ok(self.ciphertext_key_id(encrypted)? != Some(self.key_id()))
    }

    /// Return the embedded key ID. Legacy `nonce || ciphertext` values return
    /// `None` because their key ID exists only in a separate database column,
    /// when present.
    pub fn ciphertext_key_id<'a>(
        &self,
        encrypted: &'a [u8],
    ) -> Result<Option<&'a str>, EncryptionError> {
        if !encrypted.starts_with(ENVELOPE_MAGIC) {
            return Ok(None);
        }

        let envelope = parse_envelope(encrypted)?;
        Ok(Some(envelope.key_id))
    }

    pub fn key_id(&self) -> &str {
        &self.keyring.active_key_id
    }

    fn decrypt_parsed_envelope(
        &self,
        envelope: ParsedEnvelope<'_>,
        context: Option<EncryptionContext<'_>>,
    ) -> Result<String, EncryptionError> {
        let cipher = self
            .keyring
            .keys
            .get(envelope.key_id)
            .ok_or(EncryptionError::UnknownKey)?;
        let nonce_array: [u8; NONCE_LENGTH] = envelope
            .nonce
            .try_into()
            .map_err(|_| EncryptionError::MalformedCiphertext)?;
        let context_aad;
        let aad = match envelope.version {
            ENVELOPE_VERSION_V1 => envelope.header,
            ENVELOPE_VERSION_V2 => {
                let context = context.ok_or(EncryptionError::MissingContext)?;
                context_aad = context.aad(envelope.header);
                context_aad.as_slice()
            }
            _ => return Err(EncryptionError::UnsupportedEnvelopeVersion),
        };
        let plaintext = cipher
            .decrypt(
                &Nonce::from(nonce_array),
                Payload {
                    msg: envelope.ciphertext,
                    aad,
                },
            )
            .map_err(|_| EncryptionError::DecryptionFailed)?;

        String::from_utf8(plaintext).map_err(|_| EncryptionError::InvalidPlaintext)
    }

    fn decrypt_legacy(&self, encrypted: &[u8]) -> Result<String, EncryptionError> {
        if encrypted.len() < NONCE_LENGTH + TAG_LENGTH {
            return Err(EncryptionError::MalformedCiphertext);
        }
        let (nonce_bytes, ciphertext) = encrypted.split_at(NONCE_LENGTH);
        let nonce_array: [u8; NONCE_LENGTH] = nonce_bytes
            .try_into()
            .map_err(|_| EncryptionError::MalformedCiphertext)?;
        let nonce = Nonce::from(nonce_array);

        for key_id in &self.keyring.legacy_decryption_order {
            let cipher = self
                .keyring
                .keys
                .get(key_id)
                .expect("legacy decryption order must reference configured keys");
            if let Ok(plaintext) = cipher.decrypt(&nonce, ciphertext) {
                return String::from_utf8(plaintext).map_err(|_| EncryptionError::InvalidPlaintext);
            }
        }

        Err(EncryptionError::DecryptionFailed)
    }
}

fn required_environment_key() -> Result<String, EncryptionConfigurationError> {
    match std::env::var("ENCRYPTION_KEY") {
        Ok(key) => Ok(key),
        Err(std::env::VarError::NotPresent) => Err(EncryptionConfigurationError::MissingKey),
        Err(std::env::VarError::NotUnicode(_)) => Err(EncryptionConfigurationError::InvalidKey),
    }
}

fn optional_environment_value(name: &str) -> Result<Option<String>, EncryptionConfigurationError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) if name == ENCRYPTION_KEY_ID_ENV => {
            Err(EncryptionConfigurationError::InvalidKeyId)
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(EncryptionConfigurationError::InvalidPreviousKeys)
        }
    }
}

fn validate_key_id(key_id: &str) -> Result<(), EncryptionConfigurationError> {
    if key_id.is_empty()
        || key_id.len() > MAX_KEY_ID_LENGTH
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(EncryptionConfigurationError::InvalidKeyId);
    }
    Ok(())
}

fn cipher_from_hex(
    key_hex: &str,
    error: EncryptionConfigurationError,
) -> Result<Aes256Gcm, EncryptionConfigurationError> {
    if key_hex.len() != 64 || !key_hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(error);
    }
    let key_bytes = hex::decode(key_hex).map_err(|_| error)?;
    Aes256Gcm::new_from_slice(&key_bytes).map_err(|_| error)
}

fn parse_envelope(encrypted: &[u8]) -> Result<ParsedEnvelope<'_>, EncryptionError> {
    let fixed_header_length = ENVELOPE_MAGIC.len() + 2;
    if encrypted.len() < fixed_header_length + 1 + NONCE_LENGTH + TAG_LENGTH {
        return Err(EncryptionError::MalformedCiphertext);
    }
    let version = encrypted[ENVELOPE_MAGIC.len()];
    if !matches!(version, ENVELOPE_VERSION_V1 | ENVELOPE_VERSION_V2) {
        return Err(EncryptionError::UnsupportedEnvelopeVersion);
    }

    let key_id_length = usize::from(encrypted[ENVELOPE_MAGIC.len() + 1]);
    if key_id_length == 0 || key_id_length > MAX_KEY_ID_LENGTH {
        return Err(EncryptionError::MalformedCiphertext);
    }
    let header_length = fixed_header_length + key_id_length;
    if encrypted.len() < header_length + NONCE_LENGTH + TAG_LENGTH {
        return Err(EncryptionError::MalformedCiphertext);
    }
    let key_id = std::str::from_utf8(&encrypted[fixed_header_length..header_length])
        .map_err(|_| EncryptionError::MalformedCiphertext)?;
    validate_key_id(key_id).map_err(|_| EncryptionError::MalformedCiphertext)?;

    let nonce_end = header_length + NONCE_LENGTH;
    Ok(ParsedEnvelope {
        header: &encrypted[..header_length],
        version,
        key_id,
        nonce: &encrypted[header_length..nonce_end],
        ciphertext: &encrypted[nonce_end..],
    })
}

#[cfg(test)]
mod tests {
    use super::{
        cipher_from_hex, EncryptionConfigurationError, EncryptionContext, EncryptionError,
        EncryptionService, ENVELOPE_MAGIC,
    };
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    };

    const OLD_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const NEW_KEY: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    const THIRD_KEY: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn service(active_id: &str, active_key: &str, previous: Option<&str>) -> EncryptionService {
        EncryptionService::from_keyring_values(active_id, active_key, previous)
            .expect("build encryption test keyring")
    }

    fn legacy_encrypt(key_hex: &str, plaintext: &str) -> Vec<u8> {
        let cipher = Aes256Gcm::new_from_slice(&hex::decode(key_hex).unwrap()).unwrap();
        let nonce_bytes: [u8; 12] = rand::random();
        let ciphertext = cipher
            .encrypt(&Nonce::from(nonce_bytes), plaintext.as_bytes())
            .unwrap();
        let mut encrypted = nonce_bytes.to_vec();
        encrypted.extend_from_slice(&ciphertext);
        encrypted
    }

    #[test]
    fn active_writes_use_an_authenticated_versioned_envelope() {
        let service = service("key-2026-07", NEW_KEY, None);
        let encrypted = service.encrypt("credential-value").unwrap();

        assert!(encrypted.starts_with(ENVELOPE_MAGIC));
        assert_eq!(
            service.ciphertext_key_id(&encrypted).unwrap(),
            Some("key-2026-07")
        );
        assert_eq!(service.decrypt(&encrypted).unwrap(), "credential-value");
        assert!(!encrypted
            .windows("credential-value".len())
            .any(|window| window == b"credential-value"));
    }

    #[test]
    fn context_bound_envelopes_reject_record_and_field_swaps() {
        let service = service("key-2026-07", NEW_KEY, None);
        let context = EncryptionContext::new("users", "user-a", "totp_secret");
        let encrypted = service
            .encrypt_with_context("credential-value", context)
            .unwrap();

        assert_eq!(
            service.decrypt_with_context(&encrypted, context).unwrap(),
            "credential-value"
        );
        assert_eq!(
            service.decrypt(&encrypted),
            Err(EncryptionError::MissingContext)
        );
        for wrong in [
            EncryptionContext::new("users", "user-b", "totp_secret"),
            EncryptionContext::new("users", "user-a", "recovery_secret"),
            EncryptionContext::new("admins", "user-a", "totp_secret"),
        ] {
            assert_eq!(
                service.decrypt_with_context(&encrypted, wrong),
                Err(EncryptionError::DecryptionFailed)
            );
        }
    }

    #[test]
    fn contextual_rewrap_upgrades_v1_and_is_idempotent() {
        let old = service("key-old", OLD_KEY, None);
        let v1 = old.encrypt("rotating-secret").unwrap();
        let rotated = service("key-new", NEW_KEY, Some(&format!("key-old={OLD_KEY}")));
        let context = EncryptionContext::new("credentials", "credential-a", "secret");

        assert!(rotated.needs_rewrap_with_context(&v1, context).unwrap());
        let v2 = rotated.rewrap_with_context(&v1, context).unwrap();
        assert!(!rotated.needs_rewrap_with_context(&v2, context).unwrap());
        assert_eq!(
            rotated.decrypt_with_context(&v2, context).unwrap(),
            "rotating-secret"
        );
        assert_eq!(rotated.rewrap_with_context(&v2, context).unwrap(), v2);
    }

    #[test]
    fn rotation_reads_previous_envelopes_and_rewraps_with_the_active_key() {
        let old_service = service("key-old", OLD_KEY, None);
        let old_ciphertext = old_service.encrypt("rotating-secret").unwrap();
        let rotated = service("key-new", NEW_KEY, Some(&format!("key-old={OLD_KEY}")));

        assert_eq!(rotated.decrypt(&old_ciphertext).unwrap(), "rotating-secret");
        assert!(rotated.needs_rewrap(&old_ciphertext).unwrap());
        let rewrapped = rotated.rewrap(&old_ciphertext).unwrap();
        assert_eq!(
            rotated.ciphertext_key_id(&rewrapped).unwrap(),
            Some("key-new")
        );
        assert_eq!(rotated.decrypt(&rewrapped).unwrap(), "rotating-secret");
        assert_eq!(
            old_service.decrypt(&rewrapped),
            Err(EncryptionError::UnknownKey)
        );
    }

    #[test]
    fn rotation_reads_and_rewraps_legacy_nonce_prefixed_ciphertext() {
        let legacy = legacy_encrypt(OLD_KEY, "legacy-secret");
        let rotated = service("key-new", NEW_KEY, Some(&format!("key-old={OLD_KEY}")));

        assert_eq!(rotated.ciphertext_key_id(&legacy).unwrap(), None);
        assert_eq!(rotated.decrypt(&legacy).unwrap(), "legacy-secret");
        let rewrapped = rotated.rewrap(&legacy).unwrap();
        assert_eq!(
            rotated.ciphertext_key_id(&rewrapped).unwrap(),
            Some("key-new")
        );
        assert_eq!(rotated.decrypt(&rewrapped).unwrap(), "legacy-secret");
    }

    #[test]
    fn active_ciphertext_rewrap_is_verified_and_idempotent() {
        let service = service("key-new", NEW_KEY, None);
        let encrypted = service.encrypt("already-current").unwrap();

        assert!(!service.needs_rewrap(&encrypted).unwrap());
        assert_eq!(service.rewrap(&encrypted).unwrap(), encrypted);
    }

    #[test]
    fn missing_previous_keys_fail_clearly() {
        let old_envelope = service("key-old", OLD_KEY, None)
            .encrypt("old-secret")
            .unwrap();
        let old_legacy = legacy_encrypt(OLD_KEY, "old-secret");
        let new_service = service("key-new", NEW_KEY, None);

        assert_eq!(
            new_service.decrypt(&old_envelope),
            Err(EncryptionError::UnknownKey)
        );
        assert_eq!(
            new_service.decrypt(&old_legacy),
            Err(EncryptionError::DecryptionFailed)
        );
    }

    #[test]
    fn previous_key_can_be_retired_only_after_contextual_rewrap() {
        let context = EncryptionContext::new("webhooks", "hook-a", "secret_encrypted");
        let old = service("key-old", OLD_KEY, None);
        let old_value = old.encrypt_with_context("webhook-secret", context).unwrap();
        let rotating = service("key-new", NEW_KEY, Some(&format!("key-old={OLD_KEY}")));
        let rewrapped = rotating.rewrap_with_context(&old_value, context).unwrap();
        let retired = service("key-new", NEW_KEY, None);

        assert_eq!(
            retired.decrypt_with_context(&old_value, context),
            Err(EncryptionError::UnknownKey)
        );
        assert_eq!(
            retired.decrypt_with_context(&rewrapped, context).unwrap(),
            "webhook-secret"
        );
    }

    #[test]
    fn envelope_header_is_authenticated() {
        let keyring = service("key-new", NEW_KEY, Some(&format!("key-old={OLD_KEY}")));
        let mut encrypted = service("key-old", OLD_KEY, None)
            .encrypt("header-bound")
            .unwrap();
        let key_id_start = ENVELOPE_MAGIC.len() + 2;
        encrypted[key_id_start..key_id_start + "key-old".len()].copy_from_slice(b"key-new");

        assert_eq!(
            keyring.decrypt(&encrypted),
            Err(EncryptionError::DecryptionFailed)
        );
    }

    #[test]
    fn malformed_and_unsupported_envelopes_fail_without_legacy_fallback() {
        let service = service("key-new", NEW_KEY, None);
        let mut unsupported = service.encrypt("value").unwrap();
        unsupported[ENVELOPE_MAGIC.len()] = 3;

        assert_eq!(
            service.decrypt(ENVELOPE_MAGIC),
            Err(EncryptionError::MalformedCiphertext)
        );
        assert_eq!(
            service.decrypt(&unsupported),
            Err(EncryptionError::UnsupportedEnvelopeVersion)
        );
    }

    #[test]
    fn configuration_rejects_invalid_or_duplicate_key_ids_and_keys() {
        assert_eq!(
            EncryptionService::from_keyring_values("bad key id", OLD_KEY, None)
                .err()
                .unwrap(),
            EncryptionConfigurationError::InvalidKeyId
        );
        assert_eq!(
            EncryptionService::from_keyring_values(
                "key-old",
                OLD_KEY,
                Some(&format!("key-old={NEW_KEY}")),
            )
            .err()
            .unwrap(),
            EncryptionConfigurationError::DuplicateKeyId
        );
        assert_eq!(
            EncryptionService::from_keyring_values("key-new", NEW_KEY, Some("broken"))
                .err()
                .unwrap(),
            EncryptionConfigurationError::InvalidPreviousKeys
        );
        assert_eq!(
            EncryptionService::from_keyring_values("key-new", NEW_KEY, Some("key-old=not-a-key"),)
                .err()
                .unwrap(),
            EncryptionConfigurationError::InvalidPreviousKeys
        );
    }

    #[test]
    fn accepts_exactly_32_bytes_of_hexadecimal_active_key_material() {
        let service = EncryptionService::from_startup_values(Some(OLD_KEY), None, None, false)
            .expect("valid key should initialize")
            .expect("valid key should enable encryption");

        assert_eq!(service.key_id(), "default");
    }

    #[test]
    fn rejects_invalid_active_keys_without_echoing_key_material() {
        for invalid_key in [
            &OLD_KEY[..63],
            "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        ] {
            let error =
                EncryptionService::from_startup_values(Some(invalid_key), None, None, false)
                    .err()
                    .expect("invalid key should fail");

            assert_eq!(error, EncryptionConfigurationError::InvalidKey);
            assert!(!error.to_string().contains(&invalid_key[..16]));
        }
    }

    #[test]
    fn missing_key_fails_closed_by_default() {
        let error = EncryptionService::from_startup_values(None, None, None, false)
            .err()
            .expect("missing key should fail");

        assert_eq!(error, EncryptionConfigurationError::MissingKey);
    }

    #[test]
    fn development_escape_hatch_only_allows_a_missing_key() {
        assert!(
            EncryptionService::from_startup_values(None, None, None, true)
                .expect("escape hatch should permit a missing key")
                .is_none()
        );

        let error = EncryptionService::from_startup_values(
            Some("invalid"),
            Some("key-new"),
            Some(&format!("key-old={THIRD_KEY}")),
            true,
        )
        .err()
        .expect("escape hatch must not permit an invalid configured key");
        assert_eq!(error, EncryptionConfigurationError::InvalidKey);
    }

    #[test]
    fn development_escape_hatch_rejects_orphaned_keyring_metadata() {
        for (key_id, previous_keys) in [
            (Some("key-new"), None),
            (
                None,
                Some("key-old=2222222222222222222222222222222222222222222222222222222222222222"),
            ),
            (
                Some("key-new"),
                Some("key-old=2222222222222222222222222222222222222222222222222222222222222222"),
            ),
            (None, Some("malformed")),
        ] {
            let error = EncryptionService::from_startup_values(None, key_id, previous_keys, true)
                .err()
                .expect("the development escape hatch must not ignore keyring metadata");
            assert_eq!(error, EncryptionConfigurationError::MissingKey);
        }
    }

    #[test]
    fn cipher_builder_error_does_not_include_key_material() {
        let invalid = "aaaaaaaaaaaaaaaa";
        let error = cipher_from_hex(invalid, EncryptionConfigurationError::InvalidKey)
            .err()
            .unwrap();
        assert_eq!(error, EncryptionConfigurationError::InvalidKey);
        assert!(!error.to_string().contains(invalid));
    }
}
