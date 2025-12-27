use rand::Rng;
use sha2::{Digest, Sha256};

const API_KEY_PREFIX: &str = "sk_";
const API_KEY_BYTES: usize = 32;

pub struct ApiKeyService;

impl ApiKeyService {
    /// Generate a new API key with a prefix and random component
    /// Returns (full_key, prefix, key_hash)
    /// Format: sk_{prefix}_{random_component}
    /// Example: sk_abc123_def456789...
    pub fn generate() -> (String, String, String) {
        let mut rng = rand::thread_rng();

        let prefix_bytes: [u8; 6] = rng.gen();
        let prefix_component = hex::encode(prefix_bytes);

        let key_bytes: [u8; API_KEY_BYTES] = rng.gen();
        let key_component = hex::encode(key_bytes);

        let full_key = format!("{}{}_{}", API_KEY_PREFIX, prefix_component, key_component);

        let prefix_for_db = format!("{}{}", API_KEY_PREFIX, prefix_component);

        let key_hash = Self::hash_key(&full_key);

        (full_key, prefix_for_db, key_hash)
    }

    /// Hash an API key using SHA256
    pub fn hash_key(key: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Extract the prefix from a full API key
    /// Example: sk_abc123_def456... -> sk_abc123
    pub fn extract_prefix(key: &str) -> Option<String> {
        if !key.starts_with(API_KEY_PREFIX) {
            return None;
        }

        let parts: Vec<&str> = key.splitn(3, '_').collect();
        if parts.len() < 2 {
            return None;
        }

        Some(format!("{}_{}", parts[0], parts[1]))
    }

    /// Verify an API key against its hash using constant-time comparison
    pub fn verify_key(provided_key: &str, stored_hash: &str) -> bool {
        let computed_hash = Self::hash_key(provided_key);

        if computed_hash.len() != stored_hash.len() {
            return false;
        }

        let mut result = 0u8;
        for (a, b) in computed_hash.bytes().zip(stored_hash.bytes()) {
            result |= a ^ b;
        }

        result == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_key() {
        let (full_key, prefix, hash) = ApiKeyService::generate();

        assert!(full_key.starts_with("sk_"));
        assert!(prefix.starts_with("sk_"));
        assert_eq!(hash.len(), 64); // SHA256 produces 64 hex chars

        let parts: Vec<&str> = full_key.split('_').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_extract_prefix() {
        let (full_key, expected_prefix, _) = ApiKeyService::generate();
        let extracted = ApiKeyService::extract_prefix(&full_key);

        assert_eq!(extracted, Some(expected_prefix));

        assert_eq!(ApiKeyService::extract_prefix("invalid"), None);
        assert_eq!(ApiKeyService::extract_prefix("sk_"), None);
    }

    #[test]
    fn test_hash_key() {
        let key = "sk_abc123_def456";
        let hash1 = ApiKeyService::hash_key(key);
        let hash2 = ApiKeyService::hash_key(key);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_verify_key() {
        let (full_key, _, hash) = ApiKeyService::generate();

        assert!(ApiKeyService::verify_key(&full_key, &hash));

        assert!(!ApiKeyService::verify_key("sk_wrong_key", &hash));

        assert!(!ApiKeyService::verify_key(&full_key, "wrong_hash"));
    }

    #[test]
    fn test_constant_time_verification() {
        let (key1, _, hash1) = ApiKeyService::generate();
        let (key2, _, _) = ApiKeyService::generate();

        assert!(ApiKeyService::verify_key(&key1, &hash1));
        assert!(!ApiKeyService::verify_key(&key2, &hash1));
    }
}
