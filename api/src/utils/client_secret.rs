use base64::{engine::general_purpose, Engine as _};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub fn hash_client_secret(client_secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(client_secret.as_bytes());
    general_purpose::STANDARD.encode(hasher.finalize())
}

pub fn verify_client_secret(client_secret: &str, expected_hash: &str) -> bool {
    let provided_hash = hash_client_secret(client_secret);
    provided_hash
        .as_bytes()
        .ct_eq(expected_hash.as_bytes())
        .into()
}
