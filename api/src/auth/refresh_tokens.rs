use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};

const REFRESH_TOKEN_BYTES: usize = 32;

/// Generate a 256-bit opaque refresh token suitable for one-time display.
pub fn generate() -> String {
    let mut bytes = [0u8; REFRESH_TOKEN_BYTES];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Produce the irreversible database lookup value for a refresh token.
pub fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_tokens_have_256_bits_and_are_url_safe() {
        let first = generate();
        let second = generate();

        assert_eq!(URL_SAFE_NO_PAD.decode(&first).unwrap().len(), 32);
        assert_ne!(first, second);
        assert!(!first.contains('='));
    }

    #[test]
    fn hashes_are_deterministic_without_retaining_the_token() {
        let token = generate();
        let digest = hash(&token);

        assert_eq!(digest.len(), 64);
        assert_eq!(digest, hash(&token));
        assert_ne!(digest, token);
    }
}
