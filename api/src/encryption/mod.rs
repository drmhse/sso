use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

pub struct EncryptionService {
    cipher: Aes256Gcm,
    key_id: String,
}

impl EncryptionService {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let key_hex = std::env::var("ENCRYPTION_KEY")?;
        let key_bytes = hex::decode(key_hex)?;

        if key_bytes.len() != 32 {
            return Err("Encryption key must be 32 bytes (64 hex chars)".into());
        }

        let cipher = Aes256Gcm::new_from_slice(&key_bytes)?;

        Ok(Self {
            cipher,
            key_id: "default".to_string(),
        })
    }

    pub fn encrypt(&self, plaintext: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let nonce_bytes: [u8; 12] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext.as_bytes())
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
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Decryption failed: {}", e))?;

        Ok(String::from_utf8(plaintext)?)
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

impl Clone for EncryptionService {
    fn clone(&self) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(
                &std::env::var("ENCRYPTION_KEY")
                    .ok()
                    .and_then(|hex| hex::decode(hex).ok())
                    .unwrap_or_default(),
            )
            .unwrap(),
            key_id: self.key_id.clone(),
        }
    }
}
