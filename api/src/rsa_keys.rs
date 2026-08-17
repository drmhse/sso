//! RSA key generation and encoding, in pure Rust.
//!
//! These operations used to go through OpenSSL. Nothing about them needs a C
//! library, and the vendored OpenSSL they pulled in bakes its own build
//! directory into `libcrypto.a` and `libssl.a`, so those archives cannot be
//! relocated and a fresh checkout pays a full C rebuild before any Rust
//! compiles.
//!
//! The encodings here match what OpenSSL produced, because the PEM these
//! functions emit is stored in the database and read back by existing
//! deployments:
//!
//! * `private_key_pem` is PKCS#1, the `RSA PRIVATE KEY` label OpenSSL's
//!   `Rsa::private_key_to_pem` writes.
//! * `private_key_pkcs8_pem` is PKCS#8, matching `private_key_to_pem_pkcs8`.
//! * `public_key_pem` is SubjectPublicKeyInfo, matching `public_key_to_pem`.

use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::{RsaPrivateKey, RsaPublicKey};

/// Bits for every RSA key this service generates.
pub const RSA_BITS: usize = 2048;

/// A freshly generated RSA key pair.
pub struct GeneratedKey {
    private: RsaPrivateKey,
}

impl GeneratedKey {
    /// Generates a key, using the thread's random source.
    ///
    /// Key generation searches for primes, so the cost varies run to run and is
    /// measured in tens of milliseconds rather than being constant.
    pub fn generate() -> Result<Self, rsa::Error> {
        let mut rng = rand::thread_rng();
        Ok(Self {
            private: RsaPrivateKey::new(&mut rng, RSA_BITS)?,
        })
    }

    /// PKCS#1 PEM, labelled `RSA PRIVATE KEY`.
    ///
    /// Only the test fixtures need this form; the service itself stores PKCS#8.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn private_key_pem(&self) -> Result<String, rsa::pkcs1::Error> {
        self.private.to_pkcs1_pem(LineEnding::LF).map(|pem| pem.to_string())
    }

    /// PKCS#8 PEM, labelled `PRIVATE KEY`.
    pub fn private_key_pkcs8_pem(&self) -> Result<String, rsa::pkcs8::Error> {
        self.private.to_pkcs8_pem(LineEnding::LF).map(|pem| pem.to_string())
    }

    /// SubjectPublicKeyInfo PEM, labelled `PUBLIC KEY`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn public_key_pem(&self) -> Result<String, rsa::pkcs8::spki::Error> {
        RsaPublicKey::from(&self.private).to_public_key_pem(LineEnding::LF)
    }
}

/// The modulus and exponent of a public key, big-endian, for a JWK.
///
/// A JWK carries `n` and `e` as base64url of their big-endian bytes, which is
/// what OpenSSL's `BigNum::to_vec` produced here before.
/// Takes the PEM as bytes, because that is how the key store hands it back.
pub fn public_key_components(
    public_key_pem: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), rsa::pkcs8::spki::Error> {
    use rsa::pkcs8::DecodePublicKey;
    use rsa::traits::PublicKeyParts;

    let pem = std::str::from_utf8(public_key_pem)
        .map_err(|_| rsa::pkcs8::spki::Error::KeyMalformed)?;
    let key = RsaPublicKey::from_public_key_pem(pem)?;
    Ok((key.n().to_bytes_be(), key.e().to_bytes_be()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_key_is_pkcs1_and_public_key_is_spki() {
        let key = GeneratedKey::generate().expect("generate");
        assert!(key.private_key_pem().unwrap().starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(key.private_key_pkcs8_pem().unwrap().starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(key.public_key_pem().unwrap().starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    #[test]
    fn jwk_components_have_the_expected_sizes() {
        let key = GeneratedKey::generate().expect("generate");
        let (n, e) =
            public_key_components(key.public_key_pem().unwrap().as_bytes()).expect("components");
        // A 2048 bit modulus is 256 bytes with no leading zero, and the common
        // public exponent 65537 is three.
        assert_eq!(n.len(), RSA_BITS / 8);
        assert_eq!(e, vec![0x01, 0x00, 0x01]);
    }
}
