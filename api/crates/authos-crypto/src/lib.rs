//! Layer crate `authos-crypto`.

pub mod crypto;
pub mod encryption;

// Re-export lower layers under their original module names so that
// intra-crate `crate::<module>` paths keep resolving after the split.
pub use authos_core::{client_ip, config, constants, error, rsa_keys, runtime_metadata, utils};
