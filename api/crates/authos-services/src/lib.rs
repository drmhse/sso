//! Layer crate `authos-services`.

pub mod billing;
pub mod email;
pub mod jobs;
pub mod services;

// Re-export lower layers under their original module names so that
// intra-crate `crate::<module>` paths keep resolving after the split.
pub use authos_audit::audit;
pub use authos_core::{client_ip, config, constants, error, rsa_keys, runtime_metadata, utils};
pub use authos_crypto::{crypto, encryption};
pub use authos_db::db;
pub use authos_entities::entities;
pub use authos_store::store;

// Test-only aliases: `#[cfg(test)]` modules reach up for fixtures and
// cross-layer setup. Dev-dependency cycles are permitted by cargo.
#[cfg(test)]
pub use authos_testkit as test_support;
