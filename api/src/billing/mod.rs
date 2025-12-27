//! Provider-agnostic billing module.
//!
//! This module provides a unified interface for billing operations that works
//! with multiple billing providers (Stripe, Polar, etc.) through the
//! `BillingProvider` trait.

pub mod models;
pub mod providers;
pub mod traits;

pub use models::*;
pub use providers::{PolarProvider, StripeProvider};
pub use traits::BillingProvider;
