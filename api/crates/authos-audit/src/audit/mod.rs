//! Audit persistence. Sits below the store layer because store writes enqueue
//! audit records, and the actor writes them through entities directly.

pub mod actor;
