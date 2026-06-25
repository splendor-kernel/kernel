//! # Splendor Authority
//!
//! Authority-plane decision logic. This initial slice implements only the
//! Principal Registry lifecycle state machine from IDR-001. It does not grant
//! permissions, issue capabilities, replace daemon authentication, or authorize
//! gateway side effects.

mod identity;

pub use identity::{IdentityMutation, IdentityRegistry, IdentityRegistryError, RegisterPrincipal};
