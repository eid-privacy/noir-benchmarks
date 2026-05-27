//! Credential-shaped types and builders (compact JWT) decoupled from CLI I/O.
//!
//! Keeps serde models in the library crate so they can be unit-tested or reused.

pub mod jwt;
pub mod swiyu;
