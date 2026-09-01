//! CA management and on-the-fly leaf certificate minting.
//!
//! Intercepting TLS means the agent must trust a CA the proxy controls, and that CA's key can
//! impersonate every site the agent talks to. Handling of that key is the security-relevant
//! part of this crate; the certificate minting itself is routine.

pub mod ca;
pub mod leaf;
pub mod resolver;
pub mod trust;

pub use ca::{CaError, CertificateAuthority, GeneratedCa};
pub use leaf::LeafMinter;
pub use resolver::MintingResolver;
