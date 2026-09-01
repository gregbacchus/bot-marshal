//! Layered YAML configuration for bot-marshal.
//!
//! A config is a base file plus `include` globs, so curated allowlist bundles can be shipped
//! and imported per profile. Profiles compose via `extends`, merged base-first.

pub mod layer;
pub mod load;
pub mod model;
pub mod validate;

pub use load::{LoadError, load};
pub use model::{Config, Profile};
pub use validate::{Diagnostic, Severity, validate};
