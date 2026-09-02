//! Layered YAML configuration for bot-marshal.
//!
//! A config is a base file plus, by convention, one profile per file under a sibling
//! `profiles/` directory and one bundle per file under a sibling `bundles/` directory — see
//! [`load`]. Profiles compose via `extends`, merged base-first.

pub mod layer;
pub mod load;
pub mod model;
pub mod validate;

pub use load::{LoadError, load};
pub use model::{BodyTransform, Config, Profile, RequestTransforms, ResponseTransforms};
pub use validate::{Diagnostic, Severity, validate};
