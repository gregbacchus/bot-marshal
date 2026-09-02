//! Layered YAML configuration for bot-marshal.
//!
//! A config is a mandatory embedded `profile:` (the unnamed fallback for unattributed
//! traffic) plus, by convention, one *named* profile per file under a sibling `profiles/`
//! directory, one bundle per file under `bundles/`, and one transform bundle per file under
//! `transforms/` — see [`load`].

pub mod layer;
pub mod load;
pub mod model;
pub mod validate;

pub use load::{LoadError, load};
pub use model::{BodyTransform, Config, Profile, RequestTransforms, ResponseTransforms};
pub use validate::{Diagnostic, Severity, validate};
