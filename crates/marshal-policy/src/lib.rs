//! Policy chain runner and layers.
//!
//! The chain is an ordered list of layers, each returning ALLOW, DENY or PASS. The first
//! terminal verdict wins, so **ordering is semantically significant**: a denylist placed
//! first beats a later approval without needing a special-case rule. If every layer passes,
//! the profile's `default_action` decides.

pub mod build;
pub mod chain;
pub mod hosts;
pub mod layers;

pub use build::{BuildError, build_chain, resolve_profile};
pub use chain::{Chain, Outcome};
pub use hosts::{HostMatcher, MatchKind, PatternError};
