//! Host matching, re-exported from `marshal-core`.
//!
//! Lives in `marshal-core` rather than here because `marshal-judge` needs it for scope
//! matching too, and `marshal-policy` already depends on `marshal-judge` to build the chain —
//! keeping the implementation in this crate would make that a dependency cycle. Re-exported
//! under the old path so nothing outside this crate had to change.

pub use marshal_core::{HostMatcher, MatchKind, PatternError};
