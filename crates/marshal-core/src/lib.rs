//! Core types and traits for bot-marshal.
//!
//! This crate deliberately has **no I/O and no dependency on any other `marshal-*` crate**.
//! Everything downstream depends on it, which keeps the trait boundaries honest and makes the
//! policy chain unit-testable without a network.

pub mod audit;
pub mod error;
pub mod evidence;
pub mod hosts;
pub mod identity;
pub mod policy;
pub mod redact;
pub mod request;
pub mod secret;
pub mod verdict;

pub use audit::{Action, AuditRecord, AuditSink};
pub use error::{Error, Result};
pub use evidence::{Evidence, Fact, Flag, LayerOutcome};
pub use hosts::{HostMatcher, MatchKind, PatternError};
pub use identity::{ConnInfo, Credential, Identity, IdentityResolver, PeerCred, Resolved};
pub use policy::{
    BodyRequirement, CostClass, FailureMode, PolicyLayer, RequestTransform, ResponseTransform,
};
pub use redact::Redactor;
pub use request::{Authority, BodyHandle, IngressMode, Phase, RequestContext, ResponseParts};
pub use secret::{SecretSource, SecretValue};
pub use verdict::{ApprovalRequest, Decider, Decision, DenyingDecider, Reason, Verdict};
