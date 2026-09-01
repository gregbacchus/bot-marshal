//! Core types and traits for bot-marshal.
//!
//! This crate deliberately has **no I/O and no dependency on any other `marshal-*` crate**.
//! Everything downstream depends on it, which keeps the trait boundaries honest and makes the
//! policy chain unit-testable without a network.

pub mod audit;
pub mod error;
pub mod evidence;
pub mod policy;
pub mod request;
pub mod secret;
pub mod session;
pub mod verdict;

pub use audit::{Action, AuditRecord, AuditSink};
pub use error::{Error, Result};
pub use evidence::{Evidence, Fact, Flag, LayerOutcome};
pub use policy::{CostClass, FailureMode, PolicyLayer, Transform};
pub use request::{Authority, BodyHandle, IngressMode, RequestContext, ResponseParts};
pub use secret::{SecretSource, SecretValue};
pub use session::{ConnInfo, Credential, PeerCred, Resolved, SessionId, SessionResolver};
pub use verdict::{ApprovalRequest, Decider, Decision, DenyingDecider, Reason, Verdict};
