//! LLM judge policy layer with caching and circuit breaking.
//!
//! # What the judge is allowed to see
//!
//! Method, host, path, and header *names* — never header values, never the request body.
//! Both are excluded deliberately: this layer's whole job is sending a description of the
//! request to a third-party API, and anything included there is a potential leak. A header
//! value is exactly where a credential lives; the body is exactly where proprietary content
//! or a secret an earlier layer hasn't caught yet would be. See [`request::JudgeRequest`].
//!
//! # Hardening against the request being adversarial
//!
//! See [`providers`] for the specific mechanisms: the untrusted content travels as explicitly
//! delimited data rather than being concatenated into the system prompt, and the verdict
//! comes back through a forced tool call rather than free-text parsing.

pub mod breaker;
pub mod judge;
pub mod providers;
pub mod request;
pub mod scope;

pub use breaker::CircuitBreaker;
pub use judge::Judge;
pub use providers::{
    AnthropicProvider, Decision, JudgeVerdict, OpenAiProvider, Provider, ProviderError,
};
pub use request::JudgeRequest;
pub use scope::CompiledScope;
