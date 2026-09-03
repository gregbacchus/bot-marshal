//! Outbound HTTP that marshal makes on its own behalf, and the guard that constrains it.
//!
//! Two things live here because they belong together: the SSRF/DNS-rebinding guard
//! (ADR-0010), and the small one-shot client that is the only thing in the workspace which
//! opens an outbound connection that is *not* a proxied request. Keeping them in one crate
//! means the guard is reachable from every call that ought to be behind it, rather than
//! living in the proxy where only proxied traffic can see it.
//!
//! This is not the path proxied traffic takes. An agent's request is relayed by
//! `marshal-proxy`; this is for marshal calling an LLM judge or an OAuth2 token endpoint as
//! itself.

pub mod client;
pub mod endpoint;
pub mod error;
pub mod guard;
pub mod tls;

pub use client::{ClientBody, MAX_RESPONSE_BYTES, json_post_request, post_form, post_json, send};
pub use endpoint::{AsyncConn, Endpoint};
pub use error::HttpError;
pub use guard::{GuardError, UpstreamGuard};
pub use tls::{default_tls_config, with_extra_roots};
