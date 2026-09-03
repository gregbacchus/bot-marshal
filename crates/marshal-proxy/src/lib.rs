//! Proxy listeners, the upstream guard, and (from M2) MITM.
//!
//! M1 is tunnel-only: one listener sniffs SOCKS5 versus HTTP, the policy chain decides on the
//! requested authority, and an allowed connection is relayed byte-for-byte.

pub mod httpfront;
pub mod identity;
pub mod management;
pub mod mitm;
pub mod rewind;
pub mod runtime;
pub mod server;
pub mod sniff;
pub mod socks5;
pub mod stats;
pub mod tunnel;

// The guard moved to `marshal-http`, where the outbound client that must obey it also
// lives. Re-exported so `marshal_proxy::UpstreamGuard` keeps meaning what it always did.
pub use marshal_http::{GuardError, UpstreamGuard};
pub use server::{Server, ServerConfig};
pub use sniff::{Protocol, detect, sni_from_client_hello};
