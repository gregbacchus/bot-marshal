//! Proxy listeners, the upstream guard, and (from M2) MITM.
//!
//! M1 is tunnel-only: one listener sniffs SOCKS5 versus HTTP, the policy chain decides on the
//! requested authority, and an allowed connection is relayed byte-for-byte.

pub mod guard;
pub mod httpfront;
pub mod mitm;
pub mod rewind;
pub mod server;
pub mod sessions;
pub mod sniff;
pub mod socks5;
pub mod stats;
pub mod tunnel;

pub use guard::{GuardError, UpstreamGuard};
pub use server::{Server, ServerConfig};
pub use sniff::{Protocol, detect, sni_from_client_hello};
