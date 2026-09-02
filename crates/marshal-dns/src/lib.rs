//! DNS interception: resolve everything to the proxy.
//!
//! The third way to capture traffic, and the one that needs least from the client. Point a
//! container's resolver at the proxy and every hostname resolves to the proxy's address, so
//! connections arrive without the client being configured — or even aware.
//!
//! It is the weakest of the three, and worth being clear about why: a client that ships its
//! own resolver, uses DNS-over-HTTPS, or simply connects to a literal address never consults
//! us at all. DNS mode is a convenience for workloads that cannot be configured, not a
//! containment boundary. Where bypass actually matters, use netns isolation or firewall the
//! egress path.

pub mod policy;
pub mod server;

pub use policy::{Answer, DnsPolicy};
pub use server::{DnsServer, DnsServerError, serve};
