//! Identity: deciding which agent a connection belongs to, and therefore which profile
//! applies.
//!
//! Resolvers are tried in order and the first match wins. They are deliberately not
//! interchangeable in strength, and the config documents which is which:
//!
//! * `peer_cred` uid — kernel-supplied, cannot be asserted by the client. Strongest, but only
//!   separates agents that actually run as different users.
//! * `source_ip` — as trustworthy as the network. Holds when each agent owns a namespace and
//!   cannot forge a source address; collapses when two agents share one.
//! * `run` — a cgroup naming convention created by `marshal run`. Strong against a
//!   prompt-injected agent, not against one deliberately impersonating another profile, since
//!   a process can move itself between delegated cgroups.
//! * `proxy_auth` — client-asserted. Only as strong as the secret, and an agent that can read
//!   another token can choose another profile.

pub mod peercred;
pub mod resolvers;
pub mod run;

pub use resolvers::{
    IdentityRegistry, ListenerPortResolver, PeerCredResolver, ProxyAuthResolver, SourceIpResolver,
};
pub use run::RunResolver;
