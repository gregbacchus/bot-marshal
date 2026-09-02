//! The configuration document.

use std::collections::BTreeMap;

use marshal_core::Decision;
use serde::{Deserialize, Serialize};

use crate::layer::LayerConfig;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Globs, relative to this file, merged before the rest of the document is interpreted.
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub listeners: Listeners,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub upstream: Upstream,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
    #[serde(default)]
    pub sessions: Sessions,
    /// Named host sets importable by profiles via `allow.bundles`.
    #[serde(default)]
    pub bundles: BTreeMap<String, crate::layer::HostSet>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listeners {
    #[serde(default)]
    pub explicit: Option<ExplicitListener>,
    #[serde(default)]
    pub transparent: Option<TransparentListener>,
    #[serde(default)]
    pub dns: Option<DnsListener>,
    #[serde(default)]
    pub management: Option<ManagementListener>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplicitListener {
    /// HTTP CONNECT and SOCKS5 share one port; the protocol is sniffed.
    pub listen: String,
    /// Optional Unix-domain listener. Unlocks `SO_PEERCRED`, which is the only unspoofable,
    /// race-free identity available on a single host.
    #[serde(default)]
    pub unix_socket: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparentListener {
    #[serde(default)]
    pub enabled: bool,
    /// Addresses to accept redirected connections on. More than one so nftables can steer
    /// different identities to different ports.
    #[serde(default)]
    pub listen: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsListener {
    #[serde(default)]
    pub enabled: bool,
    pub listen: String,
    /// What intercepted names resolve to: the address the proxy is reachable at from the
    /// client's perspective.
    pub proxy_ip: String,
    /// Names answered by the real resolver instead of being intercepted.
    #[serde(default)]
    pub passthrough: Vec<String>,
    /// Fixed answers. Highest precedence, because they are the operator saying explicitly
    /// what a name means.
    #[serde(default)]
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsRecord {
    pub name: String,
    #[serde(default, rename = "value", alias = "values")]
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementListener {
    pub listen: String,
    pub api_key_env: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(default)]
    pub ca_cert: Option<String>,
    #[serde(default)]
    pub ca_key: Option<String>,
    #[serde(default = "default_cert_cache")]
    pub cert_cache_size: u64,
    #[serde(default = "default_leaf_expiry")]
    pub leaf_expiry_hours: u32,
    /// Hosts never intercepted — certificate-pinned clients.
    #[serde(default)]
    pub passthrough: Vec<String>,
    /// Extra CA certificates (PEM paths) trusted when verifying upstreams, for services
    /// behind an internal CA. Additive: the public roots remain trusted.
    #[serde(default)]
    pub upstream_ca_certs: Vec<String>,
}

fn default_cert_cache() -> u64 {
    1000
}
fn default_leaf_expiry() -> u32 {
    72
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    /// Checked against **every resolved IP**, after DNS resolution and before connecting.
    /// This is the SSRF and DNS-rebinding guard.
    #[serde(default = "default_deny_cidrs")]
    pub deny_cidrs: Vec<String>,
    #[serde(default)]
    pub allow_private: bool,
    /// `0` means uncapped.
    #[serde(default)]
    pub max_response_bytes: u64,
}

impl Default for Upstream {
    fn default() -> Self {
        Self { deny_cidrs: default_deny_cidrs(), allow_private: false, max_response_bytes: 0 }
    }
}

fn default_deny_cidrs() -> Vec<String> {
    [
        "169.254.0.0/16", // link-local, incl. cloud metadata endpoints
        "127.0.0.0/8",
        "::1/128",
        "fe80::/10",
        "fd00::/8",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Merged base-first from the named parent profile.
    #[serde(default)]
    pub extends: Option<String>,
    /// Applied when **every** layer returned `Pass`. Defaults to `Deny`; this is where the
    /// product's default-deny guarantee lives.
    #[serde(default)]
    pub default_action: Decision,
    /// Required acknowledgement when `default_action` is `allow`.
    #[serde(default)]
    pub i_understand_this_is_allow_by_default: bool,
    /// Whether refusals are acted on or merely recorded.
    #[serde(default)]
    pub mode: Mode,
    /// Ordered chain. First terminal verdict wins.
    #[serde(default)]
    pub policy: Vec<LayerConfig>,
    /// Applied on the way out, after the chain has allowed.
    #[serde(default)]
    pub request_transforms: RequestTransforms,
    /// Applied on the way back to the agent.
    #[serde(default)]
    pub response_transforms: ResponseTransforms,
}

/// Whether a profile enforces its policy or only reports on it.
///
/// Turning default-deny on for an existing agent breaks everything it was quietly relying on,
/// and the list of what that is cannot be known in advance. `warn` runs the whole chain,
/// records exactly what *would* have been refused, and forwards the request anyway — so the
/// allowlist can be assembled from evidence rather than guesswork.
///
/// It is deliberately noisy: a proxy silently in warn mode is worse than no proxy, because
/// somebody believes it is protecting them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Enforce,
    Warn,
}

/// Rewrites applied to an allowed request before it leaves.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestTransforms {
    #[serde(default)]
    pub headers: Option<HeaderAllowlist>,
    /// Placeholder-to-real credential swaps, so the agent never holds the real secret.
    #[serde(default)]
    pub secrets: Vec<serde_json::Value>,
}

/// Rewrites applied to a response before the agent sees it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseTransforms {
    #[serde(default)]
    pub headers: Option<HeaderAllowlist>,
    /// Body rewrites. Each of these needs the whole body in memory, so a profile that
    /// declares one is stating that responses it applies to are no longer streamable.
    #[serde(default)]
    pub body: Vec<BodyTransform>,
}

/// A rewrite of the response body.
///
/// None of these are implemented yet; a profile naming one fails to build rather than
/// quietly serving untransformed responses. The shapes are declared because they determine
/// whether a response can stream, which is a decision the rest of the design has to respect.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "transform", rename_all = "snake_case")]
pub enum BodyTransform {
    /// Replace a body with an LLM-generated summary once it exceeds `over_bytes`.
    Summarize {
        over_bytes: usize,
        #[serde(default = "default_body_cap")]
        max_bytes: usize,
        #[serde(default)]
        rules: Vec<serde_json::Value>,
    },
    /// Mechanically shrink a structured body — drop known-noisy fields, collapse arrays —
    /// without invoking a model.
    Compact {
        #[serde(default = "default_body_cap")]
        max_bytes: usize,
        #[serde(default)]
        rules: Vec<serde_json::Value>,
    },
    /// Redact secrets the upstream echoed back, so a credential the proxy injected cannot
    /// leak to the agent through a response.
    Redact {
        #[serde(default)]
        patterns: Vec<String>,
        #[serde(default = "default_body_cap")]
        max_bytes: usize,
    },
}

fn default_body_cap() -> usize {
    1024 * 1024
}

impl BodyTransform {
    pub fn name(&self) -> &'static str {
        match self {
            BodyTransform::Summarize { .. } => "summarize",
            BodyTransform::Compact { .. } => "compact",
            BodyTransform::Redact { .. } => "redact",
        }
    }

    /// Every body transform needs the body materialised; this is the cap it declares.
    pub fn max_bytes(&self) -> usize {
        match self {
            BodyTransform::Summarize { max_bytes, .. }
            | BodyTransform::Compact { max_bytes, .. }
            | BodyTransform::Redact { max_bytes, .. } => *max_bytes,
        }
    }
}

/// Default-deny header filtering: headers not listed are stripped.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderAllowlist {
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sessions {
    /// Tried in order; first match wins.
    #[serde(default)]
    pub resolvers: Vec<ResolverConfig>,
    #[serde(default)]
    pub unidentified: Option<Unidentified>,
}

/// A session resolver. Ordering is significant, and so is strength: `peer_cred` uid is
/// kernel-supplied, `source_ip` is as trustworthy as the network, and `proxy_auth` is
/// client-asserted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResolverConfig {
    ProxyAuth {
        #[serde(default)]
        credentials: Vec<ProxyAuthEntry>,
    },
    SourceIp {
        #[serde(default)]
        map: Vec<SourceIpEntry>,
    },
    PeerCred {
        /// Resolve pid/cgroup as well as uid. Costs a `/proc` walk and is racy for
        /// short-lived processes, so uid-only matching does not need it.
        #[serde(default)]
        enrich: bool,
        #[serde(default)]
        map: Vec<PeerCredEntry>,
    },
    /// Sessions created by `marshal run`, identified by the cgroup scope it names.
    Launched,
    /// Identity by which listener accepted, for agents that share a uid.
    ListenerPort {
        #[serde(default)]
        map: Vec<ListenerPortEntry>,
    },
}

impl ResolverConfig {
    pub fn name(&self) -> &'static str {
        match self {
            ResolverConfig::ProxyAuth { .. } => "proxy_auth",
            ResolverConfig::SourceIp { .. } => "source_ip",
            ResolverConfig::PeerCred { .. } => "peer_cred",
            ResolverConfig::Launched => "launched",
            ResolverConfig::ListenerPort { .. } => "listener_port",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyAuthEntry {
    pub user: String,
    /// Read from the environment rather than written in the file, so the config can be
    /// committed.
    pub password_env: String,
    pub session: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIpEntry {
    pub cidr: String,
    pub session: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerPortEntry {
    pub port: u16,
    pub session: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCredEntry {
    #[serde(default)]
    pub uid: Option<u32>,
    /// Glob over the cgroup path. Requires `enrich: true`.
    #[serde(default)]
    pub cgroup: Option<String>,
    pub session: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unidentified {
    pub profile: String,
    #[serde(default)]
    pub action: UnidentifiedAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnidentifiedAction {
    /// Serve the request under the named (restrictive) profile, flagged unattributed.
    #[default]
    AllowWithProfile,
    /// Refuse anything we cannot attribute.
    Deny,
}
