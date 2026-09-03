//! The configuration document.

use std::collections::BTreeMap;

use marshal_core::Decision;
use serde::{Deserialize, Serialize};

use crate::layer::LayerConfig;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub listeners: Listeners,
    #[serde(default)]
    pub tls: Tls,
    #[serde(default)]
    pub upstream: Upstream,
    /// The fallback profile: embedded directly, not a reference to a named one, so it's
    /// always visible in the file someone opens first and is never sourced from
    /// `profiles_path` where it would be easy to miss. Required — there must always be a
    /// knowable, non-arbitrary profile for unattributed traffic. It has no name and cannot be
    /// referenced from anywhere — `profiles`/`profiles_path` are exclusively the *named*
    /// profiles a resolver or `marshal run --profile` can pick.
    pub profile: Profile,
    /// Every *named* profile, found under `profiles_path`. Not part of the YAML schema
    /// itself; populated by `load`. Does not include the embedded `profile` above.
    #[serde(skip)]
    pub profiles: BTreeMap<String, Profile>,
    /// Directory scanned for one named profile per file (see [`crate::load`]). Relative to
    /// this file's own directory; `~/` expands against `$HOME`.
    #[serde(default = "default_profiles_path")]
    pub profiles_path: String,
    #[serde(default)]
    pub identities: Identities,
    /// Named host sets importable by profiles via `allow.bundles`.
    #[serde(default)]
    pub bundles: BTreeMap<String, crate::layer::HostSet>,
    /// Directory scanned for one bundle per file. Same resolution rules as `profiles_path`.
    #[serde(default = "default_bundles_path")]
    pub bundles_path: String,
    /// Every named transform bundle found under `transforms_path` — see [`Profile::transforms`].
    #[serde(skip)]
    pub transforms: BTreeMap<String, TransformBundle>,
    /// Directory scanned for one transform bundle per file. Same resolution rules as
    /// `profiles_path`. There is no inline equivalent — a transform bundle only ever comes
    /// from a file, referenced by name.
    #[serde(default = "default_transforms_path")]
    pub transforms_path: String,
}

fn default_profiles_path() -> String {
    "profiles".to_owned()
}

fn default_bundles_path() -> String {
    "bundles".to_owned()
}

fn default_transforms_path() -> String {
    "transforms".to_owned()
}

/// One named, reusable pair of request/response transforms, referenced by a profile via
/// `transforms: <name>` instead of embedding `request_transforms`/`response_transforms`
/// directly. Lives under `transforms_path`, one bundle per file, keyed by filename — the same
/// convention `profiles_path`/`bundles_path` use.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransformBundle {
    #[serde(default)]
    pub request_transforms: RequestTransforms,
    #[serde(default)]
    pub response_transforms: ResponseTransforms,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Listeners {
    #[serde(default)]
    pub explicit: Option<ExplicitListener>,
    #[serde(default)]
    pub dns: Option<DnsListener>,
    #[serde(default)]
    pub management: Option<ManagementListener>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExplicitListener {
    /// HTTP CONNECT and SOCKS5 share one port; the protocol is sniffed. A single address
    /// (`"127.0.0.1:8080"`) is the common case; a list binds more than one, all serving the
    /// identical protocol — the only difference is which port accepted the connection, which
    /// is what the `listener_port` identity resolver keys on.
    #[serde(deserialize_with = "one_or_many")]
    pub listen: Vec<String>,
    /// Optional Unix-domain listener. Unlocks `SO_PEERCRED`, which is the only unspoofable,
    /// race-free identity available on a single host.
    #[serde(default)]
    pub unix_socket: Option<String>,
}

/// Accepts either a bare string or a list of strings, so `listen: "addr"` keeps working
/// unchanged for the single-address case while `listen: ["addr1", "addr2"]` opts into more.
fn one_or_many<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(de)? {
        OneOrMany::One(s) => vec![s],
        OneOrMany::Many(v) => v,
    })
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
    /// A named bundle from `transforms_path`, used in place of `request_transforms`/
    /// `response_transforms` below. Mutually exclusive with setting either of them directly.
    #[serde(default)]
    pub transforms: Option<String>,
    /// Applied on the way out, after the chain has allowed. Ignored if `transforms` is set.
    #[serde(default)]
    pub request_transforms: RequestTransforms,
    /// Applied on the way back to the agent. Ignored if `transforms` is set.
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
    /// Header values to add or replace after policy allows the request.
    #[serde(default)]
    pub set_headers: std::collections::BTreeMap<String, String>,
    /// Placeholder-to-real credential swaps, so the agent never holds the real secret.
    #[serde(default)]
    pub secrets: Vec<serde_json::Value>,
}

/// Headers whose meaning belongs to connection routing or HTTP framing rather than the
/// end-to-end request. A transform that set one would either be removed later or could make
/// the bytes on the wire disagree with the request the proxy checked.
pub fn request_header_is_managed(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "content-length"
            | "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
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
/// A profile naming an unimplemented transform fails to build rather than quietly serving an
/// untransformed response. The shapes are declared here because they determine whether a
/// response can stream, which is a decision the rest of the design has to respect.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "transform", rename_all = "snake_case")]
pub enum BodyTransform {
    /// Bound the response bytes delivered to an agent.
    Limit {
        max_bytes: usize,
        #[serde(default)]
        on_oversize: ResponseOversizeAction,
    },
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

fn default_truncation_marker() -> String {
    "\n...[response truncated by bot-marshal]".into()
}

fn default_replacement_body() -> String {
    "response omitted by bot-marshal because it exceeded the configured limit".into()
}

/// What a response limit does after the upstream body exceeds `max_bytes`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ResponseOversizeAction {
    /// Replace the upstream response with a small structured proxy error.
    #[default]
    Fail,
    /// Keep a prefix and an explicit marker, within the same byte budget.
    Truncate {
        #[serde(default)]
        method: TruncationMethod,
        #[serde(default = "default_truncation_marker")]
        marker: String,
    },
    /// Discard the upstream body and substitute a bounded operator-provided message.
    Replace {
        #[serde(default = "default_replacement_body")]
        body: String,
    },
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TruncationMethod {
    Bytes,
    #[default]
    Utf8,
}

impl BodyTransform {
    pub fn name(&self) -> &'static str {
        match self {
            BodyTransform::Limit { .. } => "limit",
            BodyTransform::Summarize { .. } => "summarize",
            BodyTransform::Compact { .. } => "compact",
            BodyTransform::Redact { .. } => "redact",
        }
    }

    /// Every body transform needs the body materialised; this is the cap it declares.
    pub fn max_bytes(&self) -> usize {
        match self {
            BodyTransform::Limit { max_bytes, .. }
            | BodyTransform::Summarize { max_bytes, .. }
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
pub struct Identities {
    /// Tried in order; first match wins.
    #[serde(default)]
    pub resolvers: Vec<ResolverConfig>,
    #[serde(default)]
    pub unidentified: Option<Unidentified>,
}

/// An identity resolver. Ordering is significant, and so is strength: `peer_cred` uid is
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
    /// Identities created by `marshal run`, identified by the cgroup scope it names.
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
    pub identity: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIpEntry {
    pub cidr: String,
    pub identity: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListenerPortEntry {
    pub port: u16,
    pub identity: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCredEntry {
    #[serde(default)]
    pub uid: Option<u32>,
    /// A system username, resolved to its uid via NSS when the config is built. Mutually
    /// exclusive with `uid` — pick whichever is more convenient to write; matching still
    /// happens on the numeric id the kernel reports.
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub gid: Option<u32>,
    /// A system groupname, resolved to its gid the same way `username` resolves to a uid.
    /// Mutually exclusive with `gid`.
    #[serde(default)]
    pub groupname: Option<String>,
    /// Glob over the cgroup path. Requires `enrich: true`.
    #[serde(default)]
    pub cgroup: Option<String>,
    pub identity: String,
    pub profile: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unidentified {
    /// Which profile unattributed traffic gets. Defaults to the embedded `profile:` — set
    /// this only to name a *different* one from `profiles_path` instead.
    #[serde(default)]
    pub profile: Option<String>,
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
