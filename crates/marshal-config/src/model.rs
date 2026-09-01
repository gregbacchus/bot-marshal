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
    pub http: String,
    pub https: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsListener {
    #[serde(default)]
    pub enabled: bool,
    pub listen: String,
    pub proxy_ip: String,
    #[serde(default)]
    pub passthrough: Vec<String>,
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
    /// Ordered chain. First terminal verdict wins.
    #[serde(default)]
    pub policy: Vec<LayerConfig>,
    #[serde(default)]
    pub transforms: Transforms,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transforms {
    #[serde(default)]
    pub headers: Option<HeaderTransform>,
    #[serde(default)]
    pub secrets: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderTransform {
    /// Default-deny: headers not listed are stripped.
    #[serde(default)]
    pub allow: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sessions {
    /// Tried in order; first match wins.
    #[serde(default)]
    pub resolvers: Vec<serde_json::Value>,
    #[serde(default)]
    pub unidentified: Option<Unidentified>,
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
