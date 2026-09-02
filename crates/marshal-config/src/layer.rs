//! Policy layer configuration.
//!
//! Each variant maps to a `PolicyLayer` implementation. The chain is an ordered list: the
//! first terminal verdict wins, so position is semantically significant.

use marshal_core::{CostClass, FailureMode};
use serde::{Deserialize, Serialize};

/// What a matching layer does. `Pass` keeps evaluating downstream layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    Deny,
    Pass,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostSet {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub cidrs: Vec<String>,
    /// Names of imported bundles, e.g. `github`, `npm`.
    #[serde(default)]
    pub bundles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "layer", rename_all = "snake_case")]
pub enum LayerConfig {
    /// Hard denies. Placed first so they take precedence over any later approval — ordering
    /// gives that for free rather than needing a special rule.
    Denylist {
        #[serde(default)]
        deny: HostSet,
    },
    Allowlist {
        #[serde(default)]
        allow: HostSet,
        #[serde(default = "outcome_allow")]
        on_match: Outcome,
        #[serde(default = "outcome_pass")]
        on_miss: Outcome,
    },
    /// CEL expressions over the request and accumulated evidence.
    Rules {
        #[serde(default)]
        expressions: Vec<RuleExpr>,
    },
    /// Scans for real credentials trying to leave the boundary.
    Dlp {
        /// Scan the request body. Bodies must be buffered to be scanned, so this stops
        /// requests it applies to from streaming.
        #[serde(default)]
        scan_request: bool,
        #[serde(default)]
        scan_response: bool,
        #[serde(default)]
        patterns: Vec<String>,
        #[serde(default = "outcome_deny")]
        on_match: Outcome,
        #[serde(default)]
        annotate: Annotate,
        /// Largest body the layer will buffer in order to scan it.
        #[serde(default = "default_scan_cap")]
        max_body_bytes: usize,
        /// What to do with a body too large to scan. Defaults to refusing: an unscanned body
        /// is exactly where a credential would hide.
        #[serde(default)]
        on_oversize: Oversize,
    },
    /// MCP tool-level policy: which tools an agent may call, and with what arguments.
    Mcp {
        #[serde(default)]
        servers: Vec<McpServer>,
        /// Largest JSON-RPC message the layer will buffer in order to inspect it.
        #[serde(default = "default_scan_cap")]
        max_body_bytes: usize,
    },
    /// The LLM judge. Expensive, so it caches and circuit-breaks.
    Judge(Box<JudgeConfig>),
}

fn outcome_allow() -> Outcome {
    Outcome::Allow
}
fn outcome_pass() -> Outcome {
    Outcome::Pass
}
fn outcome_deny() -> Outcome {
    Outcome::Deny
}

fn default_scan_cap() -> usize {
    1024 * 1024
}

/// What to do with a body larger than the scan cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Oversize {
    #[default]
    Deny,
    PassUnscanned,
}

/// One MCP server and the tools permitted on it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpServer {
    #[serde(default)]
    pub name: Option<String>,
    /// Which hosts this applies to.
    #[serde(default)]
    pub rules: Vec<McpHostRule>,
    /// Default-deny: a tool not listed here cannot be called, and is filtered out of
    /// `tools/list` so the agent never sees it.
    #[serde(default)]
    pub tools: Vec<McpTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpHostRule {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpTool {
    /// Glob over the tool name, so `search_*` covers a family.
    pub name: String,
    /// Constraints on the call's arguments. All must hold.
    #[serde(default)]
    pub when: Vec<McpArgConstraint>,
}

/// A constraint on one argument of a `tools/call`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpArgConstraint {
    /// Dotted path into the arguments object, e.g. `owner` or `repo.name`.
    pub path: String,
    #[serde(default)]
    pub equals: Option<serde_json::Value>,
    #[serde(default, rename = "in")]
    pub one_of: Option<Vec<serde_json::Value>>,
    /// Regular expression the value must match, as a string.
    #[serde(default)]
    pub matches: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleExpr {
    /// CEL expression. Non-Turing-complete, so it cannot hang the request path.
    pub when: String,
    pub verdict: Outcome,
    #[serde(default)]
    pub annotate: Annotate,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Annotate {
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeConfig {
    pub provider: Provider,
    /// Only requests matching this scope reach the judge. A scope that is too broad is slow
    /// and expensive, which is why cache hit rate is an exported metric.
    #[serde(default)]
    pub scope: Vec<JudgeScope>,
    pub prompt: String,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default, with = "humantime_serde")]
    pub timeout: Option<std::time::Duration>,
    #[serde(default = "default_max_concurrent")]
    pub max_concurrent: usize,
    #[serde(default)]
    pub on_error: FailureMode,
    #[serde(default)]
    pub on_timeout: FailureMode,
    #[serde(default)]
    pub circuit_breaker: CircuitBreaker,
}

fn default_max_concurrent() -> usize {
    32
}

/// Which requests reach the judge.
///
/// Deliberately excludes header and body content — the judge never sees either, only method,
/// host, path, and header *names*. The request goes to a third-party API; anything it is
/// shown is a potential leak, and neither the body nor a header value is ever necessary to
/// answer a scoping question.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeScope {
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub methods: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Provider {
    Anthropic {
        model: String,
        api_key_env: String,
        #[serde(default)]
        max_tokens: Option<u32>,
        /// Overrides the real API endpoint — for an Anthropic-compatible gateway or
        /// self-hosted deployment. `scheme://host[:port]`, no path.
        #[serde(default)]
        base_url: Option<String>,
    },
    #[serde(rename = "openai")]
    OpenAi {
        model: String,
        api_key_env: String,
        #[serde(default)]
        max_tokens: Option<u32>,
        /// Overrides the real API endpoint — this is what makes any OpenAI-compatible
        /// server usable: Azure OpenAI, OpenRouter, a local vLLM or Ollama instance, an
        /// internal gateway. `scheme://host[:port]`, no path.
        #[serde(default)]
        base_url: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(with = "humantime_serde")]
    pub ttl: std::time::Duration,
    pub max_entries: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self { ttl: std::time::Duration::from_secs(900), max_entries: 10_000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub consecutive_failures: u32,
    #[serde(with = "humantime_serde")]
    pub cooldown: std::time::Duration,
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self { consecutive_failures: 5, cooldown: std::time::Duration::from_secs(30) }
    }
}

impl LayerConfig {
    pub fn name(&self) -> &'static str {
        match self {
            LayerConfig::Denylist { .. } => "denylist",
            LayerConfig::Allowlist { .. } => "allowlist",
            LayerConfig::Rules { .. } => "rules",
            LayerConfig::Dlp { .. } => "dlp",
            LayerConfig::Mcp { .. } => "mcp",
            LayerConfig::Judge(_) => "judge",
        }
    }

    /// Used by `validate` to warn when an expensive layer precedes a cheap one.
    pub fn cost(&self) -> CostClass {
        match self {
            LayerConfig::Denylist { .. } | LayerConfig::Allowlist { .. } => CostClass::Trivial,
            LayerConfig::Rules { .. } | LayerConfig::Mcp { .. } => CostClass::Cheap,
            LayerConfig::Dlp { .. } => CostClass::Moderate,
            LayerConfig::Judge(_) => CostClass::Expensive,
        }
    }
}
