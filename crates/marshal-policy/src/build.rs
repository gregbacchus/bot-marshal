//! Building a runnable [`Chain`] from configuration.

use std::sync::Arc;

use marshal_config::layer::{HostSet, LayerConfig};
use marshal_config::model::Config;
use marshal_core::{Decider, PolicyLayer};

use crate::chain::Chain;
use crate::hosts::{HostMatcher, PatternError};
use crate::layers::dlp::Oversize as DlpOversize;
use crate::layers::{Allowlist, Denylist, Dlp, Mcp, Rules};
use crate::mcp::McpPolicy;
use crate::patterns;
use crate::transforms::{McpToolFilter, RequestHeaderSetter, ResponseLimiter};
use marshal_judge::{AnthropicProvider, CompiledScope, Judge, OpenAiProvider, Provider};

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("unknown transform bundle `{0}`")]
    UnknownTransformBundle(String),

    #[error("profile `{profile}`: request_transforms.set_headers.{name}: invalid header name")]
    InvalidRequestHeaderName { profile: String, name: String },

    #[error(
        "profile `{profile}`: request_transforms.set_headers.{name}: header is managed by the proxy"
    )]
    ManagedRequestHeader { profile: String, name: String },

    #[error(
        "profile `{profile}`: request_transforms.set_headers.{name}: invalid header value: {source}"
    )]
    InvalidRequestHeaderValue {
        profile: String,
        name: String,
        #[source]
        source: http::header::InvalidHeaderValue,
    },

    #[error("profile `{profile}`, layer `{layer}`: {source}")]
    Pattern {
        profile: String,
        layer: &'static str,
        #[source]
        source: PatternError,
    },

    #[error("profile `{profile}`: unknown bundle `{bundle}`")]
    UnknownBundle { profile: String, bundle: String },

    #[error("profile `{profile}`: `{layer}` is not implemented yet")]
    Unimplemented { profile: String, layer: &'static str },

    #[error("profile `{profile}`: unknown dlp pattern `{pattern}`. Known patterns: {known}")]
    UnknownPattern { profile: String, pattern: String, known: String },

    #[error("profile `{profile}`: mcp: {source}")]
    Mcp {
        profile: String,
        #[source]
        source: crate::mcp::McpConfigError,
    },

    #[error("profile `{profile}`: judge scope: {source}")]
    JudgeScope {
        profile: String,
        #[source]
        source: marshal_core::PatternError,
    },

    #[error("profile `{profile}`: judge: {source}")]
    JudgeProvider {
        profile: String,
        #[source]
        source: marshal_judge::ProviderError,
    },

    #[error("profile `{profile}`: {source}")]
    Rule {
        profile: String,
        #[source]
        source: crate::layers::rules::RuleCompileError,
    },
}

/// Build request-header rewrites declared directly or through a named transform bundle.
pub fn build_request_transforms(
    cfg: &Config,
    profile_name: &str,
    profile: &marshal_config::model::Profile,
) -> Result<Vec<Arc<dyn marshal_core::RequestTransform>>, BuildError> {
    let profile = resolve_profile(cfg, profile)?;
    if profile.request_transforms.set_headers.is_empty() {
        return Ok(Vec::new());
    }

    let mut headers = Vec::with_capacity(profile.request_transforms.set_headers.len());
    for (name, value) in &profile.request_transforms.set_headers {
        let parsed_name = http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            BuildError::InvalidRequestHeaderName {
                profile: profile_name.to_owned(),
                name: name.clone(),
            }
        })?;
        if marshal_config::model::request_header_is_managed(&parsed_name) {
            return Err(BuildError::ManagedRequestHeader {
                profile: profile_name.to_owned(),
                name: name.clone(),
            });
        }
        let parsed_value = http::HeaderValue::from_str(value).map_err(|source| {
            BuildError::InvalidRequestHeaderValue {
                profile: profile_name.to_owned(),
                name: name.clone(),
                source,
            }
        })?;
        headers.push((parsed_name, parsed_value));
    }

    Ok(vec![Arc::new(RequestHeaderSetter::new(headers))])
}

/// Resolve a profile's `transforms: <name>` indirection, if it has one, into an effective
/// profile whose `request_transforms`/`response_transforms` are ready to use.
///
/// `marshal config check` already rejects a profile that sets `transforms` alongside either
/// section directly, so exactly one of "inline" or "named bundle" is ever populated on the
/// input — this just resolves the latter into the same shape as the former.
pub fn resolve_profile(
    cfg: &Config,
    profile: &marshal_config::model::Profile,
) -> Result<marshal_config::model::Profile, BuildError> {
    let mut effective = profile.clone();
    if let Some(name) = &profile.transforms {
        let bundle = cfg
            .transforms
            .get(name)
            .ok_or_else(|| BuildError::UnknownTransformBundle(name.clone()))?;
        effective.request_transforms = bundle.request_transforms.clone();
        effective.response_transforms = bundle.response_transforms.clone();
    }
    Ok(effective)
}

/// Build the chain for one profile.
///
/// Layers not yet implemented are a hard error rather than a silent skip: a config that
/// mentions `judge` must not quietly run without it, because the resulting chain would be
/// more permissive than the one the operator wrote.
pub fn build_chain(
    cfg: &Config,
    profile_name: &str,
    profile: &marshal_config::model::Profile,
    decider: Arc<dyn Decider>,
) -> Result<Chain, BuildError> {
    let profile = resolve_profile(cfg, profile)?;
    let mut layers: Vec<Arc<dyn PolicyLayer>> = Vec::new();

    for layer in &profile.policy {
        match layer {
            LayerConfig::Denylist { deny } => {
                let m = matcher(cfg, profile_name, "denylist", deny)?;
                layers.push(Arc::new(Denylist::new(m)));
            }
            LayerConfig::Allowlist { allow, on_match, on_miss } => {
                let m = matcher(cfg, profile_name, "allowlist", allow)?;
                layers.push(Arc::new(Allowlist::new(m, *on_match, *on_miss)));
            }
            LayerConfig::Dlp {
                scan_request,
                patterns: names,
                on_match,
                annotate,
                max_body_bytes,
                on_oversize,
                ..
            } => {
                // An unknown pattern name is an error rather than a skip: a profile that
                // believes it scans for GitHub tokens and silently does not is worse than one
                // that refuses to start.
                let mut compiled = Vec::new();
                for name in names {
                    compiled.push(patterns::builtin(name).ok_or_else(|| {
                        BuildError::UnknownPattern {
                            profile: profile_name.to_owned(),
                            pattern: name.clone(),
                            known: patterns::builtin_names().join(", "),
                        }
                    })?);
                }
                layers.push(Arc::new(Dlp::new(
                    compiled,
                    *scan_request,
                    *on_match,
                    annotate.flags.clone(),
                    *max_body_bytes,
                    match on_oversize {
                        marshal_config::layer::Oversize::Deny => DlpOversize::Deny,
                        marshal_config::layer::Oversize::PassUnscanned => {
                            DlpOversize::PassUnscanned
                        }
                    },
                )));
            }
            LayerConfig::Rules { expressions } => {
                let specs = expressions
                    .iter()
                    .map(|e| (e.when.clone(), e.verdict, e.annotate.flags.clone()));
                let rules = Rules::compile(specs).map_err(|source| BuildError::Rule {
                    profile: profile_name.to_owned(),
                    source,
                })?;
                layers.push(Arc::new(rules));
            }
            LayerConfig::Mcp { servers, max_body_bytes } => {
                let policy = Arc::new(McpPolicy::compile(servers).map_err(|source| {
                    BuildError::Mcp { profile: profile_name.to_owned(), source }
                })?);
                layers.push(Arc::new(Mcp::new(policy, *max_body_bytes)));
            }
            LayerConfig::Judge(cfg) => {
                let scope = CompiledScope::compile(&cfg.scope).map_err(|source| {
                    BuildError::JudgeScope { profile: profile_name.to_owned(), source }
                })?;

                let provider: Arc<dyn Provider> = match &cfg.provider {
                    marshal_config::layer::Provider::Anthropic {
                        model,
                        api_key_env,
                        max_tokens,
                        base_url,
                    } => Arc::new(
                        AnthropicProvider::from_env(
                            model.clone(),
                            api_key_env,
                            *max_tokens,
                            base_url.as_deref(),
                        )
                        .map_err(|source| BuildError::JudgeProvider {
                            profile: profile_name.to_owned(),
                            source,
                        })?,
                    ),
                    marshal_config::layer::Provider::OpenAi {
                        model,
                        api_key_env,
                        max_tokens,
                        base_url,
                    } => Arc::new(
                        OpenAiProvider::from_env(
                            model.clone(),
                            api_key_env,
                            *max_tokens,
                            base_url.as_deref(),
                        )
                        .map_err(|source| BuildError::JudgeProvider {
                            profile: profile_name.to_owned(),
                            source,
                        })?,
                    ),
                };

                layers.push(Arc::new(Judge::new(
                    scope,
                    provider,
                    cfg.prompt.clone(),
                    cfg.cache.ttl,
                    cfg.cache.max_entries,
                    cfg.max_concurrent,
                    cfg.timeout,
                    cfg.on_error,
                    cfg.on_timeout,
                    cfg.circuit_breaker.consecutive_failures,
                    cfg.circuit_breaker.cooldown,
                )));
            }
            #[allow(unreachable_patterns)]
            other => {
                return Err(BuildError::Unimplemented {
                    profile: profile_name.to_owned(),
                    layer: other.name(),
                });
            }
        }
    }

    // Same rule as an unimplemented policy layer: a profile naming a transform we cannot run
    // must not start. A response served untransformed is not what the operator asked for.
    if let Some(t) = profile
        .response_transforms
        .body
        .iter()
        .find(|t| !matches!(t, marshal_config::model::BodyTransform::Limit { .. }))
    {
        return Err(BuildError::Unimplemented {
            profile: profile_name.to_owned(),
            layer: t.name(),
        });
    }

    Ok(Chain::new(profile_name, layers, profile.default_action, decider)
        .warn_only(profile.mode == marshal_config::model::Mode::Warn))
}

/// Response transforms implied by a profile's policy.
///
/// The MCP filter is derived from the `mcp` layer rather than configured separately: gating
/// `tools/call` and hiding those same tools from `tools/list` are two halves of one policy,
/// and letting them drift apart would advertise tools that cannot be called.
pub fn build_response_transforms(
    cfg: &Config,
    profile_name: &str,
    profile: &marshal_config::model::Profile,
) -> Result<Vec<Arc<dyn marshal_core::ResponseTransform>>, BuildError> {
    let profile = resolve_profile(cfg, profile)?;
    let mut out: Vec<Arc<dyn marshal_core::ResponseTransform>> = Vec::new();

    for layer in &profile.policy {
        if let LayerConfig::Mcp { servers, max_body_bytes } = layer {
            let policy =
                Arc::new(McpPolicy::compile(servers).map_err(|source| BuildError::Mcp {
                    profile: profile_name.to_owned(),
                    source,
                })?);
            out.push(Arc::new(McpToolFilter::new(policy, *max_body_bytes)));
        }
    }
    for transform in &profile.response_transforms.body {
        if let marshal_config::model::BodyTransform::Limit { max_bytes, on_oversize } = transform {
            out.push(Arc::new(ResponseLimiter::new(*max_bytes, on_oversize.clone())));
        }
    }
    Ok(out)
}

/// Flatten a host set, expanding bundle references.
fn matcher(
    cfg: &Config,
    profile: &str,
    layer: &'static str,
    set: &HostSet,
) -> Result<HostMatcher, BuildError> {
    let mut domains = set.domains.clone();
    let mut cidrs = set.cidrs.clone();

    for bundle in &set.bundles {
        let b = cfg.bundles.get(bundle).ok_or_else(|| BuildError::UnknownBundle {
            profile: profile.to_owned(),
            bundle: bundle.clone(),
        })?;
        domains.extend(b.domains.iter().cloned());
        cidrs.extend(b.cidrs.iter().cloned());
    }

    HostMatcher::new(&domains, &cidrs).map_err(|source| BuildError::Pattern {
        profile: profile.to_owned(),
        layer,
        source,
    })
}
