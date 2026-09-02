//! Building a runnable [`Chain`] from configuration.

use std::sync::Arc;

use marshal_config::layer::{HostSet, LayerConfig};
use marshal_config::model::Config;
use marshal_core::{Decider, PolicyLayer};

use crate::chain::Chain;
use crate::hosts::{HostMatcher, PatternError};
use crate::layers::dlp::Oversize as DlpOversize;
use crate::layers::{Allowlist, Denylist, Dlp, Rules};
use crate::patterns;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("unknown profile `{0}`")]
    UnknownProfile(String),

    #[error("profile `{profile}` has a cyclic `extends` chain")]
    CyclicExtends { profile: String },

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

    #[error("profile `{profile}`: {source}")]
    Rule {
        profile: String,
        #[source]
        source: crate::layers::rules::RuleCompileError,
    },
}

/// Resolve a profile's `extends` chain into an effective profile.
///
/// Scalars and transform sections merge child-over-parent. The **policy chain does not
/// merge**: a
/// child that declares any layers replaces the parent's chain outright. Splicing two ordered
/// chains together would silently change precedence, and in a short-circuiting chain
/// precedence is the whole semantics — better to make the child restate what it wants.
pub fn resolve_profile(
    cfg: &Config,
    name: &str,
) -> Result<marshal_config::model::Profile, BuildError> {
    let mut lineage = Vec::new();
    let mut current = name.to_owned();

    loop {
        if lineage.contains(&current) {
            return Err(BuildError::CyclicExtends { profile: current });
        }
        let profile = cfg
            .profiles
            .get(&current)
            .ok_or_else(|| BuildError::UnknownProfile(current.clone()))?;
        lineage.push(current.clone());
        match &profile.extends {
            Some(parent) => current = parent.clone(),
            None => break,
        }
    }

    // Root first, so children override.
    let mut effective = marshal_config::model::Profile::default();
    for ancestor in lineage.iter().rev() {
        let p = &cfg.profiles[ancestor];
        effective.default_action = p.default_action;
        effective.i_understand_this_is_allow_by_default = p.i_understand_this_is_allow_by_default;
        if !p.policy.is_empty() {
            effective.policy = p.policy.clone();
        }
        if p.request_transforms.headers.is_some() {
            effective.request_transforms.headers = p.request_transforms.headers.clone();
        }
        if !p.request_transforms.secrets.is_empty() {
            effective.request_transforms.secrets = p.request_transforms.secrets.clone();
        }
        if p.response_transforms.headers.is_some() {
            effective.response_transforms.headers = p.response_transforms.headers.clone();
        }
        if !p.response_transforms.body.is_empty() {
            effective.response_transforms.body = p.response_transforms.body.clone();
        }
    }
    effective.extends = None;
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
    decider: Arc<dyn Decider>,
) -> Result<Chain, BuildError> {
    let profile = resolve_profile(cfg, profile_name)?;
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
    if let Some(t) = profile.response_transforms.body.first() {
        return Err(BuildError::Unimplemented {
            profile: profile_name.to_owned(),
            layer: t.name(),
        });
    }

    Ok(Chain::new(profile_name, layers, profile.default_action, decider))
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
