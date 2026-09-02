//! Configuration validation.
//!
//! Two checks here are load-bearing rather than cosmetic:
//!
//! * a profile may not default to `allow` without an explicit acknowledgement — that field is
//!   the whole default-deny guarantee;
//! * an expensive layer placed before a cheap one is flagged, because the cost of that
//!   mistake is invisible until the latency bill arrives.

use marshal_core::Decision;

use crate::model::Config;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub severity: Severity,
    /// Dotted path to the offending item, e.g. `profiles.coding-agent.policy[2]`.
    pub location: String,
    pub message: String,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tag = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(f, "{tag}: {}: {}", self.location, self.message)
    }
}

/// Returns every problem found. An empty result means the config is usable.
pub fn validate(cfg: &Config) -> Vec<Diagnostic> {
    let mut out = Vec::new();

    // The embedded fallback ("profile:") and every named one ("profiles.<name>") get the same
    // checks — it has no name of its own, so `at` is just the top-level key here rather than
    // a `profiles.` path.
    check_profile(cfg, "profile", &cfg.profile, &mut out);
    for (name, profile) in &cfg.profiles {
        check_profile(cfg, &format!("profiles.{name}"), profile, &mut out);
    }

    // Resolvers must name profiles that exist, or a matching connection resolves to nothing
    // and falls through to the fallback — silently, and under the wrong policy.
    for (i, resolver) in cfg.sessions.resolvers.iter().enumerate() {
        let at = format!("sessions.resolvers[{i}]");
        let referenced: Vec<&String> = match resolver {
            crate::model::ResolverConfig::ProxyAuth { credentials } => {
                credentials.iter().map(|c| &c.profile).collect()
            }
            crate::model::ResolverConfig::SourceIp { map } => {
                map.iter().map(|e| &e.profile).collect()
            }
            crate::model::ResolverConfig::PeerCred { enrich, map } => {
                if !*enrich && map.iter().any(|e| e.cgroup.is_some()) {
                    out.push(Diagnostic {
                        severity: Severity::Error,
                        location: format!("{at}.enrich"),
                        message: "this resolver matches on `cgroup` but has `enrich: false`, \
                                  so the cgroup is never read and those entries can never \
                                  match"
                            .into(),
                    });
                }
                if !*enrich && map.iter().any(|e| e.gid.is_some() || e.groupname.is_some()) {
                    out.push(Diagnostic {
                        severity: Severity::Warning,
                        location: format!("{at}.enrich"),
                        message: "this resolver matches on `gid`/`groupname` with \
                                  `enrich: false`: the kernel supplies gid directly for a Unix \
                                  socket connection, but a TCP connection's gid can only be \
                                  read via `enrich: true` — without it, these entries only \
                                  ever match over the Unix listener"
                            .into(),
                    });
                }
                for (i, e) in map.iter().enumerate() {
                    if e.uid.is_some() && e.username.is_some() {
                        out.push(Diagnostic {
                            severity: Severity::Error,
                            location: format!("{at}.map[{i}]"),
                            message: "`uid` and `username` both set — they resolve to the \
                                      same thing, so name only one"
                                .into(),
                        });
                    }
                    if e.gid.is_some() && e.groupname.is_some() {
                        out.push(Diagnostic {
                            severity: Severity::Error,
                            location: format!("{at}.map[{i}]"),
                            message: "`gid` and `groupname` both set — they resolve to the \
                                      same thing, so name only one"
                                .into(),
                        });
                    }
                    if e.uid.is_none()
                        && e.username.is_none()
                        && e.gid.is_none()
                        && e.groupname.is_none()
                        && e.cgroup.is_none()
                    {
                        out.push(Diagnostic {
                            severity: Severity::Error,
                            location: format!("{at}.map[{i}]"),
                            message: "none of `uid`, `username`, `gid`, `groupname`, `cgroup` \
                                      is set — this entry can never match anything"
                                .into(),
                        });
                    }
                }
                map.iter().map(|e| &e.profile).collect()
            }
            crate::model::ResolverConfig::Launched => Vec::new(),
            crate::model::ResolverConfig::ListenerPort { map } => {
                map.iter().map(|e| &e.profile).collect()
            }
        };
        for profile in referenced {
            if !cfg.profiles.contains_key(profile) {
                out.push(Diagnostic {
                    severity: Severity::Error,
                    location: at.clone(),
                    message: format!("names unknown profile `{profile}`"),
                });
            }
        }
    }

    // `profile: None` means "use the embedded `profile:`" — always valid, since that's
    // required to exist. Only an explicit override needs checking.
    if let Some(u) = &cfg.sessions.unidentified
        && let Some(name) = &u.profile
        && !cfg.profiles.contains_key(name)
    {
        out.push(Diagnostic {
            severity: Severity::Error,
            location: "sessions.unidentified.profile".into(),
            message: format!("unknown profile `{name}`"),
        });
    }

    out
}

fn check_profile(
    cfg: &Config,
    at: &str,
    profile: &crate::model::Profile,
    out: &mut Vec<Diagnostic>,
) {
    if profile.default_action == Decision::Allow && !profile.i_understand_this_is_allow_by_default {
        out.push(Diagnostic {
            severity: Severity::Error,
            location: format!("{at}.default_action"),
            message: "default_action is `allow`, which disables default-deny for every \
                          request that reaches the end of the chain. Set \
                          `i_understand_this_is_allow_by_default: true` to confirm this is \
                          deliberate."
                .into(),
        });
    }

    // Warn mode is a rollout tool, not a setting to forget about. Saying so on every
    // `config check` is the cheapest way to stop a profile living there indefinitely
    // while somebody believes it is enforcing.
    if profile.mode == crate::model::Mode::Warn {
        out.push(Diagnostic {
            severity: Severity::Warning,
            location: format!("{at}.mode"),
            message: "this profile is in WARN mode: refusals are recorded but every \
                          request is forwarded. Audit records carry `would_deny: true`; use \
                          them to build the allowlist, then set `mode: enforce`."
                .into(),
        });
    }

    if profile.policy.is_empty() {
        out.push(Diagnostic {
            severity: Severity::Warning,
            location: format!("{at}.policy"),
            message: format!(
                "empty policy chain; every request falls through to default_action \
                     (`{:?}`)",
                profile.default_action
            ),
        });
    }

    // Cost ordering: cheapest first.
    let mut highest_seen = None;
    for (i, layer) in profile.policy.iter().enumerate() {
        let cost = layer.cost();
        if let Some((prev_cost, prev_name)) = highest_seen
            && cost < prev_cost
        {
            out.push(Diagnostic {
                severity: Severity::Warning,
                location: format!("{at}.policy[{i}]"),
                message: format!(
                    "`{}` ({cost:?}) is placed after `{prev_name}` ({prev_cost:?}); \
                         ordering layers cheapest-first avoids paying for the expensive one \
                         on requests the cheap one could have decided",
                    layer.name()
                ),
            });
        }
        if highest_seen.is_none_or(|(prev, _)| cost > prev) {
            highest_seen = Some((cost, layer.name()));
        }
    }

    // An unconditional terminal verdict makes everything after it dead config. This is
    // easy to write by accident: an allowlist with `on_match: allow` reads like "permit
    // these hosts", but in a short-circuiting chain it also means "and skip every check
    // that follows". Use `on_match: pass` when later layers should still run.
    let mut terminal_at: Option<(usize, &str)> = None;
    for (i, layer) in profile.policy.iter().enumerate() {
        if let Some((terminal_index, culprit)) = terminal_at {
            out.push(Diagnostic {
                    severity: Severity::Warning,
                    location: format!("{at}.policy[{i}]"),
                    message: format!(
                        "`{}` is unreachable for allowed requests: `{culprit}` at policy[{terminal_index}] \
                         returns a terminal ALLOW on match, which stops the chain. Set that \
                         layer's `on_match` to `pass` if later layers should still run.",
                        layer.name()
                    ),
                });
            break;
        }
        if let crate::layer::LayerConfig::Allowlist { on_match, .. } = layer
            && *on_match == crate::layer::Outcome::Allow
        {
            terminal_at = Some((i, layer.name()));
        }
    }

    // Body transforms force the whole response into memory. That is a real behaviour
    // change, not a detail: an SSE or WebSocket response cannot survive it, so the
    // operator should be told rather than discovering it when an agent's stream stalls.
    for (i, t) in profile.response_transforms.body.iter().enumerate() {
        out.push(Diagnostic {
            severity: Severity::Warning,
            location: format!("{at}.response_transforms.body[{i}]"),
            message: format!(
                "`{}` buffers the response body (up to {} bytes), so responses it \
                     applies to cannot stream; scope it away from SSE and WebSocket \
                     endpoints",
                t.name(),
                t.max_bytes()
            ),
        });
    }

    // Bundle references must resolve.
    for (i, layer) in profile.policy.iter().enumerate() {
        let bundles = match layer {
            crate::layer::LayerConfig::Allowlist { allow, .. } => &allow.bundles,
            crate::layer::LayerConfig::Denylist { deny } => &deny.bundles,
            _ => continue,
        };
        for b in bundles {
            if !cfg.bundles.contains_key(b) {
                out.push(Diagnostic {
                    severity: Severity::Error,
                    location: format!("{at}.policy[{i}]"),
                    message: format!("references unknown bundle `{b}`"),
                });
            }
        }
    }

    if let Some(name) = &profile.transforms {
        let has_inline_request = profile.request_transforms.headers.is_some()
            || !profile.request_transforms.secrets.is_empty();
        let has_inline_response = profile.response_transforms.headers.is_some()
            || !profile.response_transforms.body.is_empty();
        if has_inline_request || has_inline_response {
            out.push(Diagnostic {
                severity: Severity::Error,
                location: format!("{at}.transforms"),
                message: "set alongside request_transforms/response_transforms — use one \
                              or the other, not both"
                    .into(),
            });
        }
        if !cfg.transforms.contains_key(name) {
            out.push(Diagnostic {
                severity: Severity::Error,
                location: format!("{at}.transforms"),
                message: format!("references unknown transform bundle `{name}`"),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Profile, Unidentified, UnidentifiedAction};

    fn cfg_with(profile: Profile) -> Config {
        let mut cfg = Config::default();
        cfg.profiles.insert("p".into(), profile);
        cfg
    }

    #[test]
    fn allow_by_default_requires_acknowledgement() {
        let cfg = cfg_with(Profile { default_action: Decision::Allow, ..Default::default() });
        let d = validate(&cfg);
        assert!(d.iter().any(|d| d.severity == Severity::Error
            && d.location == "profiles.p.default_action"));

        let cfg = cfg_with(Profile {
            default_action: Decision::Allow,
            i_understand_this_is_allow_by_default: true,
            ..Default::default()
        });
        assert!(!validate(&cfg).iter().any(|d| d.location == "profiles.p.default_action"));
    }

    #[test]
    fn deny_by_default_needs_no_acknowledgement() {
        let cfg = cfg_with(Profile::default());
        assert!(!validate(&cfg).iter().any(|d| d.severity == Severity::Error));
    }

    #[test]
    fn a_terminal_allowlist_makes_later_layers_unreachable() {
        use crate::layer::{HostSet, LayerConfig, Outcome};
        let allow_terminal = LayerConfig::Allowlist {
            allow: HostSet::default(),
            on_match: Outcome::Allow,
            on_miss: Outcome::Pass,
        };
        let dlp = LayerConfig::Dlp {
            scan_request: true,
            scan_response: false,
            patterns: vec![],
            on_match: Outcome::Deny,
            annotate: Default::default(),
            max_body_bytes: 1024,
            on_oversize: Default::default(),
        };

        let bad = cfg_with(Profile {
            policy: vec![allow_terminal.clone(), dlp.clone()],
            ..Default::default()
        });
        assert!(
            validate(&bad)
                .iter()
                .any(|d| d.location == "profiles.p.policy[1]" && d.message.contains("unreachable")),
            "{:?}",
            validate(&bad)
        );

        // With `on_match: pass` the later layer does run, so there is nothing to warn about.
        let good = cfg_with(Profile {
            policy: vec![
                LayerConfig::Allowlist {
                    allow: HostSet::default(),
                    on_match: Outcome::Pass,
                    on_miss: Outcome::Deny,
                },
                dlp,
            ],
            ..Default::default()
        });
        assert!(!validate(&good).iter().any(|d| d.message.contains("unreachable")));
    }

    #[test]
    fn response_body_transforms_warn_about_buffering() {
        use crate::model::{BodyTransform, ResponseTransforms};
        let cfg = cfg_with(Profile {
            response_transforms: ResponseTransforms {
                headers: None,
                body: vec![BodyTransform::Redact {
                    patterns: vec!["github-pat".into()],
                    max_bytes: 4096,
                }],
            },
            ..Default::default()
        });
        let d = validate(&cfg);
        assert!(
            d.iter().any(|d| d.severity == Severity::Warning
                && d.location == "profiles.p.response_transforms.body[0]"
                && d.message.contains("cannot stream")),
            "{d:?}"
        );
    }

    #[test]
    fn expensive_layer_before_cheap_one_warns() {
        use crate::layer::{HostSet, JudgeConfig, LayerConfig, Outcome, Provider};
        let judge = LayerConfig::Judge(Box::new(JudgeConfig {
            provider: Provider::Anthropic {
                model: "m".into(),
                api_key_env: "K".into(),
                max_tokens: None,
                base_url: None,
            },
            scope: vec![],
            prompt: "p".into(),
            cache: Default::default(),
            timeout: None,
            max_concurrent: 1,
            on_error: Default::default(),
            on_timeout: Default::default(),
            circuit_breaker: Default::default(),
        }));
        let allowlist = LayerConfig::Allowlist {
            allow: HostSet::default(),
            on_match: Outcome::Allow,
            on_miss: Outcome::Pass,
        };

        let bad = cfg_with(Profile { policy: vec![judge, allowlist], ..Default::default() });
        assert!(
            validate(&bad)
                .iter()
                .any(|d| d.severity == Severity::Warning && d.location == "profiles.p.policy[1]")
        );
    }

    #[test]
    fn unidentified_profile_left_unset_needs_no_check() {
        // `profile: None` means "use the embedded default", which always exists — nothing to
        // validate.
        let mut cfg = cfg_with(Profile::default());
        cfg.sessions.unidentified =
            Some(Unidentified { profile: None, action: UnidentifiedAction::default() });
        assert!(!validate(&cfg).iter().any(|d| d.severity == Severity::Error));
    }

    #[test]
    fn unidentified_profile_naming_an_unknown_profile_is_an_error() {
        let mut cfg = cfg_with(Profile::default());
        cfg.sessions.unidentified = Some(Unidentified {
            profile: Some("nope".into()),
            action: UnidentifiedAction::default(),
        });
        assert!(validate(&cfg).iter().any(
            |d| d.severity == Severity::Error && d.location == "sessions.unidentified.profile"
        ));

        cfg.sessions.unidentified =
            Some(Unidentified { profile: Some("p".into()), action: UnidentifiedAction::default() });
        assert!(!validate(&cfg).iter().any(|d| d.severity == Severity::Error));
    }

    #[test]
    fn a_profile_cannot_both_reference_and_embed_transforms() {
        let mut profile = Profile { transforms: Some("shared".into()), ..Default::default() };
        profile.request_transforms.headers = Some(Default::default());
        let cfg = cfg_with(profile);
        assert!(
            validate(&cfg)
                .iter()
                .any(|d| d.severity == Severity::Error && d.location == "profiles.p.transforms")
        );
    }

    #[test]
    fn a_profile_referencing_an_unknown_transform_bundle_is_an_error() {
        let cfg = cfg_with(Profile { transforms: Some("nope".into()), ..Default::default() });
        assert!(
            validate(&cfg)
                .iter()
                .any(|d| d.severity == Severity::Error && d.location == "profiles.p.transforms")
        );
    }
}
