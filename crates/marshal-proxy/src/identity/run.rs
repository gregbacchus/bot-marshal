//! Identity for agents started by `marshal run`.
//!
//! The naming convention *is* the registration. `marshal run --profile coding-agent` places
//! the agent in a cgroup named `marshal-coding-agent-<pid>.scope`, and this resolver reads the
//! identity and profile back out of that name. No control socket, no shared state, and nothing
//! to get out of sync if the proxy restarts.
//!
//! Identity and profile are separate axes. The pid is the identity; the profile segment is
//! optional, and `marshal run` without `--profile` produces `marshal-<pid>.scope` — still a
//! fully attributed identity, governed by the embedded `profile:` because no profile was
//! named, exactly as omitting `--profile` says.
//!
//! The property that makes it work for real agents is cgroup inheritance: a coding agent's
//! egress overwhelmingly comes from spawned `git`, `npm` and `curl` processes rather than the
//! agent itself, and those inherit the scope automatically.
//!
//! It requires `enrich` — reading the cgroup means walking `/proc` to find the owning pid —
//! and it is strong against a prompt-injected agent rather than against one deliberately
//! impersonating another profile, since a process can move itself between delegated cgroups.

use std::collections::HashSet;
use std::sync::Arc;

use marshal_core::{ConnInfo, Identity, IdentityResolver, Resolved};

/// The scope-name prefix `marshal run` uses.
pub const SCOPE_PREFIX: &str = "marshal-";

#[derive(Debug)]
pub struct RunResolver {
    /// Profiles that exist. A cgroup naming a profile the config does not define is ignored
    /// rather than trusted, so a stale scope cannot conjure a profile into being.
    known_profiles: HashSet<String>,
}

impl RunResolver {
    pub fn new(known_profiles: impl IntoIterator<Item = String>) -> Self {
        Self { known_profiles: known_profiles.into_iter().collect() }
    }
}

/// Pull `(identity, profile)` out of a cgroup path containing a `marshal-[<profile>-]<pid>.scope`
/// component. `None` for the profile means none was named, so the embedded `profile:` applies.
pub fn parse_scope(cgroup: &str) -> Option<(String, Option<String>)> {
    let scope =
        cgroup.split('/').rev().find(|c| c.starts_with(SCOPE_PREFIX) && c.ends_with(".scope"))?;

    let body = scope.strip_prefix(SCOPE_PREFIX)?.strip_suffix(".scope")?;
    // The pid is the final `-`-separated component; anything before it is the profile, so a
    // profile name containing a hyphen survives. A body that is nothing but the pid is the
    // no-`--profile` form — unambiguous, because a profile segment is never empty.
    let (profile, pid) = match body.rsplit_once('-') {
        Some((profile, pid)) if !profile.is_empty() => (Some(profile.to_owned()), pid),
        Some(_) => return None,
        None => (None, body),
    };
    if pid.is_empty() || !pid.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((format!("pid-{pid}"), profile))
}

#[async_trait::async_trait]
impl IdentityResolver for RunResolver {
    fn name(&self) -> &str {
        "run"
    }

    async fn resolve(&self, conn: &ConnInfo) -> Option<Resolved> {
        let cgroup = conn.peer_cred.as_ref()?.cgroup.as_ref()?;
        let (identity, profile) = parse_scope(cgroup)?;
        let profile = match profile {
            Some(profile) if !self.known_profiles.contains(&profile) => {
                tracing::warn!(
                    %profile,
                    "a run scope named a profile that is not configured; ignoring it"
                );
                return None;
            }
            Some(profile) => Some(Arc::from(profile.as_str())),
            None => None,
        };
        Some(Resolved {
            identity: Identity::new(identity),
            profile,
            attributed: true,
            resolver: Some("run".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marshal_core::{IngressMode, PeerCred};

    #[test]
    fn parses_a_scope_out_of_a_cgroup_path() {
        let (identity, profile) = parse_scope(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/marshal-coding-agent-4821.scope",
        )
        .unwrap();
        assert_eq!(profile.as_deref(), Some("coding-agent"), "a hyphenated name must survive");
        assert_eq!(identity, "pid-4821", "the pid is the identity; the profile is not");
    }

    #[test]
    fn a_scope_with_no_profile_segment_is_still_an_identity() {
        let (identity, profile) = parse_scope("0::/user.slice/marshal-4821.scope").unwrap();
        assert_eq!(identity, "pid-4821");
        assert_eq!(profile, None, "no `--profile` means the embedded profile applies");
    }

    #[test]
    fn ignores_unrelated_cgroups() {
        assert!(parse_scope("0::/user.slice/user-1000.slice").is_none());
        assert!(parse_scope("0::/app.slice/app-com.anthropic.Claude-12286.scope").is_none());
        assert!(parse_scope("").is_none());
        assert!(parse_scope("marshal-.scope").is_none());
        assert!(parse_scope("marshal-noid.scope").is_none(), "the pid must be numeric");
        assert!(parse_scope("marshal-profile-.scope").is_none());
    }

    #[tokio::test]
    async fn a_scope_naming_an_unknown_profile_is_not_trusted() {
        let r = RunResolver::new(["coding-agent".to_string()]);
        let conn = |cgroup: &str| ConnInfo {
            ingress: IngressMode::Explicit,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            local_addr: "127.0.0.1:2".parse().unwrap(),
            proxy_auth: None,
            peer_cred: Some(PeerCred { cgroup: Some(cgroup.to_string()), ..Default::default() }),
        };

        let named = r.resolve(&conn("0::/marshal-coding-agent-1.scope")).await.unwrap();
        assert_eq!(named.profile.as_deref(), Some("coding-agent"));

        // No profile named: attributed all the same, governed by the embedded `profile:`.
        let unnamed = r.resolve(&conn("0::/marshal-1.scope")).await.unwrap();
        assert!(unnamed.attributed);
        assert_eq!(unnamed.identity.to_string(), "pid-1");
        assert_eq!(unnamed.profile, None);

        // A stale or hostile scope must not conjure a profile into existence.
        assert!(r.resolve(&conn("0::/marshal-admin-1.scope")).await.is_none());
    }
}
