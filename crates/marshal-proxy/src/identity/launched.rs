//! Identity for agents started by `marshal run`.
//!
//! The naming convention *is* the registration. `marshal run --profile coding-agent` places
//! the agent in a cgroup named `marshal-coding-agent-<id>.scope`, and this resolver reads the
//! profile and identity back out of that name. No control socket, no shared state, and nothing
//! to get out of sync if the proxy restarts.
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
pub struct LaunchedResolver {
    /// Profiles that exist. A cgroup naming a profile the config does not define is ignored
    /// rather than trusted, so a stale scope cannot conjure a profile into being.
    known_profiles: HashSet<String>,
}

impl LaunchedResolver {
    pub fn new(known_profiles: impl IntoIterator<Item = String>) -> Self {
        Self { known_profiles: known_profiles.into_iter().collect() }
    }
}

/// Pull `(profile, identity)` out of a cgroup path containing a `marshal-<profile>-<id>.scope`
/// component.
pub fn parse_scope(cgroup: &str) -> Option<(String, String)> {
    let scope =
        cgroup.split('/').rev().find(|c| c.starts_with(SCOPE_PREFIX) && c.ends_with(".scope"))?;

    let body = scope.strip_prefix(SCOPE_PREFIX)?.strip_suffix(".scope")?;
    // The id is the final `-`-separated component; the profile is everything before it, so a
    // profile name containing a hyphen survives.
    let (profile, id) = body.rsplit_once('-')?;
    if profile.is_empty() || id.is_empty() {
        return None;
    }
    Some((profile.to_owned(), format!("{profile}-{id}")))
}

#[async_trait::async_trait]
impl IdentityResolver for LaunchedResolver {
    fn name(&self) -> &str {
        "launched"
    }

    async fn resolve(&self, conn: &ConnInfo) -> Option<Resolved> {
        let cgroup = conn.peer_cred.as_ref()?.cgroup.as_ref()?;
        let (profile, identity) = parse_scope(cgroup)?;
        if !self.known_profiles.contains(&profile) {
            tracing::warn!(
                %profile,
                "a launched scope named a profile that is not configured; ignoring it"
            );
            return None;
        }
        Some(Resolved {
            identity: Identity::new(identity),
            profile: Arc::from(profile.as_str()),
            attributed: true,
            resolver: Some("launched".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marshal_core::{IngressMode, PeerCred};

    #[test]
    fn parses_a_scope_out_of_a_cgroup_path() {
        let (profile, identity) = parse_scope(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/marshal-coding-agent-4821.scope",
        )
        .unwrap();
        assert_eq!(profile, "coding-agent", "a hyphenated profile name must survive");
        assert_eq!(identity, "coding-agent-4821");
    }

    #[test]
    fn ignores_unrelated_cgroups() {
        assert!(parse_scope("0::/user.slice/user-1000.slice").is_none());
        assert!(parse_scope("0::/app.slice/app-com.anthropic.Claude-12286.scope").is_none());
        assert!(parse_scope("").is_none());
        assert!(parse_scope("marshal-.scope").is_none());
        assert!(parse_scope("marshal-noid.scope").is_none());
    }

    #[tokio::test]
    async fn a_scope_naming_an_unknown_profile_is_not_trusted() {
        let r = LaunchedResolver::new(["coding-agent".to_string()]);
        let conn = |cgroup: &str| ConnInfo {
            ingress: IngressMode::Explicit,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            local_addr: "127.0.0.1:2".parse().unwrap(),
            proxy_auth: None,
            peer_cred: Some(PeerCred { cgroup: Some(cgroup.to_string()), ..Default::default() }),
        };

        assert!(r.resolve(&conn("0::/marshal-coding-agent-1.scope")).await.is_some());
        // A stale or hostile scope must not conjure a profile into existence.
        assert!(r.resolve(&conn("0::/marshal-admin-1.scope")).await.is_none());
    }
}
