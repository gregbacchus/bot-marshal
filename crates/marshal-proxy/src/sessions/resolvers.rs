//! The resolver implementations and the chain that runs them.

use std::sync::Arc;

use ipnet::IpNet;
use marshal_core::{ConnInfo, Resolved, SessionId, SessionResolver};

use super::peercred;

/// Maps a source address range to a session.
#[derive(Debug)]
pub struct SourceIpResolver {
    entries: Vec<(IpNet, SessionId, Arc<str>)>,
}

impl SourceIpResolver {
    pub fn new(
        entries: impl IntoIterator<Item = (String, String, String)>,
    ) -> Result<Self, ipnet::AddrParseError> {
        let entries = entries
            .into_iter()
            .map(|(cidr, session, profile)| {
                Ok((cidr.parse::<IpNet>()?, SessionId::new(session), Arc::from(profile.as_str())))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { entries })
    }
}

#[async_trait::async_trait]
impl SessionResolver for SourceIpResolver {
    fn name(&self) -> &str {
        "source_ip"
    }

    async fn resolve(&self, conn: &ConnInfo) -> Option<Resolved> {
        let ip = conn.client_addr.ip();
        self.entries.iter().find(|(net, _, _)| net.contains(&ip)).map(|(_, session, profile)| {
            Resolved {
                session: session.clone(),
                profile: Arc::clone(profile),
                attributed: true,
                resolver: Some("source_ip".into()),
            }
        })
    }
}

/// Maps a kernel-supplied uid or gid, or an enriched cgroup path, to a session.
#[derive(Debug)]
pub struct PeerCredResolver {
    uids: Vec<(u32, SessionId, Arc<str>)>,
    gids: Vec<(u32, SessionId, Arc<str>)>,
    cgroups: Vec<(globset::GlobMatcher, SessionId, Arc<str>)>,
}

impl PeerCredResolver {
    pub fn new(
        uids: impl IntoIterator<Item = (u32, String, String)>,
        gids: impl IntoIterator<Item = (u32, String, String)>,
        cgroups: impl IntoIterator<Item = (String, String, String)>,
    ) -> Result<Self, globset::Error> {
        Ok(Self {
            uids: uids
                .into_iter()
                .map(|(uid, s, p)| (uid, SessionId::new(s), Arc::from(p.as_str())))
                .collect(),
            gids: gids
                .into_iter()
                .map(|(gid, s, p)| (gid, SessionId::new(s), Arc::from(p.as_str())))
                .collect(),
            cgroups: cgroups
                .into_iter()
                .map(|(pattern, s, p)| {
                    Ok((
                        globset::Glob::new(&pattern)?.compile_matcher(),
                        SessionId::new(s),
                        Arc::from(p.as_str()),
                    ))
                })
                .collect::<Result<Vec<_>, globset::Error>>()?,
        })
    }

    /// Whether any entry needs pid/cgroup enrichment, which costs a `/proc` walk.
    pub fn needs_enrichment(&self) -> bool {
        !self.cgroups.is_empty()
    }
}

#[async_trait::async_trait]
impl SessionResolver for PeerCredResolver {
    fn name(&self) -> &str {
        "peer_cred"
    }

    async fn resolve(&self, conn: &ConnInfo) -> Option<Resolved> {
        let cred = conn.peer_cred.as_ref()?;

        // Uid first: it names exactly one user. Gid next: still kernel-supplied, but several
        // uids can share it, so it's the weaker of the two exact-match kinds. Cgroup last —
        // strong against a prompt-injected agent, not against one that moves itself between
        // delegated cgroups.
        if let Some(uid) = cred.uid
            && let Some((_, session, profile)) = self.uids.iter().find(|(u, _, _)| *u == uid)
        {
            return Some(Resolved {
                session: session.clone(),
                profile: Arc::clone(profile),
                attributed: true,
                resolver: Some("peer_cred:uid".into()),
            });
        }

        if let Some(gid) = cred.gid
            && let Some((_, session, profile)) = self.gids.iter().find(|(g, _, _)| *g == gid)
        {
            return Some(Resolved {
                session: session.clone(),
                profile: Arc::clone(profile),
                attributed: true,
                resolver: Some("peer_cred:gid".into()),
            });
        }

        if let Some(cgroup) = &cred.cgroup
            && let Some((_, session, profile)) =
                self.cgroups.iter().find(|(m, _, _)| m.is_match(cgroup))
        {
            return Some(Resolved {
                session: session.clone(),
                profile: Arc::clone(profile),
                attributed: true,
                resolver: Some("peer_cred:cgroup".into()),
            });
        }

        None
    }
}

/// Maps the port a connection arrived on to a session.
///
/// The fallback for agents that share a uid. nftables steers each identity to a different
/// port — `meta skuid 1001 ... redirect to :8081` — so the accepting listener *is* the
/// identity.
///
/// Weaker than it looks: it only holds if the agent cannot reach the other ports directly.
/// The shipped ruleset drops direct connections to them, and without that an agent picks its
/// own profile by choosing a port.
#[derive(Debug)]
pub struct ListenerPortResolver {
    entries: Vec<(u16, SessionId, Arc<str>)>,
}

impl ListenerPortResolver {
    pub fn new(entries: impl IntoIterator<Item = (u16, String, String)>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(port, s, p)| (port, SessionId::new(s), Arc::from(p.as_str())))
                .collect(),
        }
    }
}

#[async_trait::async_trait]
impl SessionResolver for ListenerPortResolver {
    fn name(&self) -> &str {
        "listener_port"
    }

    async fn resolve(&self, conn: &ConnInfo) -> Option<Resolved> {
        let port = conn.local_addr.port();
        self.entries.iter().find(|(p, _, _)| *p == port).map(|(_, session, profile)| Resolved {
            session: session.clone(),
            profile: Arc::clone(profile),
            attributed: true,
            resolver: Some("listener_port".into()),
        })
    }
}

/// Matches a `Proxy-Authorization` credential, or a SOCKS5 username/password.
///
/// Client-asserted, so it is only as strong as the secret. Listed last in the shipped config
/// for that reason.
pub struct ProxyAuthResolver {
    entries: Vec<(String, String, SessionId, Arc<str>)>,
}

impl std::fmt::Debug for ProxyAuthResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyAuthResolver").field("credentials", &self.entries.len()).finish()
    }
}

impl ProxyAuthResolver {
    pub fn new(entries: impl IntoIterator<Item = (String, String, String, String)>) -> Self {
        Self {
            entries: entries
                .into_iter()
                .map(|(u, p, s, prof)| (u, p, SessionId::new(s), Arc::from(prof.as_str())))
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[async_trait::async_trait]
impl SessionResolver for ProxyAuthResolver {
    fn name(&self) -> &str {
        "proxy_auth"
    }

    async fn resolve(&self, conn: &ConnInfo) -> Option<Resolved> {
        let cred = conn.proxy_auth.as_ref()?;
        // Compared in constant time so a wrong password cannot be recovered by timing. The
        // credential is weak enough already without adding an oracle.
        self.entries
            .iter()
            .find(|(u, p, _, _)| *u == cred.user && constant_time_eq(p, &cred.password))
            .map(|(_, _, session, profile)| Resolved {
                session: session.clone(),
                profile: Arc::clone(profile),
                attributed: true,
                resolver: Some("proxy_auth".into()),
            })
    }
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The `Resolved.profile` label used for audit/display when the fallback is the base
/// config's embedded `profile:` rather than a named override — it has no real name, and this
/// is never used as a lookup key (see [`SessionRegistry::uses_default_fallback`]).
pub const DEFAULT_PROFILE_LABEL: &str = "default";

/// Runs resolvers in order and falls back to an explicitly unattributed session.
pub struct SessionRegistry {
    resolvers: Vec<Arc<dyn SessionResolver>>,
    /// `None` means the fallback is the base config's embedded, unnamed `profile:` — the
    /// runtime keeps that chain separately rather than in the name-keyed map, since it has
    /// nothing to be keyed by. `Some(name)` means `sessions.unidentified.profile` explicitly
    /// named one of the profiles under `profiles_path` instead.
    fallback_profile: Option<Arc<str>>,
    /// Refuse anything that cannot be attributed, rather than serving it under the fallback.
    deny_unidentified: bool,
    /// Whether any resolver needs `/proc` enrichment.
    enrich: bool,
}

impl std::fmt::Debug for SessionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionRegistry")
            .field("resolvers", &self.resolvers.iter().map(|r| r.name()).collect::<Vec<_>>())
            .field("fallback_profile", &self.fallback_profile)
            .field("deny_unidentified", &self.deny_unidentified)
            .finish()
    }
}

impl SessionRegistry {
    pub fn new(
        resolvers: Vec<Arc<dyn SessionResolver>>,
        fallback_profile: Option<Arc<str>>,
        deny_unidentified: bool,
        enrich: bool,
    ) -> Self {
        Self { resolvers, fallback_profile, deny_unidentified, enrich }
    }

    pub fn needs_enrichment(&self) -> bool {
        self.enrich
    }

    pub fn deny_unidentified(&self) -> bool {
        self.deny_unidentified
    }

    /// Whether an unattributed connection should use the runtime's embedded default chain
    /// rather than a named one in `runtime.chains`.
    pub fn uses_default_fallback(&self) -> bool {
        self.fallback_profile.is_none()
    }

    pub fn resolver_names(&self) -> Vec<&str> {
        self.resolvers.iter().map(|r| r.name()).collect()
    }

    /// Attach kernel credentials to `conn` where the transport can supply them.
    pub fn attach_peer_cred(&self, conn: &mut ConnInfo) {
        if conn.peer_cred.is_some() {
            return;
        }
        conn.peer_cred = peercred::peer_cred_for_tcp(conn.client_addr, self.enrich);
    }

    /// First match wins; otherwise an explicitly unattributed session.
    pub async fn resolve(&self, conn: &ConnInfo) -> Resolved {
        for resolver in &self.resolvers {
            if let Some(found) = resolver.resolve(conn).await {
                return found;
            }
        }
        Resolved {
            session: SessionId::unidentified(),
            profile: self
                .fallback_profile
                .clone()
                .unwrap_or_else(|| Arc::from(DEFAULT_PROFILE_LABEL)),
            // Saying so is the point: an unattributed request must never look like an
            // attributed one in the audit trail.
            attributed: false,
            resolver: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use marshal_core::{Credential, IngressMode, PeerCred};

    fn conn() -> ConnInfo {
        ConnInfo {
            ingress: IngressMode::Explicit,
            client_addr: "127.0.0.1:5000".parse().unwrap(),
            local_addr: "127.0.0.1:8080".parse().unwrap(),
            proxy_auth: None,
            peer_cred: None,
        }
    }

    #[tokio::test]
    async fn source_ip_matches_a_range() {
        let r = SourceIpResolver::new([(
            "172.20.0.0/24".to_string(),
            "agent-a".to_string(),
            "coding".to_string(),
        )])
        .unwrap();

        let mut c = conn();
        c.client_addr = "172.20.0.7:1234".parse().unwrap();
        let got = r.resolve(&c).await.unwrap();
        assert_eq!(got.session.to_string(), "agent-a");
        assert_eq!(&*got.profile, "coding");

        c.client_addr = "10.0.0.1:1234".parse().unwrap();
        assert!(r.resolve(&c).await.is_none());
    }

    #[tokio::test]
    async fn peer_cred_prefers_uid_over_cgroup() {
        let r = PeerCredResolver::new(
            [(1001, "by-uid".to_string(), "p-uid".to_string())],
            [],
            [("*/agent.scope".to_string(), "by-cgroup".to_string(), "p-cg".to_string())],
        )
        .unwrap();

        let mut c = conn();
        c.peer_cred = Some(PeerCred {
            uid: Some(1001),
            cgroup: Some("/user.slice/agent.scope".into()),
            ..Default::default()
        });
        // Uid is the part the kernel guarantees, so it wins.
        assert_eq!(r.resolve(&c).await.unwrap().session.to_string(), "by-uid");

        c.peer_cred = Some(PeerCred {
            uid: Some(9999),
            cgroup: Some("/user.slice/agent.scope".into()),
            ..Default::default()
        });
        assert_eq!(r.resolve(&c).await.unwrap().session.to_string(), "by-cgroup");
    }

    #[tokio::test]
    async fn listener_port_identifies_by_the_accepting_socket() {
        let r = ListenerPortResolver::new([(8081, "agent-a".to_string(), "coding".to_string())]);

        let mut c = conn();
        c.local_addr = "127.0.0.1:8081".parse().unwrap();
        assert_eq!(r.resolve(&c).await.unwrap().session.to_string(), "agent-a");

        c.local_addr = "127.0.0.1:8082".parse().unwrap();
        assert!(r.resolve(&c).await.is_none());
    }

    #[tokio::test]
    async fn proxy_auth_requires_both_user_and_password() {
        let r = ProxyAuthResolver::new([(
            "agent-a".to_string(),
            "hunter2".to_string(),
            "s".to_string(),
            "p".to_string(),
        )]);

        let mut c = conn();
        c.proxy_auth = Some(Credential { user: "agent-a".into(), password: "hunter2".into() });
        assert!(r.resolve(&c).await.is_some());

        c.proxy_auth = Some(Credential { user: "agent-a".into(), password: "wrong".into() });
        assert!(r.resolve(&c).await.is_none());

        c.proxy_auth = Some(Credential { user: "other".into(), password: "hunter2".into() });
        assert!(r.resolve(&c).await.is_none());
    }

    #[tokio::test]
    async fn unmatched_connections_are_explicitly_unattributed() {
        let registry = SessionRegistry::new(
            vec![Arc::new(
                SourceIpResolver::new([(
                    "172.20.0.0/24".to_string(),
                    "a".to_string(),
                    "p".to_string(),
                )])
                .unwrap(),
            )],
            Some(Arc::from("restricted")),
            false,
            false,
        );

        let got = registry.resolve(&conn()).await;
        assert!(!got.attributed, "an unmatched connection must not look attributed");
        assert_eq!(got.session.to_string(), "unidentified");
        assert_eq!(&*got.profile, "restricted");
        assert!(got.resolver.is_none());
    }

    #[tokio::test]
    async fn resolvers_are_tried_in_order() {
        let registry = SessionRegistry::new(
            vec![
                Arc::new(
                    SourceIpResolver::new([(
                        "127.0.0.1/32".to_string(),
                        "first".to_string(),
                        "p1".to_string(),
                    )])
                    .unwrap(),
                ),
                Arc::new(
                    SourceIpResolver::new([(
                        "127.0.0.1/32".to_string(),
                        "second".to_string(),
                        "p2".to_string(),
                    )])
                    .unwrap(),
                ),
            ],
            Some(Arc::from("fallback")),
            false,
            false,
        );
        assert_eq!(registry.resolve(&conn()).await.session.to_string(), "first");
    }

    #[test]
    fn constant_time_compare_is_correct() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
    }
}
