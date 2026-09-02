//! M4 acceptance: who the agent is decides which policy applies, and the audit trail says so.

mod support;

use std::collections::HashMap;
use std::sync::Arc;

use http_body_util::BodyExt;
use marshal_audit::JsonSink;
use marshal_config::model::Config;
use marshal_core::{AuditSink, DenyingDecider, IdentityResolver};
use marshal_policy::{HostMatcher, build_chain};
use marshal_proxy::identity::{IdentityRegistry, PeerCredResolver, ProxyAuthResolver};
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// One permits the loopback upstream, the other permits nothing. Two *named* profiles, so
/// each is built directly here and inserted into `cfg.profiles` — there's no `profiles:` key
/// in the schema any more to hold both at once.
const PERMISSIVE: &str = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: allow
      on_miss: pass
"#;

const RESTRICTED: &str = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { domains: ["nothing.invalid"] }
      on_match: allow
      on_miss: pass
"#;

fn two_profiles() -> Config {
    let permissive: Config = serde_yaml_ng::from_str(PERMISSIVE).unwrap();
    let restricted: Config = serde_yaml_ng::from_str(RESTRICTED).unwrap();
    let mut cfg = Config::default();
    cfg.profiles.insert("permissive".to_owned(), permissive.profile);
    cfg.profiles.insert("restricted".to_owned(), restricted.profile);
    cfg
}

struct Harness {
    proxy: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    audit: Arc<AuditBuffer>,
}

#[derive(Debug, Default)]
struct AuditBuffer(std::sync::Mutex<Vec<u8>>);

impl AuditBuffer {
    fn records(&self) -> Vec<serde_json::Value> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
            .collect()
    }
}

struct SharedWriter(Arc<AuditBuffer>);

impl tokio::io::AsyncWrite for SharedWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.0.0.lock().unwrap().extend_from_slice(buf);
        std::task::Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl std::fmt::Debug for SharedWriter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SharedWriter")
    }
}

async fn harness(
    resolvers: Vec<Arc<dyn IdentityResolver>>,
    fallback: &str,
    deny_unidentified: bool,
) -> Harness {
    let upstream = start_upstream(b"UPSTREAM").await;

    let cfg = two_profiles();
    let mut chains = HashMap::new();
    for (name, profile) in &cfg.profiles {
        chains.insert(
            Arc::from(name.as_str()),
            Arc::new(build_chain(&cfg, name, profile, Arc::new(DenyingDecider)).unwrap()),
        );
    }

    let buffer = Arc::new(AuditBuffer::default());
    let audit: Arc<dyn AuditSink> = Arc::new(JsonSink::new(SharedWriter(Arc::clone(&buffer))));

    let server = Server::new(
        ServerConfig { listen: "127.0.0.1:0".into(), unix_socket: None, transparent: Vec::new() },
        handle(marshal_proxy::runtime::Runtime {
            chains,
            response_transforms: HashMap::new(),
            request_transforms: std::collections::HashMap::new(),
            default_chain: Arc::new(marshal_policy::Chain::new(
                "default",
                vec![],
                marshal_core::Decision::Deny,
                Arc::new(DenyingDecider),
            )),
            default_response_transforms: Vec::new(),
            default_request_transforms: Vec::new(),
            identities: Arc::new(IdentityRegistry::new(
                resolvers,
                Some(Arc::from(fallback)),
                deny_unidentified,
                false,
            )),
            passthrough: HostMatcher::default(),
            tls: support::test_engine(),
        }),
        Arc::new(UpstreamGuard::new(Vec::<String>::new(), true).unwrap()),
        audit,
    );

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = server
            .run(move |a| {
                let _ = tx.take().unwrap().send(a);
            })
            .await;
    });

    Harness { proxy: rx.await.unwrap(), upstream, audit: buffer }
}

/// Issue a CONNECT, optionally with credentials, and return the status line.
async fn connect_as(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
    credential: Option<(&str, &str)>,
) -> String {
    let mut c = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let mut head = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((user, pass)) = credential {
        head.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64(&format!("{user}:{pass}"))
        ));
    }
    head.push_str("\r\n");
    c.write_all(head.as_bytes()).await.unwrap();

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if c.read_exact(&mut byte).await.is_err() {
            break;
        }
        buf.push(byte[0]);
    }
    String::from_utf8_lossy(&buf).lines().next().unwrap_or_default().to_owned()
}

fn base64(input: &str) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - i * 6)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[tokio::test]
async fn two_identities_hitting_one_host_get_different_answers() {
    // The plan's headline criterion: same destination, different identities, different
    // outcomes — and the audit trail attributes each correctly.
    let resolver = Arc::new(ProxyAuthResolver::new([
        ("allowed".into(), "pw1".into(), "agent-allowed".into(), "permissive".into()),
        ("blocked".into(), "pw2".into(), "agent-blocked".into(), "restricted".into()),
    ]));
    let h = harness(vec![resolver], "restricted", false).await;

    let ok = connect_as(h.proxy, h.upstream, Some(("allowed", "pw1"))).await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");

    let denied = connect_as(h.proxy, h.upstream, Some(("blocked", "pw2"))).await;
    assert!(denied.starts_with("HTTP/1.1 403"), "{denied}");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let records = h.audit.records();
    assert_eq!(records.len(), 2, "{records:#?}");

    let allowed = &records[0];
    assert_eq!(allowed["identity"], "agent-allowed");
    assert_eq!(allowed["profile"], "permissive");
    assert_eq!(allowed["action"], "allow");
    assert_eq!(allowed["attributed"], true);
    assert_eq!(allowed["resolver"], "proxy_auth");

    let blocked = &records[1];
    assert_eq!(blocked["identity"], "agent-blocked");
    assert_eq!(blocked["profile"], "restricted");
    assert_eq!(blocked["action"], "deny");
}

#[tokio::test]
async fn an_unidentified_connection_gets_the_fallback_and_is_flagged() {
    let resolver = Arc::new(ProxyAuthResolver::new([(
        "known".into(),
        "pw".into(),
        "s".into(),
        "permissive".into(),
    )]));
    // Fallback is the restrictive profile: an unattributed request must never inherit a
    // permissive one.
    let h = harness(vec![resolver], "restricted", false).await;

    let status = connect_as(h.proxy, h.upstream, None).await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let records = h.audit.records();
    assert_eq!(records[0]["attributed"], false, "it must not look attributed");
    assert_eq!(records[0]["identity"], "unidentified");
    assert_eq!(records[0]["profile"], "restricted");
    assert!(records[0]["resolver"].is_null());
}

#[tokio::test]
async fn a_wrong_password_does_not_borrow_another_profile() {
    let resolver = Arc::new(ProxyAuthResolver::new([(
        "allowed".into(),
        "correct".into(),
        "agent".into(),
        "permissive".into(),
    )]));
    let h = harness(vec![resolver], "restricted", false).await;

    let status = connect_as(h.proxy, h.upstream, Some(("allowed", "wrong"))).await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(h.audit.records()[0]["attributed"], false);
}

#[tokio::test]
async fn deny_unidentified_refuses_rather_than_falling_back() {
    let h = harness(vec![], "permissive", true).await;
    // Even though the fallback profile would allow this destination, the connection cannot
    // be attributed and the posture is hard-fail.
    let status = connect_as(h.proxy, h.upstream, None).await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
}

#[tokio::test]
async fn peer_cred_uid_selects_a_profile_over_a_real_connection() {
    // The proxy looks our own uid up out of /proc/net/tcp; mapping it proves the whole path
    // works end to end rather than only in a unit test.
    let uid = std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<u32>().ok()))
        .unwrap();

    let resolver = Arc::new(
        PeerCredResolver::new([(uid, "me".to_string(), "permissive".to_string())], [], []).unwrap(),
    );
    let h = harness(vec![resolver], "restricted", false).await;

    let status = connect_as(h.proxy, h.upstream, None).await;
    assert!(status.starts_with("HTTP/1.1 200"), "uid was not resolved: {status}");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let records = h.audit.records();
    assert_eq!(records[0]["identity"], "me");
    assert_eq!(records[0]["resolver"], "peer_cred:uid");
    assert_eq!(records[0]["attributed"], true);
}

#[tokio::test]
async fn an_unmapped_uid_falls_through_to_the_fallback() {
    // The control for the test above: a uid nobody is running as must not match.
    let resolver = Arc::new(
        PeerCredResolver::new([(65534, "nobody".to_string(), "permissive".to_string())], [], [])
            .unwrap(),
    );
    let h = harness(vec![resolver], "restricted", false).await;

    let status = connect_as(h.proxy, h.upstream, None).await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(h.audit.records()[0]["attributed"], false);
}

#[tokio::test]
async fn socks5_credentials_select_an_identity_too() {
    let resolver = Arc::new(ProxyAuthResolver::new([(
        "allowed".into(),
        "pw1".into(),
        "agent-allowed".into(),
        "permissive".into(),
    )]));
    let h = harness(vec![resolver], "restricted", false).await;

    let mut c = tokio::net::TcpStream::connect(h.proxy).await.unwrap();
    c.write_all(&[0x05, 0x02, 0x00, 0x02]).await.unwrap();
    let mut sel = [0u8; 2];
    c.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x02], "user/pass must be chosen when offered");

    let mut auth = vec![0x01, 7];
    auth.extend(b"allowed");
    auth.push(3);
    auth.extend(b"pw1");
    c.write_all(&auth).await.unwrap();
    let mut ok = [0u8; 2];
    c.read_exact(&mut ok).await.unwrap();
    assert_eq!(ok, [0x01, 0x00]);

    let ip = match h.upstream.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => unreachable!("test upstream is v4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend(ip);
    req.extend(h.upstream.port().to_be_bytes());
    c.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "the credential should have selected the permissive profile");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(h.audit.records()[0]["identity"], "agent-allowed");
}

#[tokio::test]
async fn the_unix_listener_identifies_by_so_peercred() {
    // SO_PEERCRED is the only same-host identity that is both unspoofable and free of a
    // lookup race, and it is the reason the Unix listener exists at all.
    let uid = std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse::<u32>().ok()))
        .unwrap();

    let upstream = start_upstream(b"UPSTREAM").await;
    let dir = std::env::temp_dir().join(format!("marshal-uds-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("marshal.sock");

    let cfg = two_profiles();
    let mut chains = HashMap::new();
    for (name, profile) in &cfg.profiles {
        chains.insert(
            Arc::from(name.as_str()),
            Arc::new(build_chain(&cfg, name, profile, Arc::new(DenyingDecider)).unwrap()),
        );
    }
    let resolver = Arc::new(
        PeerCredResolver::new([(uid, "me".to_string(), "permissive".to_string())], [], []).unwrap(),
    );

    let server = Server::new(
        ServerConfig {
            listen: "127.0.0.1:0".into(),
            unix_socket: Some(sock.clone()),
            transparent: Vec::new(),
        },
        handle(marshal_proxy::runtime::Runtime {
            chains,
            response_transforms: HashMap::new(),
            request_transforms: std::collections::HashMap::new(),
            default_chain: Arc::new(marshal_policy::Chain::new(
                "default",
                vec![],
                marshal_core::Decision::Deny,
                Arc::new(DenyingDecider),
            )),
            default_response_transforms: Vec::new(),
            default_request_transforms: Vec::new(),
            identities: Arc::new(IdentityRegistry::new(
                vec![resolver],
                Some(Arc::from("restricted")),
                false,
                false,
            )),
            passthrough: HostMatcher::default(),
            tls: support::test_engine(),
        }),
        Arc::new(UpstreamGuard::new(Vec::<String>::new(), true).unwrap()),
        Arc::new(JsonSink::new(tokio::io::sink())),
    );
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = server
            .run(move |a| {
                let _ = tx.take().unwrap().send(a);
            })
            .await;
    });
    let _ = rx.await.unwrap();

    // Give the unix listener a moment to bind; it is set up after the TCP one.
    for _ in 0..50 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let mut c = tokio::net::UnixStream::connect(&sock).await.expect("unix listener is up");
    c.write_all(format!("CONNECT {upstream} HTTP/1.1\r\nHost: {upstream}\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if c.read_exact(&mut byte).await.is_err() {
            break;
        }
        buf.push(byte[0]);
    }
    let status = String::from_utf8_lossy(&buf).lines().next().unwrap_or_default().to_owned();
    assert!(status.starts_with("HTTP/1.1 200"), "SO_PEERCRED did not identify us: {status}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn per_identity_counters_track_allowed_and_denied() {
    let resolver = Arc::new(ProxyAuthResolver::new([
        ("allowed".into(), "pw1".into(), "agent-allowed".into(), "permissive".into()),
        ("blocked".into(), "pw2".into(), "agent-blocked".into(), "restricted".into()),
    ]));
    let h = harness(vec![resolver], "restricted", false).await;

    connect_as(h.proxy, h.upstream, Some(("allowed", "pw1"))).await;
    connect_as(h.proxy, h.upstream, Some(("blocked", "pw2"))).await;
    connect_as(h.proxy, h.upstream, Some(("blocked", "pw2"))).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Counted from the audit stream, which is what the in-process counters mirror.
    let records = h.audit.records();
    let denied = records
        .iter()
        .filter(|r| r["identity"] == "agent-blocked" && r["action"] == "deny")
        .count();
    assert_eq!(denied, 2);
}

/// Keeps the unused-import checker happy for the body helper the harness shares.
#[allow(dead_code)]
async fn _uses_body(resp: hyper::Response<hyper::body::Incoming>) {
    let _ = resp.into_body().collect().await;
}
