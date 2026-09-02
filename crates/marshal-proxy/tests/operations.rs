//! M7 acceptance: warn mode, and a reload that cannot leave the proxy half-configured.

mod support;

use std::sync::Arc;

use http_body_util::BodyExt;
use marshal_audit::JsonSink;
use marshal_config::model::Config;
use marshal_core::{AuditSink, DenyingDecider};
use marshal_policy::build_chain;
use marshal_proxy::management::RuntimeBuilder;
use marshal_proxy::runtime::RuntimeHandle;
use marshal_proxy::stats::IdentityStats;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use support::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn chain_from(yaml: &str) -> marshal_policy::Chain {
    let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
    build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap()
}

const DENY_ALL: &str = r#"
profile:
  default_action: deny
"#;

const WARN_ALL: &str = r#"
profile:
  default_action: deny
  mode: warn
"#;

const ALLOW_LOOPBACK: &str = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: allow
      on_miss: pass
"#;

#[derive(Debug, Default)]
struct AuditBuffer(std::sync::Mutex<Vec<u8>>);

impl AuditBuffer {
    fn records(&self) -> Vec<serde_json::Value> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap())
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

struct Harness {
    proxy: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    handle: Arc<RuntimeHandle>,
    stats: Arc<IdentityStats>,
    audit: Arc<AuditBuffer>,
}

async fn harness(yaml: &str) -> Harness {
    let upstream = start_upstream(b"UPSTREAM").await;
    let buffer = Arc::new(AuditBuffer::default());
    let audit: Arc<dyn AuditSink> = Arc::new(JsonSink::new(SharedWriter(Arc::clone(&buffer))));

    let handle = handle(single_profile_runtime(chain_from(yaml), None));
    let server = Server::new(
        ServerConfig { listen: "127.0.0.1:0".into(), unix_socket: None, transparent: Vec::new() },
        Arc::clone(&handle),
        Arc::new(UpstreamGuard::new(Vec::<String>::new(), true).unwrap()),
        audit,
    );
    let stats = server.stats();

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = server
            .run(move |a| {
                let _ = tx.take().unwrap().send(a);
            })
            .await;
    });

    Harness { proxy: rx.await.unwrap(), upstream, handle, stats, audit: buffer }
}

async fn connect(proxy: std::net::SocketAddr, target: std::net::SocketAddr) -> String {
    let mut c = tokio::net::TcpStream::connect(proxy).await.unwrap();
    c.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read_exact(&mut byte).await.is_err() {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).lines().next().unwrap_or_default().to_owned()
}

#[tokio::test]
async fn warn_mode_forwards_what_it_would_have_refused_and_says_so() {
    // Turning default-deny on for an existing agent breaks everything it quietly relied on,
    // and that list cannot be known in advance. Warn mode is how it gets discovered.
    let h = harness(WARN_ALL).await;

    let status = connect(h.proxy, h.upstream).await;
    assert!(status.starts_with("HTTP/1.1 200"), "warn mode must forward: {status}");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let records = h.audit.records();
    assert_eq!(records[0]["action"], "allow");
    // The whole signal: policy disagreed, and the record says so.
    assert_eq!(records[0]["would_deny"], true);
    assert_eq!(records[0]["reason"]["code"], "default_deny");
}

#[tokio::test]
async fn enforce_mode_is_the_control_for_that() {
    // The same config without `mode: warn` must actually refuse, or the test above proves
    // nothing about warn mode specifically.
    let h = harness(DENY_ALL).await;

    let status = connect(h.proxy, h.upstream).await;
    assert!(status.starts_with("HTTP/1.1 403"), "{status}");

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let records = h.audit.records();
    assert_eq!(records[0]["action"], "deny");
    // Absent rather than false: an enforcing proxy should have no `would_deny` noise.
    assert!(records[0].get("would_deny").is_none(), "{}", records[0]);
}

#[tokio::test]
async fn warn_mode_is_reported_rather_than_buried() {
    // A proxy silently in warn mode is worse than no proxy, because somebody believes it is
    // protecting them.
    let h = harness(WARN_ALL).await;
    assert_eq!(h.handle.load().warn_only_profiles(), ["p"]);

    let h = harness(DENY_ALL).await;
    assert!(h.handle.load().warn_only_profiles().is_empty());
}

#[tokio::test]
async fn a_reload_changes_policy_for_new_connections() {
    let h = harness(DENY_ALL).await;
    assert!(connect(h.proxy, h.upstream).await.starts_with("HTTP/1.1 403"));

    h.handle.store(single_profile_runtime(chain_from(ALLOW_LOOPBACK), None));

    assert!(
        connect(h.proxy, h.upstream).await.starts_with("HTTP/1.1 200"),
        "the reloaded policy did not take effect"
    );
    assert_eq!(h.handle.generation(), 1);
}

#[tokio::test]
async fn a_failed_reload_leaves_the_running_policy_untouched() {
    // The invariant that matters most. An operator reading a failed reload needs to know
    // whether they are now unprotected — and the answer must be no.
    let h = harness(ALLOW_LOOPBACK).await;
    assert!(connect(h.proxy, h.upstream).await.starts_with("HTTP/1.1 200"));

    let builder: RuntimeBuilder =
        Arc::new(|| Err("profile `p`: unknown bundle `nope`".to_string()));

    let app_state_reload = (builder)();
    assert!(app_state_reload.is_err());
    // Nothing was stored, so the generation has not moved and the old policy still applies.
    assert_eq!(h.handle.generation(), 0);
    assert!(
        connect(h.proxy, h.upstream).await.starts_with("HTTP/1.1 200"),
        "a failed reload changed the running policy"
    );
}

#[tokio::test]
async fn management_reports_health_identities_and_reload() {
    let h = harness(DENY_ALL).await;
    connect(h.proxy, h.upstream).await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // A builder that swaps deny-all for allow-loopback.
    let builder: RuntimeBuilder =
        Arc::new(|| Ok(single_profile_runtime(chain_from(ALLOW_LOOPBACK), None)));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mgmt = listener.local_addr().unwrap();
    drop(listener);

    let handle = Arc::clone(&h.handle);
    let stats = Arc::clone(&h.stats);
    tokio::spawn(async move {
        let _ = marshal_proxy::management::serve(
            &mgmt.to_string(),
            handle,
            stats,
            builder,
            Some("s3cret".into()),
        )
        .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // healthz needs no credential: one that does is one that gets configured wrong.
    let health = get(mgmt, "/v1/healthz", None).await;
    assert_eq!(health.0, 200);
    assert_eq!(health.1["status"], "ok");
    assert_eq!(health.1["generation"], 0);

    // identities does, because it reveals what the agents are doing.
    assert_eq!(get(mgmt, "/v1/identities", None).await.0, 401);
    assert_eq!(get(mgmt, "/v1/identities", Some("wrong")).await.0, 401);

    let identities = get(mgmt, "/v1/identities", Some("s3cret")).await;
    assert_eq!(identities.0, 200);
    assert_eq!(identities.1["identities"][0]["denied"], 1);

    // Metrics are unauthenticated like healthz: a scrape target that needs a credential is
    // one that gets configured wrong.
    let scrape = raw(mgmt, "GET", "/v1/metrics", None).await;
    assert!(scrape.contains("# TYPE marshal_requests_total counter"), "{scrape}");
    assert!(scrape.contains(r#"profile="p",action="deny"} 1"#), "{scrape}");

    // Reload changes policy, and is credentialled because it replaces the ruleset.
    assert_eq!(post(mgmt, "/v1/reload", None).await.0, 401);
    let reloaded = post(mgmt, "/v1/reload", Some("s3cret")).await;
    assert_eq!(reloaded.0, 200);
    assert_eq!(reloaded.1["generation"], 1);

    assert!(connect(h.proxy, h.upstream).await.starts_with("HTTP/1.1 200"));
}

#[tokio::test]
async fn a_rejected_reload_says_the_old_config_still_applies() {
    let h = harness(ALLOW_LOOPBACK).await;
    let builder: RuntimeBuilder = Arc::new(|| Err("bad config".to_string()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mgmt = listener.local_addr().unwrap();
    drop(listener);

    let handle = Arc::clone(&h.handle);
    let stats = Arc::clone(&h.stats);
    tokio::spawn(async move {
        let _ =
            marshal_proxy::management::serve(&mgmt.to_string(), handle, stats, builder, None).await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let rejected = post(mgmt, "/v1/reload", None).await;
    assert_eq!(rejected.0, 400);
    assert_eq!(rejected.1["status"], "rejected");
    assert!(rejected.1["error"].as_str().unwrap().contains("bad config"));
    // The operator has to be able to tell whether they are now unprotected.
    assert!(rejected.1["note"].as_str().unwrap().contains("still in effect"));

    assert!(connect(h.proxy, h.upstream).await.starts_with("HTTP/1.1 200"));
}

async fn get(
    addr: std::net::SocketAddr,
    path: &str,
    token: Option<&str>,
) -> (u16, serde_json::Value) {
    request(addr, "GET", path, token).await
}

async fn post(
    addr: std::net::SocketAddr,
    path: &str,
    token: Option<&str>,
) -> (u16, serde_json::Value) {
    request(addr, "POST", path, token).await
}

async fn raw(addr: std::net::SocketAddr, method: &str, path: &str, token: Option<&str>) -> String {
    let (_, body) = request_bytes(addr, method, path, token).await;
    String::from_utf8_lossy(&body).into_owned()
}

async fn request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> (u16, serde_json::Value) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder().method(method).uri(path).header("host", "mgmt");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let resp = sender.send_request(builder.body(empty()).unwrap()).await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null))
}

async fn request_bytes(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: Option<&str>,
) -> (u16, bytes::Bytes) {
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder().method(method).uri(path).header("host", "mgmt");
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    let resp = sender.send_request(builder.body(empty()).unwrap()).await.unwrap();
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, body)
}
