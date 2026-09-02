//! End-to-end tests against a real listener.
//!
//! These drive actual sockets rather than mocking the front-ends, because the properties
//! worth testing here — that nothing upstream is contacted before a verdict, that a denial
//! is legible to the agent, that a CONNECT cannot be laundered into a different host — all
//! live in the interaction between parsing, policy, and the network.

mod support;

use std::sync::Arc;

use marshal_audit::JsonSink;
use marshal_config::model::Config;
use marshal_core::{AuditSink, DenyingDecider};
use marshal_policy::build_chain;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use support::{handle, single_profile_runtime, start_upstream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Start a proxy on an ephemeral port.
///
/// The guard is deliberately opened up here: test upstreams live on loopback, which the
/// shipped defaults block. Those defaults are the guard's own job and are covered by its unit
/// tests; these tests are about the listener and the chain.
async fn start_proxy(yaml: &str, profile: &str) -> std::net::SocketAddr {
    start_proxy_with_guard(yaml, profile, UpstreamGuard::new(Vec::<String>::new(), true).unwrap())
        .await
}

async fn start_proxy_with_guard(
    yaml: &str,
    profile: &str,
    guard: UpstreamGuard,
) -> std::net::SocketAddr {
    let cfg: Config = serde_yaml_ng::from_str(yaml).expect("config parses");
    let chain = build_chain(&cfg, profile, Arc::new(DenyingDecider)).expect("chain builds");
    let audit: Arc<dyn AuditSink> = Arc::new(JsonSink::new(tokio::io::sink()));

    let server = Server::new(
        ServerConfig { listen: "127.0.0.1:0".into(), unix_socket: None, transparent: Vec::new() },
        // `tls: None` here means "passthrough everything": interception is mandatory, but
        // these tests are about the plain-relay path a passthrough host still gets (byte
        // relay plus the SNI cross-check), not about MITM itself — that is tests/mitm.rs.
        handle(single_profile_runtime(chain, None)),
        Arc::new(guard),
        audit,
    );

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = server
            .run(move |addr| {
                let _ = tx.take().expect("called once").send(addr);
            })
            .await;
    });
    rx.await.expect("server bound")
}

/// Allows the loopback upstreams the tests spin up.
const ALLOW_LOOPBACK: &str = r#"
profiles:
  p:
    default_action: deny
    policy:
      - layer: allowlist
        allow: { cidrs: ["127.0.0.0/8"] }
        on_match: allow
        on_miss: pass
"#;

/// Read a proxy response head up to the blank line. Reading a fixed number of bytes would
/// couple the tests to the exact header set the proxy happens to send.
async fn read_head(c: &mut TcpStream) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read_exact(&mut byte).await.is_err() {
            break;
        }
        head.push(byte[0]);
    }
    String::from_utf8_lossy(&head).into_owned()
}

const DENY_ALL: &str = r#"
profiles:
  p:
    default_action: deny
    policy:
      - layer: allowlist
        allow: { domains: ["allowed.test"] }
        on_match: allow
        on_miss: pass
"#;

#[tokio::test]
async fn denial_body_is_structured_and_actionable() {
    let proxy = start_proxy(DENY_ALL, "p").await;
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(b"CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n")
        .await
        .unwrap();

    let mut out = String::new();
    c.read_to_string(&mut out).await.unwrap();

    assert!(out.starts_with("HTTP/1.1 403 Forbidden"), "{out}");
    let body = out.split_once("\r\n\r\n").expect("body follows the head").1;
    let json: serde_json::Value = serde_json::from_str(body).expect("body is JSON");

    // A bare 403 makes agents retry-loop; the reason has to say which layer refused and why.
    assert_eq!(json["error"], "egress_denied");
    assert_eq!(json["profile"], "p");
    assert_eq!(json["reason"]["layer"], "default_action");
    assert_eq!(json["reason"]["code"], "default_deny");
    assert!(json["reason"]["message"].as_str().unwrap().contains("deny"));
}

#[tokio::test]
async fn denied_connect_never_contacts_upstream() {
    // The upstream records connections. A denial must not produce one: policy runs before
    // the network is touched, not after.
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let h = Arc::clone(&hits);
    tokio::spawn(async move {
        while l.accept().await.is_ok() {
            h.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let proxy = start_proxy(DENY_ALL, "p").await;
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", addr.port()).as_bytes())
        .await
        .unwrap();
    let mut out = String::new();
    c.read_to_string(&mut out).await.unwrap();

    assert!(out.starts_with("HTTP/1.1 403"));
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[tokio::test]
async fn allowed_connect_relays_bytes() {
    let upstream = start_upstream(b"HELLO").await;
    let proxy = start_proxy(ALLOW_LOOPBACK, "p").await;

    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", upstream.port()).as_bytes())
        .await
        .unwrap();

    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 200 Connection Established"), "{head}");

    let mut greeting = [0u8; 5];
    c.read_exact(&mut greeting).await.unwrap();
    assert_eq!(&greeting, b"HELLO");

    c.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    c.read_exact(&mut echoed).await.unwrap();
    assert_eq!(&echoed, b"ping", "the tunnel must be transparent in both directions");
}

#[tokio::test]
async fn socks5_denial_uses_the_not_allowed_reply_code() {
    let proxy = start_proxy(DENY_ALL, "p").await;
    let mut c = TcpStream::connect(proxy).await.unwrap();

    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // greeting: NO_AUTH
    let mut sel = [0u8; 2];
    c.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x03, 12];
    req.extend(b"blocked.test");
    req.extend(443u16.to_be_bytes());
    c.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).await.unwrap();
    // 0x02 is "connection not allowed by ruleset" — a policy refusal, distinguishable from
    // a network failure so the client does not retry as if the host were merely down.
    assert_eq!(reply[1], 0x02, "policy denial must not masquerade as a network error");
}

#[tokio::test]
async fn connect_authority_and_tls_sni_must_agree() {
    // A tunnel opened to an allowlisted host that then presents SNI for a different one is
    // an attempt to launder a denied destination through an allowed CONNECT.
    let upstream = start_upstream(b"").await;
    let proxy = start_proxy(ALLOW_LOOPBACK, "p").await;
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", upstream.port()).as_bytes())
        .await
        .unwrap();

    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    c.write_all(&client_hello("evil.example.com")).await.unwrap();

    // The proxy tears the connection down rather than relaying the mismatched handshake.
    // Either a clean EOF or a reset is acceptable; what matters is that the upstream's
    // greeting never reaches the client.
    let mut buf = Vec::new();
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), c.read_to_end(&mut buf))
        .await
        .expect("proxy must close promptly, not hang");
    match read {
        Ok(n) => assert_eq!(n, 0, "nothing should be relayed after an SNI mismatch: {buf:?}"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}"),
    }
}

#[tokio::test]
async fn socks5_connect_authority_and_tls_sni_must_agree() {
    // The same laundering trick as `connect_authority_and_tls_sni_must_agree`, but through a
    // SOCKS5 CONNECT rather than an HTTP one. Shared-IP hosting (a CDN or load balancer
    // serving many sites off one address) routes by the SNI inside the tunnel — a plain relay
    // never inspects that, so without this check a SOCKS5 client could open a tunnel to an
    // allowlisted host and have the origin serve different, denied content instead.
    let upstream = start_upstream(b"").await;
    let proxy = start_proxy(ALLOW_LOOPBACK, "p").await;

    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // greeting: NO_AUTH
    let mut sel = [0u8; 2];
    c.read_exact(&mut sel).await.unwrap();
    assert_eq!(sel, [0x05, 0x00]);

    let ip = match upstream.ip() {
        std::net::IpAddr::V4(v4) => v4.octets(),
        _ => unreachable!("test upstream is v4"),
    };
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend(ip);
    req.extend(upstream.port().to_be_bytes());
    c.write_all(&req).await.unwrap();

    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "the CONNECT itself is to an allowed host");

    c.write_all(&client_hello("evil.example.com")).await.unwrap();

    let mut buf = Vec::new();
    let read = tokio::time::timeout(std::time::Duration::from_secs(5), c.read_to_end(&mut buf))
        .await
        .expect("proxy must close promptly, not hang");
    match read {
        Ok(n) => assert_eq!(n, 0, "nothing should be relayed after an SNI mismatch: {buf:?}"),
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset, "{e}"),
    }
}

#[tokio::test]
async fn matching_sni_is_relayed() {
    let upstream = start_upstream(b"OK").await;
    let proxy = start_proxy(ALLOW_LOOPBACK, "p").await;
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(format!("CONNECT 127.0.0.1:{} HTTP/1.1\r\n\r\n", upstream.port()).as_bytes())
        .await
        .unwrap();
    let head = read_head(&mut c).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    // SNI equal to the CONNECT authority: the tunnel proceeds.
    c.write_all(&client_hello("127.0.0.1")).await.unwrap();
    let mut greeting = [0u8; 2];
    tokio::time::timeout(std::time::Duration::from_secs(5), c.read_exact(&mut greeting))
        .await
        .expect("upstream greeting should arrive")
        .unwrap();
    assert_eq!(&greeting, b"OK");
}

#[tokio::test]
async fn absolute_form_http_is_rewritten_to_origin_form() {
    let upstream = start_upstream(b"").await;
    let proxy = start_proxy(ALLOW_LOOPBACK, "p").await;
    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(
        format!(
            "GET http://127.0.0.1:{}/zen?a=1 HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Marker: keep\r\n\r\n",
            upstream.port()
        )
        .as_bytes(),
    )
    .await
    .unwrap();

    // The echo upstream returns whatever it received.
    let mut buf = vec![0u8; 256];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), c.read(&mut buf))
        .await
        .expect("upstream should echo the head")
        .unwrap();
    let seen = String::from_utf8_lossy(&buf[..n]).into_owned();

    assert!(seen.starts_with("GET /zen?a=1 HTTP/1.1\r\n"), "got: {seen:?}");
    assert!(seen.contains("X-Marker: keep"), "headers must pass through untouched: {seen:?}");
}

/// Minimal well-formed ClientHello carrying one SNI name.
fn client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut list = vec![0x00];
    list.extend((name.len() as u16).to_be_bytes());
    list.extend(name);

    let mut sni = Vec::new();
    sni.extend((list.len() as u16).to_be_bytes());
    sni.extend(&list);

    let mut exts = Vec::new();
    exts.extend(0x0000u16.to_be_bytes());
    exts.extend((sni.len() as u16).to_be_bytes());
    exts.extend(&sni);

    let mut body = vec![0x03, 0x03];
    body.extend([0u8; 32]);
    body.push(0);
    body.extend(2u16.to_be_bytes());
    body.extend([0x13, 0x01]);
    body.push(1);
    body.push(0);
    body.extend((exts.len() as u16).to_be_bytes());
    body.extend(&exts);

    let mut hs = vec![0x01];
    hs.extend(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend(&body);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(&hs);
    rec
}

#[tokio::test]
async fn the_guard_blocks_what_the_allowlist_would_permit() {
    // Defence in depth: an allowlist that names a metadata or private range must not be
    // enough on its own. The guard is a second, independent gate on the resolved address,
    // and it is the one that closes SSRF.
    let yaml = r#"
profiles:
  p:
    default_action: deny
    policy:
      - layer: allowlist
        allow: { cidrs: ["169.254.0.0/16", "127.0.0.0/8"] }
        on_match: allow
        on_miss: pass
"#;
    let guard = UpstreamGuard::new(["169.254.0.0/16"], true).unwrap();
    let proxy = start_proxy_with_guard(yaml, "p", guard).await;

    let mut c = TcpStream::connect(proxy).await.unwrap();
    c.write_all(
        b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: 169.254.169.254\r\n\r\n",
    )
    .await
    .unwrap();

    let mut out = String::new();
    c.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 502"), "{out}");
    assert!(out.contains("blocked by"), "the refusal must name the rule: {out}");
}
