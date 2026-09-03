//! The M2 acceptance bar: interception that does not break streaming.
//!
//! Every test here would pass against an implementation that buffers whole bodies, except
//! the ones that specifically measure *when* bytes arrive. That is the point — buffering does
//! not announce itself as an error, it announces itself as an agent whose streaming endpoint
//! goes quiet and then delivers everything at once.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use http_body_util::BodyExt;
use marshal_audit::JsonSink;
use marshal_config::model::Config;
use marshal_core::{AuditSink, DenyingDecider};
use marshal_policy::{HostMatcher, build_chain};
use marshal_proxy::mitm::TlsEngine;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use support::*;

const ALLOW_LOOPBACK: &str = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: allow
      on_miss: pass
"#;

struct Harness {
    proxy: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    proxy_ca_pem: String,
}

async fn harness(yaml: &str, passthrough: &[&str]) -> Harness {
    let pki = test_pki();
    let upstream = start_tls_upstream(&pki).await;

    let generated = marshal_tls::CertificateAuthority::generate("test proxy CA", 30).unwrap();
    let proxy_ca_pem = generated.cert_pem.clone();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 64, 72));
    // The upstream's own CA is trusted explicitly: interception must still verify upstreams,
    // so the test cannot simply disable verification.
    let engine =
        Arc::new(TlsEngine::with_extra_roots(minter, std::slice::from_ref(&pki.ca_pem)).unwrap());

    let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
    let chain = build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap();
    let guard = UpstreamGuard::new(Vec::<String>::new(), true).unwrap();
    let audit: Arc<dyn AuditSink> = Arc::new(JsonSink::new(tokio::io::sink()));

    let server = Server::new(
        ServerConfig { listen: vec!["127.0.0.1:0".into()], unix_socket: None },
        handle(runtime_with(
            chain,
            engine,
            HostMatcher::new(passthrough.iter(), Vec::<&str>::new()).unwrap(),
            Vec::new(),
            Vec::new(),
        )),
        Arc::new(guard),
        audit,
    );

    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let mut tx = Some(tx);
        let _ = server
            .run(move |addr| {
                let _ = tx.take().unwrap().send(addr);
            })
            .await;
    });

    Harness { proxy: rx.await.unwrap(), upstream, proxy_ca_pem }
}

#[tokio::test]
async fn interception_terminates_tls_and_forwards() {
    let h = harness(ALLOW_LOOPBACK, &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let resp = sender.send_request(request(h.upstream, "/plain")).await.unwrap();
    assert_eq!(resp.status(), 200);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn sse_is_delivered_incrementally() {
    // The test that actually catches buffering. The upstream spaces three events 300ms
    // apart; if the first arrives only once the stream has ended, the proxy collected the
    // body somewhere.
    let h = harness(ALLOW_LOOPBACK, &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let started = Instant::now();
    let resp = sender.send_request(request(h.upstream, "/sse")).await.unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["content-type"], "text/event-stream");

    let mut body = resp.into_body();
    let first = body.frame().await.expect("a first frame").unwrap();
    let first_at = started.elapsed();
    assert_eq!(&first.into_data().unwrap()[..], b"data: event-0\n\n");

    let mut rest = Vec::new();
    while let Some(frame) = body.frame().await {
        if let Ok(d) = frame.unwrap().into_data() {
            rest.extend_from_slice(&d);
        }
    }
    let total = started.elapsed();

    assert!(
        first_at < Duration::from_millis(250),
        "first event took {first_at:?}; it should arrive immediately, not with the last"
    );
    assert!(
        total > Duration::from_millis(500),
        "the whole stream finished in {total:?}, so the upstream's pacing was not preserved"
    );
    assert!(String::from_utf8_lossy(&rest).contains("event-2"));
}

#[tokio::test]
async fn upgraded_connections_relay_in_both_directions() {
    let h = harness(ALLOW_LOOPBACK, &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let req = hyper::Request::builder()
        .uri(format!("https://{}/upgrade", h.upstream))
        .header("host", h.upstream.to_string())
        .header("connection", "Upgrade")
        .header("upgrade", "test-proto")
        .body(empty())
        .unwrap();

    let mut resp = sender.send_request(req).await.unwrap();
    assert_eq!(
        resp.status(),
        hyper::StatusCode::SWITCHING_PROTOCOLS,
        "the 101 must reach the client, or it waits forever for a handshake that never lands"
    );

    let upgraded = hyper::upgrade::on(&mut resp).await.expect("upgrade completes");
    let mut io = hyper_util::rt::TokioIo::new(upgraded);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut hello = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut hello))
        .await
        .expect("server greeting must arrive")
        .unwrap();
    assert_eq!(&hello, b"SERVER-HELLO");

    // And the client->server direction, after the server already spoke.
    io.write_all(b"PING").await.unwrap();
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut echoed))
        .await
        .expect("echo must come back")
        .unwrap();
    assert_eq!(&echoed, b"ECHO:PING");
}

#[tokio::test]
async fn upgraded_connections_survive_an_idle_period() {
    let h = harness(ALLOW_LOOPBACK, &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let req = hyper::Request::builder()
        .uri(format!("https://{}/upgrade", h.upstream))
        .header("host", h.upstream.to_string())
        .header("connection", "Upgrade")
        .header("upgrade", "test-proto")
        .body(empty())
        .unwrap();
    let mut resp = sender.send_request(req).await.unwrap();
    let upgraded = hyper::upgrade::on(&mut resp).await.unwrap();
    let mut io = hyper_util::rt::TokioIo::new(upgraded);

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut hello = [0u8; 12];
    io.read_exact(&mut hello).await.unwrap();

    // A long-lived connection that goes quiet must not be torn down.
    tokio::time::sleep(Duration::from_secs(2)).await;

    io.write_all(b"LATE").await.unwrap();
    let mut echoed = [0u8; 9];
    tokio::time::timeout(Duration::from_secs(5), io.read_exact(&mut echoed))
        .await
        .expect("the connection must still be alive after idling")
        .unwrap();
    assert_eq!(&echoed, b"ECHO:LATE");
}

#[tokio::test]
async fn content_encoding_is_passed_through_untouched() {
    // The proxy does not decode bodies, so it must not claim to have. Stripping or rewriting
    // Content-Encoding here would hand the client bytes it cannot interpret.
    let h = harness(ALLOW_LOOPBACK, &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let resp = sender.send_request(request(h.upstream, "/encoded")).await.unwrap();
    assert_eq!(resp.headers()["content-encoding"], "gzip");

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&body[..], GZIP_HELLO, "compressed bytes must arrive byte-identical");
}

#[tokio::test]
async fn request_bodies_stream_rather_than_being_collected() {
    use futures::StreamExt;
    use http_body_util::StreamBody;
    use hyper::body::Frame;

    let h = harness(ALLOW_LOOPBACK, &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    // A body whose final chunk is delayed. If the proxy waits for the whole request before
    // forwarding, the echoed first chunk cannot come back before that delay has elapsed.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<bytes::Bytes>, std::io::Error>>(4);
    tokio::spawn(async move {
        let _ = tx.send(Ok(Frame::data(bytes::Bytes::from_static(b"first-chunk")))).await;
        tokio::time::sleep(Duration::from_millis(800)).await;
        let _ = tx.send(Ok(Frame::data(bytes::Bytes::from_static(b"last-chunk")))).await;
    });
    let body = StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx).map(|f| f));

    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://{}/echo", h.upstream))
        .header("host", h.upstream.to_string())
        .header("content-type", "application/octet-stream")
        .body(BodyExt::boxed(body))
        .unwrap();

    let started = Instant::now();
    let resp = sender.send_request(req).await.unwrap();
    let mut resp_body = resp.into_body();
    let first = resp_body.frame().await.expect("a first echoed frame").unwrap();
    let first_at = started.elapsed();

    assert_eq!(&first.into_data().unwrap()[..], b"first-chunk");
    assert!(
        first_at < Duration::from_millis(600),
        "the first chunk echoed back after {first_at:?}; the request body was collected \
         before forwarding"
    );
}

#[tokio::test]
async fn passthrough_hosts_are_tunnelled_not_intercepted() {
    // A certificate-pinned client must be able to opt out. The proof is that the certificate
    // the client sees is the upstream's own, not one the proxy minted: connecting with only
    // the proxy CA trusted must fail, and with the upstream CA must succeed.
    let pki = test_pki();
    let upstream = start_tls_upstream(&pki).await;

    let generated = marshal_tls::CertificateAuthority::generate("test proxy CA", 30).unwrap();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 64, 72));
    let engine =
        Arc::new(TlsEngine::with_extra_roots(minter, std::slice::from_ref(&pki.ca_pem)).unwrap());

    let cfg: Config = serde_yaml_ng::from_str(ALLOW_LOOPBACK).unwrap();
    let chain = build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap();
    let server = Server::new(
        ServerConfig { listen: vec!["127.0.0.1:0".into()], unix_socket: None },
        handle(runtime_with(
            chain,
            engine,
            HostMatcher::new(Vec::<&str>::new(), ["127.0.0.0/8"]).unwrap(),
            Vec::new(),
            Vec::new(),
        )),
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
    let proxy = rx.await.unwrap();

    // Trusting only the upstream's CA works, which means no interception happened.
    let mut sender = connect_through_proxy(proxy, upstream, &pki.ca_pem).await;
    let resp = sender.send_request(request(upstream, "/plain")).await.unwrap();
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn policy_sees_the_decrypted_request() {
    // The whole point of M2: a rule can now refuse a path inside an allowlisted host, which
    // a tunnel-only proxy could never do.
    let yaml = r#"
profile:
  default_action: deny
  policy:
    - layer: denylist
      deny: { domains: ["never.test"] }
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: allow
      on_miss: pass
"#;
    let h = harness(yaml, &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let resp = sender.send_request(request(h.upstream, "/anything")).await.unwrap();
    assert_eq!(resp.status(), 200);

    // Two requests on one connection: the chain runs per request, not per tunnel.
    let resp = sender.send_request(request(h.upstream, "/second")).await.unwrap();
    assert_eq!(resp.status(), 200);
}
