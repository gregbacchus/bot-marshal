//! M3 acceptance: the agent holds a placeholder, the upstream receives the real credential,
//! and the audit trail contains no trace of it.

mod support;

use std::sync::Arc;

use http_body_util::BodyExt;
use marshal_audit::JsonSink;
use marshal_config::model::Config;
use marshal_core::{AuditSink, DenyingDecider, RequestTransform};
use marshal_policy::{HostMatcher, build_chain};
use marshal_proxy::mitm::TlsEngine;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use marshal_secrets::{Injection, MatchSites, SecretInjector, SecretSwap, SwapKind};
use support::*;

/// The real credential. Deliberately shaped like a GitHub token so the DLP tests can use the
/// same value and prove the two layers do not fight each other.
const REAL_SECRET: &str = "ghp_realsecretvalue0000000000000000000000";
const PLACEHOLDER: &str = "marshal-github-placeholder";

const ALLOW_LOOPBACK: &str = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: allow
      on_miss: pass
"#;

/// A source that yields a fixed value, so the test does not depend on process environment.
#[derive(Debug)]
struct FixedSecret(&'static str);

#[async_trait::async_trait]
impl marshal_core::SecretSource for FixedSecret {
    fn name(&self) -> &str {
        "TEST_SECRET"
    }
    async fn resolve(&self) -> marshal_core::Result<marshal_core::SecretValue> {
        Ok(marshal_core::SecretValue::new(self.0))
    }
}

struct Harness {
    proxy: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    proxy_ca_pem: String,
    /// Everything the audit sink wrote, for the "no secret anywhere" assertion.
    audit: Arc<AuditBuffer>,
}

/// Collects raw audit bytes so a test can search them the way an operator would.
#[derive(Debug, Default)]
struct AuditBuffer(std::sync::Mutex<Vec<u8>>);

impl AuditBuffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for &AuditBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

async fn harness(yaml: &str, swaps: Vec<SecretSwap>, redact: &[&str]) -> Harness {
    let pki = test_pki();
    let upstream = start_tls_upstream(&pki).await;

    let generated = marshal_tls::CertificateAuthority::generate("test proxy CA", 30).unwrap();
    let proxy_ca_pem = generated.cert_pem.clone();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 64, 72));
    let engine =
        Arc::new(TlsEngine::with_extra_roots(minter, std::slice::from_ref(&pki.ca_pem)).unwrap());

    let cfg: Config = serde_yaml_ng::from_str(yaml).unwrap();
    let chain = build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap();

    let buffer = Arc::new(AuditBuffer::default());
    let sink = {
        let buffer = Arc::clone(&buffer);
        let writer = SharedWriter(buffer);
        JsonSink::new(writer)
            .redacting(marshal_core::Redactor::new(redact.iter().map(|s| s.to_string())))
    };
    let audit_sink: Arc<dyn AuditSink> = Arc::new(sink);

    let mut transforms: Vec<Arc<dyn RequestTransform>> = Vec::new();
    if !swaps.is_empty() {
        transforms.push(Arc::new(SecretInjector::new(swaps)));
    }

    let server = Server::new(
        ServerConfig { listen: vec!["127.0.0.1:0".into()], unix_socket: None },
        handle(runtime_with(chain, engine, HostMatcher::default(), transforms, Vec::new())),
        Arc::new(UpstreamGuard::new(Vec::<String>::new(), true).unwrap()),
        audit_sink,
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

    Harness { proxy: rx.await.unwrap(), upstream, proxy_ca_pem, audit: buffer }
}

/// Adapts the shared buffer to the async writer the sink expects.
struct SharedWriter(Arc<AuditBuffer>);

impl tokio::io::AsyncWrite for SharedWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::io::Write;
        let mut w = &*self.0;
        std::task::Poll::Ready(w.write(buf))
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

fn swap(sites: MatchSites, require: bool) -> SecretSwap {
    SecretSwap {
        name: "TEST_SECRET".into(),
        source: Arc::new(FixedSecret(REAL_SECRET)),
        kind: SwapKind::Placeholder { proxy_value: PLACEHOLDER.into(), sites, require },
        hosts: HostMatcher::new(Vec::<&str>::new(), ["127.0.0.0/8"]).unwrap(),
    }
}

fn inject_swap(injection: Injection) -> SecretSwap {
    SecretSwap {
        name: "TEST_SECRET".into(),
        source: Arc::new(FixedSecret(REAL_SECRET)),
        kind: SwapKind::Inject(injection),
        hosts: HostMatcher::new(Vec::<&str>::new(), ["127.0.0.0/8"]).unwrap(),
    }
}

async fn reflect(
    h: &Harness,
    build: impl FnOnce(hyper::http::request::Builder) -> hyper::Request<TestBody>,
) -> serde_json::Value {
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;
    let req = build(
        hyper::Request::builder()
            .uri(format!("https://{}/reflect", h.upstream))
            .header("host", h.upstream.to_string()),
    );
    let resp = sender.send_request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn the_placeholder_is_swapped_for_the_real_credential() {
    let h = harness(ALLOW_LOOPBACK, vec![swap(MatchSites::default(), true)], &[REAL_SECRET]).await;

    let seen = reflect(&h, |b| {
        b.header("authorization", format!("Bearer {PLACEHOLDER}")).body(empty()).unwrap()
    })
    .await;

    assert_eq!(
        seen["authorization"],
        format!("Bearer {REAL_SECRET}"),
        "the upstream must receive the real credential"
    );
}

#[tokio::test]
async fn the_placeholder_is_swapped_inside_a_basic_auth_challenge() {
    // git-over-HTTPS, most package registries, and container registry auth all normally send
    // credentials as `Authorization: Basic base64("user:password")`, not a plain bearer
    // token. The placeholder must be found inside the *decoded* credential and the header
    // re-encoded — the exact same config as the bearer-token case, no extra flag.
    let h = harness(ALLOW_LOOPBACK, vec![swap(MatchSites::default(), true)], &[REAL_SECRET]).await;

    use base64_test_helper::b64;
    let placeholder_basic = format!("Basic {}", b64(&format!("x-access-token:{PLACEHOLDER}")));

    let seen =
        reflect(&h, |b| b.header("authorization", placeholder_basic).body(empty()).unwrap()).await;

    let expected = format!("Basic {}", b64(&format!("x-access-token:{REAL_SECRET}")));
    assert_eq!(
        seen["authorization"], expected,
        "the decoded credential must carry the real secret, re-encoded"
    );
}

#[tokio::test]
async fn a_basic_auth_challenge_without_the_placeholder_is_left_alone() {
    // A Basic header that happens not to carry the placeholder (a different service's
    // credential, entirely unrelated auth) must not be touched or misread as a match.
    let h = harness(ALLOW_LOOPBACK, vec![swap(MatchSites::default(), false)], &[REAL_SECRET]).await;

    use base64_test_helper::b64;
    let unrelated = format!("Basic {}", b64("someone:something-else-entirely"));

    let seen =
        reflect(&h, |b| b.header("authorization", unrelated.clone()).body(empty()).unwrap()).await;

    assert_eq!(seen["authorization"], unrelated, "an unrelated Basic header must pass through");
}

#[tokio::test]
async fn inject_adds_basic_auth_the_client_never_sent_at_all() {
    // The defining property of Inject mode: the client presents nothing related to
    // authentication — no placeholder, no header — and the credential appears anyway.
    let h = harness(
        ALLOW_LOOPBACK,
        vec![inject_swap(Injection::Basic { username: "x-access-token".into() })],
        &[REAL_SECRET],
    )
    .await;

    let seen = reflect(&h, |b| b.body(empty()).unwrap()).await;

    use base64_test_helper::b64;
    let expected = format!("Basic {}", b64(&format!("x-access-token:{REAL_SECRET}")));
    assert_eq!(seen["authorization"], expected);
}

#[tokio::test]
async fn inject_overwrites_whatever_authorization_the_client_did_send() {
    // If a client sends its own (irrelevant) Authorization header, Inject mode replaces it —
    // the configured credential is authoritative for this host, not a fallback.
    let h = harness(
        ALLOW_LOOPBACK,
        vec![inject_swap(Injection::Basic { username: "x-access-token".into() })],
        &[REAL_SECRET],
    )
    .await;

    let seen = reflect(&h, |b| {
        b.header("authorization", "Bearer something-unrelated").body(empty()).unwrap()
    })
    .await;

    use base64_test_helper::b64;
    let expected = format!("Basic {}", b64(&format!("x-access-token:{REAL_SECRET}")));
    assert_eq!(seen["authorization"], expected);
}

mod base64_test_helper {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /// Minimal standard base64 encoder, so this test file does not need a dependency to
    /// construct the exact wire format `Authorization: Basic` uses.
    pub fn b64(input: &str) -> String {
        let input = input.as_bytes();
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0];
            let b1 = chunk.get(1).copied().unwrap_or(0);
            let b2 = chunk.get(2).copied().unwrap_or(0);
            out.push(ALPHABET[(b0 >> 2) as usize] as char);
            out.push(ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 { ALPHABET[(b2 & 0x3f) as usize] as char } else { '=' });
        }
        out
    }
}

#[tokio::test]
async fn the_real_secret_never_appears_in_the_audit_trail() {
    // The plan's acceptance criterion, tested the way an operator would check it: search the
    // entire audit output for the literal value.
    //
    // Note what this does and does not prove. As the code stands no field of `AuditRecord`
    // is populated from a header value, so this would also pass with redaction switched off
    // — it is a regression guard against a future field that does carry one, not a
    // demonstration that redaction works. That the redactor actually fires is proved by
    // `marshal_audit`'s own tests, which feed it a record containing the secret.
    let h = harness(ALLOW_LOOPBACK, vec![swap(MatchSites::default(), true)], &[REAL_SECRET]).await;

    reflect(&h, |b| {
        b.header("authorization", format!("Bearer {PLACEHOLDER}")).body(empty()).unwrap()
    })
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let audit = h.audit.contents();
    assert!(!audit.is_empty(), "the audit sink recorded nothing, so this proves nothing");
    assert!(
        !audit.contains(REAL_SECRET),
        "the real credential leaked into the audit trail:\n{audit}"
    );
    // The placeholder is safe to log and useful for debugging, so it should still be there
    // if it appears at all — redaction must not be indiscriminate.
    assert!(audit.contains("\"host\""), "records are still structured: {audit}");
}

#[tokio::test]
async fn a_required_placeholder_that_is_missing_is_refused() {
    // Forwarding unauthenticated would surface as a confusing 401 from the upstream, which
    // an agent cannot act on. Refusing here says exactly what to do instead.
    let h = harness(ALLOW_LOOPBACK, vec![swap(MatchSites::default(), true)], &[REAL_SECRET]).await;

    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;
    let resp = sender.send_request(request(h.upstream, "/reflect")).await.unwrap();
    assert_eq!(resp.status(), 403);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let message = doc["reason"]["message"].as_str().unwrap();
    assert!(message.contains(PLACEHOLDER), "the refusal must say what to send: {message}");
    assert!(!message.contains(REAL_SECRET));
}

#[tokio::test]
async fn swaps_reach_the_query_string_and_body_when_configured() {
    let sites = MatchSites { headers: vec![], query: true, body: true };
    let h = harness(ALLOW_LOOPBACK, vec![swap(sites, false)], &[REAL_SECRET]).await;

    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://{}/reflect?token={PLACEHOLDER}", h.upstream))
        .header("host", h.upstream.to_string())
        .header("content-type", "application/json")
        .body(full(format!(r#"{{"key":"{PLACEHOLDER}"}}"#).into_bytes()))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let seen: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(seen["query"].as_str().unwrap().contains(REAL_SECRET), "query: {seen}");
    assert!(seen["body"].as_str().unwrap().contains(REAL_SECRET), "body: {seen}");
    // A swap changes the byte count; a stale Content-Length would desynchronise the
    // connection, and the upstream reading a complete JSON document proves it did not.
    assert!(seen["body"].as_str().unwrap().ends_with("\"}"), "body truncated: {seen}");
}

#[tokio::test]
async fn requests_to_other_hosts_are_not_touched() {
    // The swap is scoped by host. A placeholder sent elsewhere must stay a placeholder,
    // or the proxy becomes a way to launder the credential to any allowed destination.
    let mut s = swap(MatchSites::default(), false);
    s.hosts = HostMatcher::new(["only.example.com"], Vec::<&str>::new()).unwrap();
    let h = harness(ALLOW_LOOPBACK, vec![s], &[REAL_SECRET]).await;

    let seen = reflect(&h, |b| {
        b.header("authorization", format!("Bearer {PLACEHOLDER}")).body(empty()).unwrap()
    })
    .await;

    assert_eq!(seen["authorization"], format!("Bearer {PLACEHOLDER}"));
}

const WITH_DLP: &str = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: pass
      on_miss: deny
    - layer: dlp
      scan_request: true
      patterns: ["github-pat", "aws-access-key", "private-key-pem"]
      on_match: deny
      max_body_bytes: 1024
      on_oversize: deny
    - layer: rules
      expressions:
        - when: 'req.method in ["GET", "POST"]'
          verdict: allow
"#;

#[tokio::test]
async fn dlp_blocks_a_real_credential_leaving_in_a_header() {
    let h = harness(WITH_DLP, vec![], &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let req = hyper::Request::builder()
        .uri(format!("https://{}/reflect", h.upstream))
        .header("host", h.upstream.to_string())
        .header("x-forwarded-token", REAL_SECRET)
        .body(empty())
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 403);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["reason"]["layer"], "dlp");
    assert_eq!(doc["reason"]["code"], "credential_in_request");
    // The finding names the pattern and the location, never the matched value — writing it
    // out would be the exfiltration this layer exists to prevent.
    let message = doc["reason"]["message"].as_str().unwrap();
    assert!(message.contains("github-pat"), "{message}");
    assert!(!message.contains(REAL_SECRET), "the finding quoted the credential: {message}");
}

#[tokio::test]
async fn dlp_blocks_a_credential_in_the_body() {
    let h = harness(WITH_DLP, vec![], &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://{}/reflect", h.upstream))
        .header("host", h.upstream.to_string())
        .body(full(format!(r#"{{"note":"key is {REAL_SECRET}"}}"#).into_bytes()))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["reason"]["layer"], "dlp");
}

#[tokio::test]
async fn dlp_lets_ordinary_traffic_through() {
    // False positives are the failure mode that gets a security layer switched off.
    let h = harness(WITH_DLP, vec![], &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://{}/reflect", h.upstream))
        .header("host", h.upstream.to_string())
        .header("authorization", format!("Bearer {PLACEHOLDER}"))
        .body(full(br#"{"title":"Fix the AKIA prefix parser","sha":"abc123"}"#.to_vec()))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200, "ordinary content must not trip the scanner");
}

#[tokio::test]
async fn a_body_too_large_to_scan_is_refused_rather_than_passed_unscanned() {
    // An unscanned body is exactly where a credential would hide, so the default is to
    // refuse. The alternative is configurable, but it must be a choice.
    let h = harness(WITH_DLP, vec![], &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;

    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://{}/reflect", h.upstream))
        .header("host", h.upstream.to_string())
        .body(full(vec![b'x'; 4096]))
        .unwrap();

    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 403);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["reason"]["code"], "body_too_large_to_scan");
}

#[tokio::test]
async fn rules_can_refuse_a_method_inside_an_allowed_host() {
    // The thing a tunnel-only proxy could never do: allow a host but refuse an operation.
    let yaml = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: pass
      on_miss: deny
    - layer: rules
      expressions:
        - when: 'req.method == "DELETE"'
          verdict: deny
        - when: 'req.path.startsWith("/reflect")'
          verdict: allow
"#;
    let h = harness(yaml, vec![], &[]).await;

    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;
    let resp = sender.send_request(request(h.upstream, "/reflect")).await.unwrap();
    assert_eq!(resp.status(), 200);

    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;
    let req = hyper::Request::builder()
        .method("DELETE")
        .uri(format!("https://{}/reflect", h.upstream))
        .header("host", h.upstream.to_string())
        .body(empty())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 403);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(doc["reason"]["layer"], "rules");
    assert_eq!(doc["reason"]["rule"], r#"req.method == "DELETE""#);
}

#[tokio::test]
async fn rules_can_read_evidence_left_by_an_earlier_layer() {
    // The chain's whole justification: a cheap layer records a fact, a later one acts on it.
    let yaml = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: pass
      on_miss: deny
    - layer: rules
      expressions:
        - when: 'ev.facts["allowlist.matched"] == "127.0.0.0/8"'
          verdict: allow
"#;
    let h = harness(yaml, vec![], &[]).await;
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;
    let resp = sender.send_request(request(h.upstream, "/reflect")).await.unwrap();
    assert_eq!(resp.status(), 200, "the rule could not see the allowlist's fact");
}
