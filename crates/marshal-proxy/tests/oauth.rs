//! OAuth2 credential acquisition, end to end through the real proxy.
//!
//! The unit tests in `marshal-secrets` prove the shape of a token request. This proves the
//! part they cannot: that an agent sending nothing reaches the upstream authenticated with a
//! token marshal minted, that the token endpoint is called once and not once per request, and
//! that neither the client secret nor the minted token appears anywhere in the audit trail.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use http_body_util::BodyExt;
use marshal_audit::JsonSink;
use marshal_config::model::Config;
use marshal_core::{AuditSink, DenyingDecider, Redactor, RequestTransform, SecretSource};
use marshal_policy::{HostMatcher, build_chain};
use marshal_proxy::mitm::TlsEngine;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use marshal_secrets::{
    ClientAuth, Grant, Injection, Oauth2Config, Oauth2Source, SecretInjector, SecretSwap,
    TokenStore,
};
use support::TestPki;
use support::*;

/// The client secret marshal presents to the token endpoint. Never leaves the boundary.
const CLIENT_SECRET: &str = "cs_realclientsecret000000000000000000000";
/// What the token endpoint mints. Also never leaves the boundary — the agent gets the
/// *effect* of holding it, never the value.
const MINTED_TOKEN: &str = "at_mintedaccesstoken00000000000000000000";

const ALLOW_LOOPBACK: &str = r#"
profile:
  default_action: deny
  policy:
    - layer: allowlist
      allow: { cidrs: ["127.0.0.0/8"] }
      on_match: allow
      on_miss: pass
"#;

/// A stand-in token endpoint that records what it was asked and answers with `body`.
#[derive(Debug)]
struct FakeAuthServer {
    addr: std::net::SocketAddr,
    calls: Arc<AtomicUsize>,
    seen: Arc<std::sync::Mutex<Vec<String>>>,
}

impl FakeAuthServer {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn last_request(&self) -> String {
        self.seen.lock().unwrap().last().cloned().unwrap_or_default()
    }

    fn token_endpoint(&self) -> String {
        format!("http://{}/oauth2/token", self.addr)
    }
}

/// Answers every request with `responses[i]`, saturating at the last one.
async fn fake_auth_server(responses: Vec<(u16, String)>) -> FakeAuthServer {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));

    let (c, s) = (Arc::clone(&calls), Arc::clone(&seen));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else { return };
            let (c, s, responses) = (Arc::clone(&c), Arc::clone(&s), responses.clone());
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
                let i = c.fetch_add(1, Ordering::SeqCst);
                s.lock().unwrap().push(raw);

                let (status, body) = responses.get(i).unwrap_or(responses.last().unwrap());
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(body.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    FakeAuthServer { addr, calls, seen }
}

fn token_body(access_token: &str, expires_in: u64) -> String {
    format!(
        r#"{{"access_token":"{access_token}","token_type":"Bearer","expires_in":{expires_in}}}"#
    )
}

struct Harness {
    proxy: std::net::SocketAddr,
    upstream: std::net::SocketAddr,
    proxy_ca_pem: String,
    audit: Arc<AuditBuffer>,
    redactor: Redactor,
}

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

/// A source returning a fixed value, standing in for the env var a client secret comes from.
#[derive(Debug)]
struct Fixed(&'static str);

#[async_trait::async_trait]
impl SecretSource for Fixed {
    fn name(&self) -> &str {
        "CLIENT_SECRET"
    }
    async fn resolve(&self) -> marshal_core::Result<marshal_core::SecretValue> {
        Ok(marshal_core::SecretValue::new(self.0))
    }
}

fn oauth_source(auth: &FakeAuthServer, redactor: &Redactor, grant: Grant) -> Arc<Oauth2Source> {
    Arc::new(
        Oauth2Source::new(
            "SERVICE",
            Oauth2Config {
                token_endpoint: auth.token_endpoint(),
                client_id: "marshal".into(),
                client_auth: ClientAuth::ClientSecretBasic {
                    secret: Arc::new(Fixed(CLIENT_SECRET)),
                },
                grant,
                scope: vec!["read:things".into()],
                audience: None,
                extra_params: Default::default(),
                expiry_skew: Duration::ZERO,
                authorization_endpoint: None,
                redirect_uri: None,
                device_authorization_endpoint: None,
            },
            Arc::new(TokenStore::new(None)),
            marshal_http::default_tls_config(),
            // No guard: the fake token endpoint is on loopback, which is exactly what the
            // guard exists to refuse. Production wiring passes one.
            None,
            redactor.clone(),
        )
        .unwrap(),
    )
}

async fn harness(source: Arc<dyn SecretSource>, redactor: Redactor) -> Harness {
    let pki = test_pki();
    let upstream = start_tls_upstream(&pki).await;

    let generated = marshal_tls::CertificateAuthority::generate("test proxy CA", 30).unwrap();
    let proxy_ca_pem = generated.cert_pem.clone();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 64, 72));
    let engine =
        Arc::new(TlsEngine::with_extra_roots(minter, std::slice::from_ref(&pki.ca_pem)).unwrap());

    let cfg: Config = serde_yaml_ng::from_str(ALLOW_LOOPBACK).unwrap();
    let chain = build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap();

    let buffer = Arc::new(AuditBuffer::default());
    let sink = JsonSink::new(SharedWriter(Arc::clone(&buffer))).redacting(redactor.clone());
    let audit_sink: Arc<dyn AuditSink> = Arc::new(sink);

    let swap = SecretSwap {
        name: "SERVICE".into(),
        injection: Injection::Bearer { source },
        hosts: HostMatcher::new(Vec::<&str>::new(), ["127.0.0.0/8"]).unwrap(),
    };
    let transforms: Vec<Arc<dyn RequestTransform>> =
        vec![Arc::new(SecretInjector::new(vec![swap]))];

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

    Harness { proxy: rx.await.unwrap(), upstream, proxy_ca_pem, audit: buffer, redactor }
}

/// Send a request with no credential of any kind, and report the headers the upstream saw.
async fn reflect(h: &Harness) -> serde_json::Value {
    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;
    let req = hyper::Request::builder()
        .uri(format!("https://{}/reflect", h.upstream))
        .header("host", h.upstream.to_string())
        .body(empty())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn a_client_holding_nothing_reaches_the_upstream_with_a_minted_token() {
    let auth = fake_auth_server(vec![(200, token_body(MINTED_TOKEN, 3600))]).await;
    let redactor = Redactor::default();
    let h = harness(oauth_source(&auth, &redactor, Grant::ClientCredentials), redactor).await;

    let seen = reflect(&h).await;
    assert_eq!(seen["authorization"], format!("Bearer {MINTED_TOKEN}"));
    assert_eq!(auth.calls(), 1);
}

#[tokio::test]
async fn the_token_request_carries_the_grant_and_client_auth_the_provider_expects() {
    let auth = fake_auth_server(vec![(200, token_body(MINTED_TOKEN, 3600))]).await;
    let redactor = Redactor::default();
    let h = harness(oauth_source(&auth, &redactor, Grant::ClientCredentials), redactor).await;
    reflect(&h).await;

    let req = auth.last_request();
    // Absolute-form request line, which RFC 9112 requires every server to accept.
    assert!(req.starts_with("POST http://"), "{req}");
    assert!(req.contains("/oauth2/token HTTP/1.1"), "{req}");
    // The port must be in the Host header: an auth server behind virtual hosting routes on it.
    assert!(req.contains(&format!("host: {}", auth.addr)), "{req}");
    assert!(req.contains("content-type: application/x-www-form-urlencoded"), "{req}");
    assert!(req.contains("grant_type=client_credentials"), "{req}");
    // client_secret_basic: the credential is in the header, never the body.
    assert!(req.contains("authorization: Basic "), "{req}");
    assert!(!req.contains(CLIENT_SECRET), "the client secret must not be sent in the clear");
}

#[tokio::test]
async fn a_live_token_is_reused_rather_than_reminted_on_every_request() {
    // The whole point of the cache. Without it, every proxied request costs a round trip to
    // the auth server, and providers rate-limit token endpoints hard.
    let auth = fake_auth_server(vec![(200, token_body(MINTED_TOKEN, 3600))]).await;
    let redactor = Redactor::default();
    let h = harness(oauth_source(&auth, &redactor, Grant::ClientCredentials), redactor).await;

    for _ in 0..5 {
        assert_eq!(reflect(&h).await["authorization"], format!("Bearer {MINTED_TOKEN}"));
    }
    assert_eq!(auth.calls(), 1, "the token endpoint should have been called exactly once");
}

#[tokio::test]
async fn an_expired_token_is_reminted_and_the_new_one_is_used() {
    let auth = fake_auth_server(vec![
        // One second, and the skew is zero in this harness, so it is stale almost at once.
        (200, token_body("at_first00000000000000000000000000000000", 1)),
        (200, token_body(MINTED_TOKEN, 3600)),
    ])
    .await;
    let redactor = Redactor::default();
    let h = harness(oauth_source(&auth, &redactor, Grant::ClientCredentials), redactor).await;

    assert_eq!(
        reflect(&h).await["authorization"],
        "Bearer at_first00000000000000000000000000000000"
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(reflect(&h).await["authorization"], format!("Bearer {MINTED_TOKEN}"));
    assert_eq!(auth.calls(), 2);
}

#[tokio::test]
async fn concurrent_requests_on_a_cold_cache_mint_exactly_once() {
    // Some providers invalidate the previous refresh token on every use, so a concurrent
    // double refresh is not merely wasteful — it can break the credential outright.
    let auth = fake_auth_server(vec![(200, token_body(MINTED_TOKEN, 3600))]).await;
    let redactor = Redactor::default();
    let source = oauth_source(&auth, &redactor, Grant::ClientCredentials);

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let source = Arc::clone(&source);
        tasks.spawn(async move { source.resolve().await.unwrap().expose().to_owned() });
    }
    while let Some(r) = tasks.join_next().await {
        assert_eq!(r.unwrap(), MINTED_TOKEN);
    }
    assert_eq!(auth.calls(), 1, "20 concurrent resolves should have minted one token");
}

#[tokio::test]
async fn a_token_endpoint_failure_denies_the_request_and_names_the_cause() {
    // Fail closed: an unauthenticated request reaching the upstream would be worse than a
    // refusal, and the refusal has to say enough for an operator to act.
    let auth = fake_auth_server(vec![(
        400,
        r#"{"error":"invalid_client","error_description":"unknown client"}"#.to_string(),
    )])
    .await;
    let redactor = Redactor::default();
    let h = harness(oauth_source(&auth, &redactor, Grant::ClientCredentials), redactor).await;

    let mut sender = connect_through_proxy(h.proxy, h.upstream, &h.proxy_ca_pem).await;
    let req = hyper::Request::builder()
        .uri(format!("https://{}/reflect", h.upstream))
        .header("host", h.upstream.to_string())
        .body(empty())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 403);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("invalid_client"), "{text}");
    assert!(text.contains("unknown client"), "{text}");
}

#[tokio::test]
async fn neither_the_client_secret_nor_the_minted_token_reaches_the_audit_trail() {
    // The value being searched for here did not exist when the process started — this is
    // exactly the case a redactor sealed at startup could not have covered (ADR-0029).
    let auth = fake_auth_server(vec![(200, token_body(MINTED_TOKEN, 3600))]).await;
    let redactor = Redactor::default();
    let h = harness(oauth_source(&auth, &redactor, Grant::ClientCredentials), redactor).await;

    reflect(&h).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let audit = h.audit.contents();
    assert!(!audit.is_empty(), "the audit sink recorded nothing, so this proves nothing");
    assert!(audit.contains("\"host\""), "the audit records should still be structured");
    assert!(!audit.contains(MINTED_TOKEN), "the minted access token appears in the audit trail");
    assert!(!audit.contains(CLIENT_SECRET), "the client secret appears in the audit trail");
}

#[tokio::test]
async fn the_minted_token_is_learned_by_the_redactor_that_the_sinks_already_hold() {
    // The mechanism the previous test depends on, asserted directly: a sink took its clone
    // before the token existed, and must still redact it.
    let auth = fake_auth_server(vec![(200, token_body(MINTED_TOKEN, 3600))]).await;
    let redactor = Redactor::default();
    let sink_copy = redactor.clone();
    assert!(sink_copy.is_empty());

    let h = harness(oauth_source(&auth, &redactor, Grant::ClientCredentials), redactor).await;
    reflect(&h).await;

    assert!(sink_copy.redact(&format!("Bearer {MINTED_TOKEN}")).contains("redacted"));
    assert!(!h.redactor.is_empty());
}

#[tokio::test]
async fn the_refresh_grant_presents_its_refresh_token_and_uses_what_it_gets_back() {
    let auth = fake_auth_server(vec![(200, token_body(MINTED_TOKEN, 3600))]).await;
    let redactor = Redactor::default();
    let grant =
        Grant::RefreshToken { source: Arc::new(Fixed("rt_configuredrefreshtoken0000000000000")) };
    let h = harness(oauth_source(&auth, &redactor, grant), redactor).await;

    assert_eq!(reflect(&h).await["authorization"], format!("Bearer {MINTED_TOKEN}"));
    let req = auth.last_request();
    assert!(req.contains("grant_type=refresh_token"), "{req}");
    assert!(req.contains("refresh_token=rt_configuredrefreshtoken0000000000000"), "{req}");
}

// ===========================================================================================
// In-band capture: the agent drives the flow through the proxy and ends up holding nothing.
// ===========================================================================================

/// A TLS OAuth2 provider that actually enforces PKCE, so "marshal owns the verifier" is
/// something the test proves rather than assumes.
#[derive(Debug)]
struct FakeProvider {
    addr: std::net::SocketAddr,
    /// The `code_challenge` each authorize request carried.
    challenges: Arc<std::sync::Mutex<Vec<String>>>,
    /// Every token exchange attempted, as its form body.
    exchanges: Arc<std::sync::Mutex<Vec<String>>>,
}

/// The code the provider issues. The agent must never see this value.
const REAL_CODE: &str = "REALCODE_onlymarshalcanredeemthis";

async fn fake_provider(pki: &TestPki) -> FakeProvider {
    use hyper::{Request as HReq, Response as HResp};

    let certs: Vec<_> =
        rustls_pemfile::certs(&mut pki.leaf_pem.as_bytes()).collect::<Result<_, _>>().unwrap();
    let key = rustls_pemfile::private_key(&mut pki.leaf_key_pem.as_bytes()).unwrap().unwrap();
    let mut cfg =
        rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let challenges = Arc::new(std::sync::Mutex::new(Vec::new()));
    let exchanges = Arc::new(std::sync::Mutex::new(Vec::new()));

    let (ch, ex) = (Arc::clone(&challenges), Arc::clone(&exchanges));
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let (acceptor, ch, ex) = (acceptor.clone(), Arc::clone(&ch), Arc::clone(&ex));
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let service = hyper::service::service_fn(
                    move |req: HReq<hyper::body::Incoming>| {
                        let (ch, ex) = (Arc::clone(&ch), Arc::clone(&ex));
                        async move {
                            let path = req.uri().path().to_owned();
                            let query = req.uri().query().unwrap_or("").to_owned();
                            let body = req.into_body().collect().await.unwrap().to_bytes();
                            let body = String::from_utf8_lossy(&body).into_owned();

                            let resp = match path.as_str() {
                                "/oauth2/authorize" => {
                                    let q = form_pairs(&query);
                                    ch.lock().unwrap().push(get(&q, "code_challenge").to_owned());
                                    let location = format!(
                                        "{}?code={REAL_CODE}&state={}",
                                        get(&q, "redirect_uri"),
                                        get(&q, "state")
                                    );
                                    HResp::builder()
                                        .status(302)
                                        .header("location", location)
                                        .body(full(Vec::new()))
                                        .unwrap()
                                }
                                "/oauth2/token" => {
                                    ex.lock().unwrap().push(body.clone());
                                    let f = form_pairs(&body);
                                    // The whole point: only the party holding the verifier that
                                    // matches the recorded challenge may redeem the code.
                                    let verifier = get(&f, "code_verifier");
                                    let expected =
                                        ch.lock().unwrap().last().cloned().unwrap_or_default();
                                    let actual = pkce_s256(verifier);
                                    if get(&f, "code") != REAL_CODE || actual != expected {
                                        HResp::builder()
                                        .status(400)
                                        .header("content-type", "application/json")
                                        .body(full(
                                            br#"{"error":"invalid_grant","error_description":"PKCE mismatch"}"#
                                                .to_vec(),
                                        ))
                                        .unwrap()
                                    } else {
                                        HResp::builder()
                                        .status(200)
                                        .header("content-type", "application/json")
                                        .body(full(
                                            format!(
                                                r#"{{"access_token":"{MINTED_TOKEN}","token_type":"Bearer","expires_in":3600,"refresh_token":"rt_CAPTURED_0001","scope":"offline_access"}}"#
                                            )
                                            .into_bytes(),
                                        ))
                                        .unwrap()
                                    }
                                }
                                _ => HResp::builder().status(404).body(full(Vec::new())).unwrap(),
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    },
                );
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            });
        }
    });

    FakeProvider { addr, challenges, exchanges }
}

fn form_pairs(s: &str) -> Vec<(String, String)> {
    s.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            (pct(k), pct(v))
        })
        .collect()
}

fn get<'a>(pairs: &'a [(String, String)], name: &str) -> &'a str {
    pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str()).unwrap_or("")
}

fn pct(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                match u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16) {
                    Ok(x) => {
                        out.push(x);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            x => {
                out.push(x);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// An independent S256 implementation, so the test does not verify marshal against itself.
fn pkce_s256(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(verifier.as_bytes());
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in digest.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(alphabet[(b0 >> 2) as usize] as char);
        out.push(alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(alphabet[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

struct CaptureHarness {
    proxy: std::net::SocketAddr,
    provider: std::net::SocketAddr,
    proxy_ca_pem: String,
    audit: Arc<AuditBuffer>,
}

async fn capture_harness(
    store_dir: std::path::PathBuf,
) -> (CaptureHarness, FakeProvider, Redactor) {
    let pki = test_pki();
    let provider = fake_provider(&pki).await;

    let generated = marshal_tls::CertificateAuthority::generate("test proxy CA", 30).unwrap();
    let proxy_ca_pem = generated.cert_pem.clone();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 64, 72));
    let engine =
        Arc::new(TlsEngine::with_extra_roots(minter, std::slice::from_ref(&pki.ca_pem)).unwrap());

    let cfg: Config = serde_yaml_ng::from_str(ALLOW_LOOPBACK).unwrap();
    let chain = build_chain(&cfg, "p", &cfg.profile, Arc::new(DenyingDecider)).unwrap();

    let redactor = Redactor::default();
    let buffer = Arc::new(AuditBuffer::default());
    let sink = JsonSink::new(SharedWriter(Arc::clone(&buffer))).redacting(redactor.clone());

    let source = Arc::new(
        marshal_secrets::Oauth2Source::new(
            "SERVICE",
            Oauth2Config {
                token_endpoint: format!("https://{}/oauth2/token", provider.addr),
                client_id: "marshal".into(),
                client_auth: ClientAuth::None,
                grant: Grant::Enrolled,
                scope: vec!["offline_access".into()],
                audience: None,
                extra_params: Default::default(),
                expiry_skew: Duration::ZERO,
                authorization_endpoint: Some(format!("https://{}/oauth2/authorize", provider.addr)),
                redirect_uri: None,
                device_authorization_endpoint: None,
            },
            Arc::new(TokenStore::new(Some(store_dir))),
            // The provider presents the test PKI's leaf, so marshal's own out-of-band call
            // has to trust that root — the same extra-roots wiring the MITM engine uses.
            support::client_config(&pki.ca_pem),
            None,
            redactor.clone(),
        )
        .unwrap(),
    );

    let broker = Arc::new(
        marshal_secrets::Oauth2Broker::new(
            "SERVICE",
            source,
            &format!("https://{}/oauth2/authorize", provider.addr),
            &format!("https://{}/oauth2/token", provider.addr),
        )
        .unwrap(),
    );

    let server = Server::new(
        ServerConfig { listen: vec!["127.0.0.1:0".into()], unix_socket: None },
        handle(support::runtime_with_responders(
            chain,
            engine,
            HostMatcher::default(),
            vec![Arc::clone(&broker) as Arc<dyn RequestTransform>],
            vec![Arc::clone(&broker) as Arc<dyn marshal_core::ResponseTransform>],
            vec![broker as Arc<dyn marshal_core::RequestResponder>],
        )),
        Arc::new(UpstreamGuard::new(Vec::<String>::new(), true).unwrap()),
        Arc::new(sink) as Arc<dyn AuditSink>,
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
    (
        CaptureHarness { proxy, provider: provider.addr, proxy_ca_pem, audit: buffer },
        provider,
        redactor,
    )
}

fn temp_state(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("marshal-capture-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// The agent's authorization request, as its OAuth library would build it.
async fn agent_authorize(
    h: &CaptureHarness,
    challenge: &str,
) -> hyper::Response<hyper::body::Incoming> {
    let mut sender = connect_through_proxy(h.proxy, h.provider, &h.proxy_ca_pem).await;
    let uri = format!(
        "https://{}/oauth2/authorize?response_type=code&client_id=agent&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=AGENTSTATE123&code_challenge={challenge}&code_challenge_method=S256",
        h.provider
    );
    let req = hyper::Request::builder()
        .uri(uri)
        .header("host", h.provider.to_string())
        .body(empty())
        .unwrap();
    sender.send_request(req).await.unwrap()
}

#[tokio::test]
async fn the_challenge_the_provider_records_is_marshals_not_the_agents() {
    let (h, provider, _r) = capture_harness(temp_state("challenge")).await;
    let agent_challenge = pkce_s256("the-agents-own-verifier-which-marshal-must-replace");

    agent_authorize(&h, &agent_challenge).await;

    let recorded = provider.challenges.lock().unwrap().clone();
    assert_eq!(recorded.len(), 1);
    assert_ne!(
        recorded[0], agent_challenge,
        "the agent's challenge reached the provider, so the agent could redeem its own code"
    );
}

#[tokio::test]
async fn the_agent_never_sees_the_real_authorization_code() {
    let (h, _provider, _r) = capture_harness(temp_state("code")).await;
    let resp = agent_authorize(&h, &pkce_s256("agent-verifier")).await;

    assert_eq!(resp.status(), 302);
    let location = resp.headers().get("location").unwrap().to_str().unwrap().to_owned();
    assert!(!location.contains(REAL_CODE), "the real code reached the agent: {location}");
    assert!(location.contains("code=marshal-managed-code-SERVICE"), "{location}");
    // The agent's own CSRF check has to keep working, so `state` must survive untouched.
    assert!(location.contains("state=AGENTSTATE123"), "{location}");
}

#[tokio::test]
async fn marshal_redeems_the_code_itself_and_stores_the_grant() {
    let dir = temp_state("redeem");
    let (h, provider, _r) = capture_harness(dir.clone()).await;
    agent_authorize(&h, &pkce_s256("agent-verifier")).await;

    // One exchange, from marshal, and the provider's PKCE check passed — which it only can
    // if the verifier presented matches the challenge marshal substituted.
    let exchanges = provider.exchanges.lock().unwrap().clone();
    assert_eq!(exchanges.len(), 1, "expected exactly one exchange: {exchanges:?}");
    assert!(exchanges[0].contains("grant_type=authorization_code"), "{}", exchanges[0]);
    assert!(exchanges[0].contains(&format!("code={REAL_CODE}")), "{}", exchanges[0]);

    let stored = TokenStore::new(Some(dir)).grant("SERVICE").unwrap().expect("a grant was stored");
    assert_eq!(stored.refresh_token.expose(), "rt_CAPTURED_0001");
}

#[tokio::test]
async fn the_agents_own_token_request_is_answered_locally_and_never_forwarded() {
    let (h, provider, _r) = capture_harness(temp_state("answer")).await;
    agent_authorize(&h, &pkce_s256("agent-verifier")).await;
    let after_capture = provider.exchanges.lock().unwrap().len();

    // The agent now does what its OAuth library does next: exchange the code it was given.
    let mut sender = connect_through_proxy(h.proxy, h.provider, &h.proxy_ca_pem).await;
    let form = "grant_type=authorization_code&code=marshal-managed-code-SERVICE&code_verifier=the-agents-own-verifier&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb";
    let req = hyper::Request::builder()
        .method("POST")
        .uri(format!("https://{}/oauth2/token", h.provider))
        .header("host", h.provider.to_string())
        .header("content-type", "application/x-www-form-urlencoded")
        .body(full(form.as_bytes().to_vec()))
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();

    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("proxy-agent").unwrap(), "bot-marshal");
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // A well-formed token response the agent's state machine can consume, carrying nothing.
    assert_eq!(json["token_type"], "Bearer");
    assert_eq!(json["access_token"], "marshal-managed-token-SERVICE");
    assert_ne!(json["access_token"], MINTED_TOKEN);

    assert_eq!(
        provider.exchanges.lock().unwrap().len(),
        after_capture,
        "the agent's exchange reached the provider; it must be answered locally instead"
    );
}

#[tokio::test]
async fn no_part_of_the_captured_credential_reaches_the_audit_trail() {
    let (h, _provider, _r) = capture_harness(temp_state("audit")).await;
    agent_authorize(&h, &pkce_s256("agent-verifier")).await;
    tokio::time::sleep(Duration::from_millis(150)).await;

    let audit = h.audit.contents();
    assert!(!audit.is_empty(), "the audit sink recorded nothing, so this proves nothing");
    assert!(audit.contains("\"host\""), "the audit records should still be structured");
    for value in [MINTED_TOKEN, "rt_CAPTURED_0001", REAL_CODE] {
        assert!(!audit.contains(value), "`{value}` appears in the audit trail");
    }
}

#[tokio::test]
async fn a_request_that_is_not_an_authorization_code_flow_is_left_alone() {
    // The authorize endpoint also serves the implicit flow and its own login pages. Rewriting
    // those would break them and capture nothing.
    let (h, provider, _r) = capture_harness(temp_state("untouched")).await;
    let mut sender = connect_through_proxy(h.proxy, h.provider, &h.proxy_ca_pem).await;
    let req = hyper::Request::builder()
        .uri(format!(
            "https://{}/oauth2/authorize?response_type=token&client_id=agent&redirect_uri=http%3A%2F%2F127.0.0.1%3A9999%2Fcb&state=S",
            h.provider
        ))
        .header("host", h.provider.to_string())
        .body(empty())
        .unwrap();
    sender.send_request(req).await.unwrap();

    // No challenge was substituted, so nothing was recorded as one marshal issued.
    assert_eq!(provider.challenges.lock().unwrap().as_slice(), [""]);
}

#[tokio::test]
async fn a_redirect_carrying_a_state_marshal_did_not_issue_is_not_touched() {
    // The response hook fires on any Location with a `state`; it must only act on one from a
    // flow it started, or it would corrupt unrelated redirects.
    let (h, _provider, _r) = capture_harness(temp_state("foreign")).await;
    let mut sender = connect_through_proxy(h.proxy, h.provider, &h.proxy_ca_pem).await;
    // /nope 404s, but the point is a response marshal has no pending flow for.
    let req = hyper::Request::builder()
        .uri(format!("https://{}/nope?state=SOMEONEELSE&code=THEIRCODE", h.provider))
        .header("host", h.provider.to_string())
        .body(empty())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 404);
}
