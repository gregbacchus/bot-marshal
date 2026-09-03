//! Shared scaffolding for the interception tests: a TLS upstream and a client that speaks
//! through the proxy the way a real tool does.

#![allow(dead_code)]

use rustls::pki_types::pem::PemObject;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody, combinators::BoxBody};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use tokio::net::TcpListener;

pub type TestBody = BoxBody<Bytes, std::io::Error>;

/// A CA plus a leaf for 127.0.0.1, so the test upstream is a genuine TLS server the proxy
/// must verify rather than a hole punched in verification.
pub struct TestPki {
    pub ca_pem: String,
    pub leaf_pem: String,
    pub leaf_key_pem: String,
}

pub fn test_pki() -> TestPki {
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.distinguished_name.push(DnType::CommonName, "test upstream CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    let issuer = Issuer::from_ca_cert_pem(&ca_pem, ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["127.0.0.1".to_string()]).unwrap();
    leaf_params.distinguished_name.push(DnType::CommonName, "127.0.0.1");
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    TestPki { ca_pem, leaf_pem: leaf.pem(), leaf_key_pem: leaf_key.serialize_pem() }
}

/// Start an HTTPS upstream exposing the endpoints the streaming tests need.
pub async fn start_tls_upstream(pki: &TestPki) -> std::net::SocketAddr {
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(pki.leaf_pem.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    let key =
        rustls::pki_types::PrivateKeyDer::from_pem_slice(pki.leaf_key_pem.as_bytes()).unwrap();

    let mut cfg =
        rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key).unwrap();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(tcp).await else { return };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(tls),
                        hyper::service::service_fn(upstream_service),
                    )
                    .with_upgrades()
                    .await;
            });
        }
    });
    addr
}

async fn upstream_service(
    req: Request<Incoming>,
) -> Result<Response<TestBody>, std::convert::Infallible> {
    let path = req.uri().path().to_owned();
    match path.as_str() {
        // Emits three events with a gap between them. A proxy that buffers turns this into
        // one delivery at the end, which is the failure this endpoint exists to expose.
        "/sse" => {
            let stream = futures::stream::unfold(0usize, |i| async move {
                if i >= 3 {
                    return None;
                }
                if i > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                }
                let frame = Frame::data(Bytes::from(format!("data: event-{i}\n\n")));
                Some((Ok::<_, std::io::Error>(frame), i + 1))
            });
            Ok(Response::builder()
                .header("content-type", "text/event-stream")
                .header("cache-control", "no-cache")
                .body(BodyExt::boxed(StreamBody::new(stream)))
                .unwrap())
        }

        // Echoes the request body back as it arrives, so a streamed upload can be observed
        // arriving in pieces rather than all at once.
        "/echo" => {
            let body = req.into_body().map_err(std::io::Error::other).boxed();
            Ok(Response::builder().status(StatusCode::OK).body(body).unwrap())
        }

        "/large" => Ok(Response::builder()
            .status(StatusCode::OK)
            .body(full(b"abcdefghijklmnopqrstuvwxyz".to_vec()))
            .unwrap()),

        // Serves bytes that are already compressed. The proxy must not decode, re-encode, or
        // strip the header, or the client sees garbage.
        "/encoded" => Ok(Response::builder()
            .header("content-encoding", "gzip")
            .header("content-type", "application/octet-stream")
            .body(full(GZIP_HELLO.to_vec()))
            .unwrap()),

        // Minimal protocol upgrade. Real WebSocket framing adds nothing to what is being
        // tested here, which is that a 101 hands back a raw bidirectional stream.
        "/upgrade" => {
            let mut req = req;
            tokio::spawn(async move {
                if let Ok(upgraded) = hyper::upgrade::on(&mut req).await {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut io = hyper_util::rt::TokioIo::new(upgraded);
                    let _ = io.write_all(b"SERVER-HELLO").await;
                    let mut buf = [0u8; 64];
                    while let Ok(n) = io.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        let mut echoed = b"ECHO:".to_vec();
                        echoed.extend_from_slice(&buf[..n]);
                        if io.write_all(&echoed).await.is_err() {
                            break;
                        }
                    }
                }
            });
            Ok(Response::builder()
                .status(StatusCode::SWITCHING_PROTOCOLS)
                .header("connection", "Upgrade")
                .header("upgrade", "test-proto")
                .body(empty())
                .unwrap())
        }

        // A minimal MCP server: answers tools/list with three tools, and echoes any
        // tools/call back so a test can see what actually reached it.
        "/mcp" => {
            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let doc: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
            let id = doc.get("id").cloned().unwrap_or(serde_json::Value::Null);

            let reply = match doc.get("method").and_then(|m| m.as_str()) {
                Some("tools/list") => serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "tools": [
                        { "name": "search_code", "description": "search" },
                        { "name": "create_issue", "description": "create" },
                        { "name": "delete_repository", "description": "danger" }
                    ]}
                }),
                _ => serde_json::json!({
                    "jsonrpc": "2.0", "id": id,
                    "result": { "called": doc.get("params").cloned() }
                }),
            };
            Ok(Response::builder()
                .header("content-type", "application/json")
                .body(full(serde_json::to_vec(&reply).unwrap()))
                .unwrap())
        }

        // The same listing delivered as SSE, which is how MCP's streamable HTTP transport
        // usually returns it.
        "/mcp-sse" => {
            let listing = serde_json::json!({
                "jsonrpc": "2.0", "id": 1,
                "result": { "tools": [
                    { "name": "search_code" },
                    { "name": "delete_repository" }
                ]}
            });
            let events =
                format!("event: message\ndata: {}\n\n", serde_json::to_string(&listing).unwrap());
            Ok(Response::builder()
                .header("content-type", "text/event-stream")
                .body(full(events.into_bytes()))
                .unwrap())
        }

        // Reports exactly what arrived, so a test can assert on what the *upstream* saw
        // rather than on what the proxy claims to have sent.
        "/reflect" => {
            let auth = req
                .headers()
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let api_key = req
                .headers()
                .get("x-api-key")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let query = req.uri().query().unwrap_or("").to_owned();
            let body = req.into_body().collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let doc = serde_json::json!({
                "authorization": auth,
                "x-api-key": api_key,
                "query": query,
                "body": String::from_utf8_lossy(&body),
            });
            Ok(Response::builder()
                .header("content-type", "application/json")
                .body(full(serde_json::to_vec(&doc).unwrap()))
                .unwrap())
        }

        _ => Ok(Response::builder().status(StatusCode::OK).body(full(b"ok".to_vec())).unwrap()),
    }
}

/// gzip of "hello, streaming world" — a fixed blob so the test does not depend on a
/// compression library producing byte-identical output.
pub const GZIP_HELLO: &[u8] = &[
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0xd7,
    0x51, 0x28, 0x2e, 0x29, 0x4a, 0x4d, 0xcc, 0xcd, 0xcc, 0x4b, 0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49,
    0x01, 0x00, 0x1b, 0x5a, 0x8f, 0x37, 0x16, 0x00, 0x00, 0x00,
];

pub fn full(bytes: Vec<u8>) -> TestBody {
    Full::new(Bytes::from(bytes)).map_err(|e: std::convert::Infallible| match e {}).boxed()
}

pub fn empty() -> TestBody {
    Full::new(Bytes::new()).map_err(|e: std::convert::Infallible| match e {}).boxed()
}

/// A rustls client config trusting only `ca_pem` — the proxy's CA, as a real client would
/// after following the trust instructions.
pub fn client_config(ca_pem: &str) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut cfg =
        rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// CONNECT through the proxy, then complete TLS, returning a ready HTTP sender.
pub async fn connect_through_proxy(
    proxy: std::net::SocketAddr,
    target: std::net::SocketAddr,
    ca_pem: &str,
) -> hyper::client::conn::http1::SendRequest<TestBody> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut tcp = tokio::net::TcpStream::connect(proxy).await.unwrap();
    tcp.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();

    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tcp.read_exact(&mut byte).await.expect("proxy must answer the CONNECT");
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head).into_owned();
    assert!(head.starts_with("HTTP/1.1 200"), "CONNECT refused: {head}");

    let name = rustls::pki_types::ServerName::from(target.ip());
    let tls = tokio_rustls::TlsConnector::from(client_config(ca_pem))
        .connect(name, tcp)
        .await
        .expect("the proxy's minted certificate must validate against its own CA");

    let (sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls)).await.unwrap();
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    sender
}

pub fn request(target: std::net::SocketAddr, path: &str) -> Request<TestBody> {
    Request::builder()
        .uri(format!("https://{target}{path}"))
        .header("host", target.to_string())
        .body(empty())
        .unwrap()
}

/// A registry with no resolvers: everything lands in the unattributed fallback, which is what
/// the pre-M4 tests assume.
pub fn no_resolvers() -> Arc<marshal_proxy::identity::IdentityRegistry> {
    Arc::new(marshal_proxy::identity::IdentityRegistry::new(
        vec![],
        Some(Arc::from("p")),
        false,
        false,
    ))
}

/// A plain TCP upstream that greets and echoes, for tests that do not need TLS.
pub async fn start_upstream(greeting: &'static [u8]) -> std::net::SocketAddr {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = s.write_all(greeting).await;
                let mut buf = [0u8; 1024];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    addr
}

/// A throwaway CA for tests that need *a* TlsEngine but do not care which.
pub fn test_engine() -> Arc<marshal_proxy::mitm::TlsEngine> {
    let generated = marshal_tls::CertificateAuthority::generate("test", 1).unwrap();
    let ca = marshal_tls::CertificateAuthority::from_pem(&generated.cert_pem, &generated.key_pem)
        .unwrap();
    let minter = Arc::new(marshal_tls::LeafMinter::new(Arc::new(ca), 16, 72));
    Arc::new(marshal_proxy::mitm::TlsEngine::new(minter).unwrap())
}

/// A single-profile runtime, which is what most tests want.
///
/// `tls: None` means "this test does not care about interception" — it gets a throwaway
/// engine plus a passthrough-everything match, which reproduces the old plain-relay
/// behaviour for tests built against plain TCP upstreams, while still satisfying the
/// invariant that interception is mandatory except for a deliberate passthrough exception.
/// `tls: Some(engine)` means the test wants MITM to actually happen for its hosts.
pub fn single_profile_runtime(
    chain: marshal_policy::Chain,
    tls: Option<Arc<marshal_proxy::mitm::TlsEngine>>,
) -> marshal_proxy::runtime::Runtime {
    match tls {
        Some(engine) => runtime_with(
            chain,
            engine,
            marshal_policy::HostMatcher::default(),
            Vec::new(),
            Vec::new(),
        ),
        None => runtime_with(
            chain,
            test_engine(),
            marshal_policy::HostMatcher::new(Vec::<&str>::new(), ["0.0.0.0/0", "::/0"]).unwrap(),
            Vec::new(),
            Vec::new(),
        ),
    }
}

pub fn runtime_with(
    chain: marshal_policy::Chain,
    tls: Arc<marshal_proxy::mitm::TlsEngine>,
    passthrough: marshal_policy::HostMatcher,
    request_transforms: Vec<Arc<dyn marshal_core::RequestTransform>>,
    response_transforms: Vec<Arc<dyn marshal_core::ResponseTransform>>,
) -> marshal_proxy::runtime::Runtime {
    runtime_with_responders(
        chain,
        tls,
        passthrough,
        request_transforms,
        response_transforms,
        vec![],
    )
}

/// As [`runtime_with`], plus responders — anything that may answer a request instead of
/// letting it reach the upstream.
pub fn runtime_with_responders(
    chain: marshal_policy::Chain,
    tls: Arc<marshal_proxy::mitm::TlsEngine>,
    passthrough: marshal_policy::HostMatcher,
    request_transforms: Vec<Arc<dyn marshal_core::RequestTransform>>,
    response_transforms: Vec<Arc<dyn marshal_core::ResponseTransform>>,
    responders: Vec<Arc<dyn marshal_core::RequestResponder>>,
) -> marshal_proxy::runtime::Runtime {
    let mut chains = std::collections::HashMap::new();
    chains.insert(Arc::from("p"), Arc::new(chain));

    let mut response_map = std::collections::HashMap::new();
    if !response_transforms.is_empty() {
        response_map.insert(Arc::from("p"), response_transforms);
    }

    let mut request_map = std::collections::HashMap::new();
    if !request_transforms.is_empty() {
        request_map.insert(Arc::from("p"), request_transforms);
    }

    let mut responder_map = std::collections::HashMap::new();
    if !responders.is_empty() {
        responder_map.insert(Arc::from("p"), responders);
    }

    marshal_proxy::runtime::Runtime {
        chains,
        response_transforms: response_map,
        responders: responder_map,
        request_transforms: request_map,
        default_chain: Arc::new(marshal_policy::Chain::new(
            "default",
            vec![],
            marshal_core::Decision::Deny,
            Arc::new(marshal_core::DenyingDecider),
        )),
        default_response_transforms: Vec::new(),
        default_responders: Vec::new(),
        default_request_transforms: Vec::new(),
        identities: no_resolvers(),
        passthrough,
        tls,
    }
}

/// Wrap a runtime in the handle the server reads through.
pub fn handle(
    runtime: marshal_proxy::runtime::Runtime,
) -> Arc<marshal_proxy::runtime::RuntimeHandle> {
    Arc::new(marshal_proxy::runtime::RuntimeHandle::new(runtime))
}
