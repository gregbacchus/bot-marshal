//! TLS interception: terminate the client's TLS, evaluate policy against the real request,
//! and re-originate to the upstream.
//!
//! # Streaming is the constraint that shapes this module
//!
//! Bodies are never collected. Both directions forward `hyper::body::Incoming` straight
//! through, so a chunked upload streams, an SSE response arrives event by event, and a
//! WebSocket upgrade becomes a raw relay. It is very easy to write this module in a way that
//! passes every functional test and still buffers — the symptom is not an error, it is an
//! agent whose streaming endpoint delivers everything at once when the response finally ends.
//!
//! # ALPN
//!
//! Both sides negotiate HTTP/1.1 only, deliberately. Offering h2 to the client while speaking
//! HTTP/1.1 upstream (or the reverse) means translating between framing layers, and h2's
//! multiplexing does not survive that translation cleanly. HTTP/2 is a later milestone; until
//! then the downgrade is explicit and stated rather than an accident of configuration.

use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use marshal_core::{
    Action, AuditRecord, AuditSink, Authority, BodyHandle, Evidence, IngressMode, Reason,
    RequestContext, SessionId,
};
use marshal_policy::Chain;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// The body type flowing through the proxy. Boxed so an upstream response and a locally
/// generated denial can share one signature; still streaming underneath.
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, thiserror::Error)]
pub enum MitmError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tls: {0}")]
    Tls(#[from] rustls::Error),
    #[error("http: {0}")]
    Http(#[from] hyper::Error),
    #[error("invalid upstream name `{0}`")]
    InvalidServerName(String),
}

/// Everything the interception path needs, built once at startup.
pub struct TlsEngine {
    minter: Arc<marshal_tls::LeafMinter>,
    client_config: Arc<rustls::ClientConfig>,
}

impl std::fmt::Debug for TlsEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsEngine").finish_non_exhaustive()
    }
}

impl TlsEngine {
    pub fn new(minter: Arc<marshal_tls::LeafMinter>) -> Result<Self, MitmError> {
        Self::with_extra_roots(minter, &[])
    }

    /// As [`TlsEngine::new`], additionally trusting `extra_root_pems` when verifying
    /// upstreams. Needed wherever an agent legitimately talks to a service behind an internal
    /// CA; the public roots are still trusted, so this widens rather than replaces.
    pub fn with_extra_roots(
        minter: Arc<marshal_tls::LeafMinter>,
        extra_root_pems: &[String],
    ) -> Result<Self, MitmError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        for pem in extra_root_pems {
            for cert in rustls_pemfile::certs(&mut pem.as_bytes()) {
                let cert = cert.map_err(std::io::Error::other)?;
                roots.add(cert).map_err(MitmError::Tls)?;
            }
        }

        // Upstream verification stays on. Interception exists to inspect what the agent
        // sends, not to weaken what it connects to: an agent behind a proxy that skipped
        // verification would be strictly worse off than one with no proxy at all.
        let mut client_config =
            rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(Self { minter, client_config: Arc::new(client_config) })
    }

    /// Server config that mints a certificate for whatever name the client asks for.
    fn server_config(&self, fallback_name: &str) -> Arc<rustls::ServerConfig> {
        let resolver =
            Arc::new(marshal_tls::MintingResolver::new(Arc::clone(&self.minter), fallback_name));
        let mut cfg =
            rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(resolver);
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(cfg)
    }
}

/// Per-connection state for an intercepted tunnel.
pub struct MitmHandler {
    pub chain: Arc<Chain>,
    pub audit: Arc<dyn AuditSink>,
    pub authority: Authority,
    pub session: SessionId,
    pub profile: Arc<str>,
    pub client_addr: std::net::SocketAddr,
}

impl std::fmt::Debug for MitmHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MitmHandler").field("authority", &self.authority).finish_non_exhaustive()
    }
}

/// Intercept one CONNECT tunnel.
///
/// `client` is the raw stream after `200 Connection Established`; `upstream` is the TCP
/// connection the guard already checked and opened.
pub async fn intercept<C>(
    client: C,
    upstream: TcpStream,
    engine: Arc<TlsEngine>,
    handler: Arc<MitmHandler>,
) -> Result<(), MitmError>
where
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let host = handler.authority.host.clone();

    // Client side first: its ClientHello names the certificate we must mint.
    let acceptor = TlsAcceptor::from(engine.server_config(&host));
    let client_tls = acceptor.accept(client).await?;

    // Upstream side, verified against the real web PKI.
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| MitmError::InvalidServerName(host.clone()))?
        .to_owned();
    let connector = TlsConnector::from(Arc::clone(&engine.client_config));
    let upstream_tls = connector.connect(server_name, upstream).await?;

    let (sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(upstream_tls)).await?;

    let sender = Arc::new(tokio::sync::Mutex::new(sender));

    let service = hyper::service::service_fn(move |req: Request<Incoming>| {
        let handler = Arc::clone(&handler);
        let sender = Arc::clone(&sender);
        async move { handle_request(req, handler, sender).await }
    });

    let serve = hyper::server::conn::http1::Builder::new()
        .serve_connection(hyper_util::rt::TokioIo::new(client_tls), service)
        .with_upgrades();

    // Both connection futures are driven to completion together, and deliberately *not* with
    // `select!`. After a 101 the upstream future finishes almost immediately, and cancelling
    // the client future at that moment drops it mid-upgrade — the client then never receives
    // its half of the handshake and reports an unexpected EOF. Whichever side happened to
    // finish first decided whether the upgrade worked.
    //
    // Joining terminates cleanly in both directions: when the client goes away the service is
    // dropped, which drops the last `SendRequest` and ends the upstream connection; when the
    // upstream goes away the next request fails and hyper closes the client connection.
    let (served, upstream_done) = tokio::join!(serve, conn.with_upgrades());
    if let Err(e) = served {
        tracing::debug!(error = %e, "client connection ended");
    }
    if let Err(e) = upstream_done {
        tracing::debug!(error = %e, "upstream connection ended");
    }
    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    handler: Arc<MitmHandler>,
    sender: Arc<tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<Incoming>>>,
) -> Result<Response<ProxyBody>, MitmError> {
    let started = std::time::Instant::now();

    // Policy now sees the real request, not just the tunnel destination.
    let cx = RequestContext {
        session: handler.session.clone(),
        profile: Arc::clone(&handler.profile),
        ingress: IngressMode::Explicit,
        client_addr: handler.client_addr,
        authority: handler.authority.clone(),
        method: req.method().clone(),
        uri: req.uri().clone(),
        headers: req.headers().clone(),
        // Streaming: the body is not materialised, and no layer at M2 asks for it.
        body: BodyHandle::Streaming,
        evidence: Evidence::new(),
    };

    let outcome = handler.chain.evaluate(&cx).await;
    if outcome.action == Action::Deny {
        emit(&handler, &cx, &outcome.reason, Action::Deny, outcome.evidence, None, started).await;
        return Ok(denial_response(&outcome.reason, &cx));
    }

    let mut req = req;
    let is_upgrade = req.headers().contains_key(hyper::header::UPGRADE);

    // The upgrade handle must be taken from the client request *before* it is forwarded,
    // because sending consumes it. The future resolves only once we return a 101, so taking
    // it this early is safe and is the intended proxy pattern.
    let client_upgrade = is_upgrade.then(|| hyper::upgrade::on(&mut req));

    let (mut parts, body) = req.into_parts();
    parts.uri = origin_form(&parts.uri);
    strip_hop_by_hop(&mut parts.headers, is_upgrade);
    let upstream_req = Request::from_parts(parts, body);

    let mut response = {
        let mut sender = sender.lock().await;
        sender.send_request(upstream_req).await?
    };

    let status = response.status();
    emit(
        &handler,
        &cx,
        &outcome.reason,
        Action::Allow,
        outcome.evidence,
        Some(status.as_u16()),
        started,
    )
    .await;

    if status == StatusCode::SWITCHING_PROTOCOLS
        && let Some(client_upgrade) = client_upgrade
    {
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        tokio::spawn(async move {
            match tokio::try_join!(client_upgrade, upstream_upgrade) {
                Ok((c, u)) => {
                    // Past this point the proxy has no view of the traffic: an upgraded
                    // connection is whatever protocol the two ends agreed on.
                    let mut c = hyper_util::rt::TokioIo::new(c);
                    let mut u = hyper_util::rt::TokioIo::new(u);
                    if let Err(e) = tokio::io::copy_bidirectional(&mut c, &mut u).await {
                        tracing::debug!(error = %e, "upgraded stream ended");
                    }
                }
                Err(e) => tracing::warn!(error = %e, "upgrade handshake failed"),
            }
        });

        // Return the upstream's 101 verbatim so the client sees the handshake it expects.
        let (parts, _) = response.into_parts();
        return Ok(Response::from_parts(parts, empty_body()));
    }

    let (mut parts, body) = response.into_parts();
    strip_hop_by_hop(&mut parts.headers, false);
    // `Incoming` straight through: the response streams, and Content-Encoding is untouched
    // because nothing here decodes it.
    Ok(Response::from_parts(parts, body.boxed()))
}

fn origin_form(uri: &hyper::Uri) -> hyper::Uri {
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    path.parse().unwrap_or_else(|_| hyper::Uri::from_static("/"))
}

/// Remove headers that describe *this* hop and must not be forwarded.
///
/// `Connection` and `Upgrade` are kept for an upgrade request: stripping them turns a
/// WebSocket handshake into an ordinary GET that the upstream answers with 200, and the
/// client then waits forever for a 101 that will never come.
fn strip_hop_by_hop(headers: &mut hyper::HeaderMap, keep_upgrade: bool) {
    const HOP_BY_HOP: &[&str] = &[
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
    ];
    for h in HOP_BY_HOP {
        headers.remove(*h);
    }
    if !keep_upgrade {
        headers.remove("connection");
        headers.remove("upgrade");
    }
}

fn empty_body() -> ProxyBody {
    Full::new(Bytes::new()).map_err(|e: std::convert::Infallible| match e {}).boxed()
}

fn denial_response(reason: &Reason, cx: &RequestContext) -> Response<ProxyBody> {
    let body = serde_json::json!({
        "error": "egress_denied",
        "proxy": "bot-marshal",
        "session": cx.session.to_string(),
        "profile": cx.profile.to_string(),
        "reason": reason,
    });
    let bytes = Bytes::from(serde_json::to_vec_pretty(&body).unwrap_or_default());

    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header("content-type", "application/json")
        .header("proxy-agent", "bot-marshal")
        .body(Full::new(bytes).map_err(|e: std::convert::Infallible| match e {}).boxed())
        .expect("a static denial response is always valid")
}

#[allow(clippy::too_many_arguments)]
async fn emit(
    handler: &MitmHandler,
    cx: &RequestContext,
    reason: &Reason,
    action: Action,
    evidence: Evidence,
    status_code: Option<u16>,
    started: std::time::Instant,
) {
    handler
        .audit
        .emit(AuditRecord {
            session: cx.session.to_string(),
            attributed: false,
            resolver: None,
            profile: cx.profile.to_string(),
            ingress: "explicit".into(),
            host: cx.authority.host.clone(),
            method: cx.method.to_string(),
            path: cx.uri.path().to_string(),
            action,
            reason: reason.clone(),
            trail: evidence.trail,
            status_code,
            duration_ms: started.elapsed().as_millis() as u64,
        })
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hop_by_hop_headers_are_stripped() {
        let mut h = hyper::HeaderMap::new();
        h.insert("transfer-encoding", "chunked".parse().unwrap());
        h.insert("proxy-authorization", "Basic x".parse().unwrap());
        h.insert("connection", "keep-alive".parse().unwrap());
        h.insert("content-type", "application/json".parse().unwrap());

        strip_hop_by_hop(&mut h, false);
        assert!(!h.contains_key("transfer-encoding"));
        assert!(!h.contains_key("proxy-authorization"));
        assert!(!h.contains_key("connection"));
        assert!(h.contains_key("content-type"), "end-to-end headers must survive");
    }

    #[test]
    fn upgrade_headers_survive_for_an_upgrade_request() {
        // Stripping these turns a WebSocket handshake into a plain GET; the upstream answers
        // 200 and the client waits forever for a 101.
        let mut h = hyper::HeaderMap::new();
        h.insert("connection", "Upgrade".parse().unwrap());
        h.insert("upgrade", "websocket".parse().unwrap());
        h.insert("proxy-connection", "keep-alive".parse().unwrap());

        strip_hop_by_hop(&mut h, true);
        assert_eq!(h.get("connection").unwrap(), "Upgrade");
        assert_eq!(h.get("upgrade").unwrap(), "websocket");
        assert!(!h.contains_key("proxy-connection"));
    }

    #[test]
    fn absolute_uris_become_origin_form() {
        let u: hyper::Uri = "https://api.github.com/repos/x?y=1".parse().unwrap();
        assert_eq!(origin_form(&u).to_string(), "/repos/x?y=1");
        let u: hyper::Uri = "/already".parse().unwrap();
        assert_eq!(origin_form(&u).to_string(), "/already");
    }
}
