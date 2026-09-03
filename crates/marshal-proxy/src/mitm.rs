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
    Action, AuditRecord, AuditSink, Authority, BodyHandle, BodyRequirement, Evidence, Identity,
    IngressMode, Reason, RequestContext, RequestTransform, ResponseParts, ResponseTransform,
};
use marshal_policy::Chain;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

/// The body type flowing through the proxy. Boxed so an upstream response and a locally
/// generated denial can share one signature; still streaming underneath.
pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// JSON-RPC error code for a policy refusal. Inside the reserved implementation-defined
/// server-error range.
pub const MCP_DENIED_CODE: i64 = -32001;

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
    /// How the tunnel this handler decrypts was captured. Recorded on every request inside
    /// it, so an intercepted transparent connection doesn't audit as explicit traffic.
    pub ingress: IngressMode,
    pub identity: Identity,
    pub profile: Arc<str>,
    pub client_addr: std::net::SocketAddr,
    /// Applied after the chain allows. Rewriting is not deciding.
    pub request_transforms: Vec<Arc<dyn RequestTransform>>,
    /// Applied to the response on its way back to the agent.
    pub response_transforms: Vec<Arc<dyn ResponseTransform>>,
    /// Counters. Intercepted requests must be recorded here too: once TLS is terminated a
    /// single CONNECT carries many requests, and counting only tunnels understates an agent's
    /// activity by whatever its connection reuse happens to be.
    pub stats: Arc<crate::stats::IdentityStats>,
    /// Whether a resolver matched. Recorded so an unattributed request never looks
    /// attributed in the audit trail.
    pub attributed: bool,
    pub resolver: Option<String>,
}

impl MitmHandler {
    /// The strongest body requirement across the chain and the transforms.
    fn body_requirement(&self) -> BodyRequirement {
        self.request_transforms
            .iter()
            .map(|t| t.body_requirement())
            .fold(self.chain.body_requirement(), |acc, r| acc.combine(r))
    }

    /// What the response side needs. Kept separate from the request side so a transform that
    /// rewrites responses does not force request bodies to be buffered as well.
    fn response_body_requirement(&self) -> BodyRequirement {
        self.response_transforms
            .iter()
            .map(|t| t.body_requirement())
            .fold(BodyRequirement::Streaming, |acc, r| acc.combine(r))
    }
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
    sender: Arc<tokio::sync::Mutex<hyper::client::conn::http1::SendRequest<ProxyBody>>>,
) -> Result<Response<ProxyBody>, MitmError> {
    let started = std::time::Instant::now();

    let mut req = req;
    let is_upgrade = req.headers().contains_key(hyper::header::UPGRADE);

    // The upgrade handle must be taken from the client request *before* it is forwarded,
    // because sending consumes it. The future resolves only once we return a 101, so taking
    // it this early is safe and is the intended proxy pattern.
    let client_upgrade = is_upgrade.then(|| hyper::upgrade::on(&mut req));

    let (mut parts, incoming) = req.into_parts();

    // Buffer only if something actually asks for it. Buffering by default would quietly stop
    // uploads streaming, and an upgrade has no body to buffer in the first place.
    let requirement =
        if is_upgrade { BodyRequirement::Streaming } else { handler.body_requirement() };
    let (body_handle, forward_body) = materialise(incoming, requirement).await?;

    // Whether this is a JSON-RPC call is a property of the request, so it is read here rather
    // than taken from layer evidence. That matters twice over: a layer returning `Deny`
    // contributes no evidence, and a refusal from *any* layer — allowlist, dlp, rules — should
    // still reach an MCP client as a protocol error rather than a transport failure.
    let jsonrpc_id = match &body_handle {
        BodyHandle::Buffered(bytes) => {
            marshal_policy::jsonrpc::parse_request(bytes).map(|m| match m {
                marshal_policy::jsonrpc::Message::ToolsCall(c) => c.id,
                marshal_policy::jsonrpc::Message::ToolsList { id } => id,
                marshal_policy::jsonrpc::Message::Other { id, .. } => id,
            })
        }
        _ => None,
    };

    // Policy now sees the real request, not just the tunnel destination.
    let mut cx = RequestContext {
        identity: handler.identity.clone(),
        profile: Arc::clone(&handler.profile),
        ingress: handler.ingress,
        phase: marshal_core::Phase::Request,
        client_addr: handler.client_addr,
        authority: handler.authority.clone(),
        method: parts.method.clone(),
        uri: parts.uri.clone(),
        headers: parts.headers.clone(),
        body: body_handle,
        evidence: Evidence::new(),
    };

    let outcome = handler.chain.evaluate(&cx).await;
    let would_deny = outcome.would_deny;
    if outcome.action == Action::Deny {
        emit(&handler, &cx, &outcome.reason, Action::Deny, outcome.evidence, None, started, false)
            .await;
        return Ok(denial_response(&outcome.reason, &cx, jsonrpc_id));
    }

    // Transforms run only once the chain has allowed.
    for transform in &handler.request_transforms {
        if let Err(e) = transform.apply(&mut cx).await {
            // A transform that cannot do its job must not be skipped: a request forwarded
            // without its credential swap would leak the placeholder upstream and fail in a
            // way that looks like an upstream problem.
            let reason = Reason::new(transform.name(), "transform_failed", e.to_string());
            emit(&handler, &cx, &reason, Action::Deny, outcome.evidence, None, started, false)
                .await;
            return Ok(denial_response(&reason, &cx, jsonrpc_id));
        }
    }

    parts.uri = origin_form(&cx.uri);
    parts.headers = cx.headers.clone();
    strip_hop_by_hop(&mut parts.headers, is_upgrade);

    // A transform may have rewritten a buffered body; if so, send what it produced.
    let forward_body = match &cx.body {
        BodyHandle::Buffered(bytes) => {
            if let Some(len) = parts.headers.get(hyper::header::CONTENT_LENGTH)
                && len.to_str().ok().and_then(|v| v.parse::<usize>().ok()) != Some(bytes.len())
            {
                // A swap changes the byte count; a stale Content-Length would desynchronise
                // the upstream connection.
                parts.headers.insert(
                    hyper::header::CONTENT_LENGTH,
                    hyper::header::HeaderValue::from(bytes.len()),
                );
            }
            Full::new(bytes.clone()).map_err(|e: std::convert::Infallible| match e {}).boxed()
        }
        _ => forward_body,
    };

    let upstream_req = Request::from_parts(parts, forward_body);

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
        would_deny,
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

    if handler.response_transforms.is_empty() {
        // `Incoming` straight through: the response streams, and Content-Encoding is
        // untouched because nothing here decodes it.
        return Ok(Response::from_parts(parts, body.boxed()));
    }

    // An SSE response is filtered event by event rather than buffered, because buffering it
    // would undo the streaming the rest of the proxy guarantees. Anything else is
    // materialised up to the declared cap.
    if is_event_stream(&parts.headers) {
        // Rewriting changes the length, and a stale Content-Length makes hyper tear the
        // connection down mid-body. Dropping it moves the response to chunked encoding,
        // which is what a stream of unknown length needs anyway.
        parts.headers.remove(hyper::header::CONTENT_LENGTH);
        let filtered = filter_event_stream(body, Arc::clone(&handler), cx.authority.host.clone());
        return Ok(Response::from_parts(parts, filtered));
    }

    let (body_handle, forward) = materialise(body, handler.response_body_requirement()).await?;
    let mut resp =
        ResponseParts { status: parts.status, headers: parts.headers, body: body_handle };

    for transform in &handler.response_transforms {
        if let Err(e) = transform.apply(&cx, &mut resp).await {
            // A response transform that cannot run must not be skipped: a `tools/list` that
            // slipped past the filter advertises tools the agent is not allowed to call.
            tracing::error!(transform = transform.name(), error = %e, "response transform failed");
            let reason = Reason::new(transform.name(), "response_transform_failed", e.to_string());
            return Ok(denial_response(&reason, &cx, jsonrpc_id));
        }
    }

    parts.status = resp.status;
    parts.headers = resp.headers;
    let out = match resp.body {
        BodyHandle::Buffered(bytes) => {
            Full::new(bytes).map_err(|e: std::convert::Infallible| match e {}).boxed()
        }
        _ => forward,
    };
    Ok(Response::from_parts(parts, out))
}

fn is_event_stream(headers: &hyper::HeaderMap) -> bool {
    headers
        .get(hyper::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/event-stream"))
}

/// Rewrite an SSE body chunk by chunk, so it keeps streaming.
///
/// A chunk boundary can fall mid-event, so a partial trailing event is held back until the
/// rest of it arrives rather than being parsed as truncated JSON. Whatever is still held when
/// the stream ends is flushed unmodified — a stream that stops mid-event is the upstream's
/// business, and dropping those bytes would silently truncate the response.
fn filter_event_stream(body: Incoming, handler: Arc<MitmHandler>, host: String) -> ProxyBody {
    use http_body_util::BodyStream;

    struct State {
        stream: BodyStream<Incoming>,
        pending: String,
        done: bool,
    }

    let state = State { stream: BodyStream::new(body), pending: String::new(), done: false };

    let stream = futures::stream::unfold(state, move |mut state| {
        let handler = Arc::clone(&handler);
        let host = host.clone();
        async move {
            use futures::StreamExt;

            loop {
                if state.done {
                    return None;
                }

                match state.stream.next().await {
                    Some(Err(e)) => {
                        state.done = true;
                        return Some((Err(e), state));
                    }
                    Some(Ok(frame)) => {
                        let Ok(data) = frame.into_data() else { continue };
                        state.pending.push_str(&String::from_utf8_lossy(&data));

                        // Only whole events (terminated by a blank line) are safe to parse.
                        let Some(end) = state.pending.rfind("\n\n").map(|i| i + 2) else {
                            continue;
                        };
                        let ready: String = state.pending.drain(..end).collect();
                        let out = rewrite(&handler, &host, ready);
                        return Some((Ok(hyper::body::Frame::data(Bytes::from(out))), state));
                    }
                    None => {
                        state.done = true;
                        if state.pending.is_empty() {
                            return None;
                        }
                        // Flush the partial event verbatim rather than discarding it.
                        let tail = std::mem::take(&mut state.pending);
                        return Some((Ok(hyper::body::Frame::data(Bytes::from(tail))), state));
                    }
                }
            }
        }
    });

    BodyExt::boxed(http_body_util::StreamBody::new(stream))
}

fn rewrite(handler: &MitmHandler, host: &str, mut chunk: String) -> String {
    for transform in &handler.response_transforms {
        if let Some(rewritten) = transform.rewrite_chunk(host, &chunk) {
            chunk = rewritten;
        }
    }
    chunk
}

/// Turn an incoming body into what policy sees plus what gets forwarded.
///
/// When buffering is asked for, the body is collected up to the cap. If it exceeds the cap,
/// policy is told the body is still streaming — so a layer like DLP applies its own oversize
/// rule rather than silently scanning a truncated prefix — while the bytes already read are
/// put back in front of the remainder so nothing is lost or reordered.
async fn materialise(
    incoming: Incoming,
    requirement: BodyRequirement,
) -> Result<(BodyHandle, ProxyBody), MitmError> {
    let BodyRequirement::Buffered { cap } = requirement else {
        return Ok((BodyHandle::Streaming, incoming.boxed()));
    };

    use futures::StreamExt;
    use http_body_util::BodyStream;

    let mut stream = BodyStream::new(incoming);
    let mut collected: Vec<hyper::body::Frame<Bytes>> = Vec::new();
    let mut total = 0usize;
    let mut overflowed = false;

    while let Some(frame) = stream.next().await {
        let frame = frame?;
        if let Some(d) = frame.data_ref() {
            total += d.len();
        }
        collected.push(frame);
        if total > cap {
            overflowed = true;
            break;
        }
    }

    if overflowed {
        let prefix = futures::stream::iter(collected.into_iter().map(Ok));
        let rejoined = http_body_util::StreamBody::new(prefix.chain(stream));
        return Ok((BodyHandle::Streaming, BodyExt::boxed(rejoined)));
    }

    let mut bytes = bytes::BytesMut::with_capacity(total);
    for frame in &collected {
        if let Some(d) = frame.data_ref() {
            bytes.extend_from_slice(d);
        }
    }
    let bytes = bytes.freeze();

    let forward =
        Full::new(bytes.clone()).map_err(|e: std::convert::Infallible| match e {}).boxed();
    Ok((BodyHandle::Buffered(bytes), forward))
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

fn denial_response(
    reason: &Reason,
    cx: &RequestContext,
    jsonrpc: Option<Option<serde_json::Value>>,
) -> Response<ProxyBody> {
    // A denied JSON-RPC call comes back as a JSON-RPC error, not an HTTP 403. The client is
    // an MCP implementation: a transport-level failure reads as "the server is down" and
    // produces reconnects, whereas a protocol error is something the agent can act on.
    if let Some(id) = jsonrpc {
        let doc = marshal_policy::jsonrpc::error_response(
            id,
            MCP_DENIED_CODE,
            &format!("{} [{}]", reason.message, reason.code),
        );
        let bytes = Bytes::from(serde_json::to_vec(&doc).unwrap_or_default());
        return Response::builder()
            // 200 with a JSON-RPC error, which is what the protocol expects; the refusal is
            // in the payload, not the status line.
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .header("proxy-agent", "bot-marshal")
            .body(Full::new(bytes).map_err(|e: std::convert::Infallible| match e {}).boxed())
            .expect("a static denial response is always valid");
    }

    let body = serde_json::json!({
        "error": "egress_denied",
        "proxy": "bot-marshal",
        "identity": cx.identity.to_string(),
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
    would_deny: bool,
) {
    handler.stats.record(&cx.identity, &cx.profile, action == Action::Allow, would_deny);
    handler
        .audit
        .emit(AuditRecord {
            identity: cx.identity.to_string(),
            attributed: handler.attributed,
            resolver: handler.resolver.clone(),
            profile: cx.profile.to_string(),
            ingress: match cx.ingress {
                IngressMode::Explicit => "explicit",
                IngressMode::Dns => "dns",
            }
            .into(),
            host: cx.authority.host.clone(),
            method: cx.method.to_string(),
            path: cx.uri.path().to_string(),
            action,
            reason: reason.clone(),
            would_deny,
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
