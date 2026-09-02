//! The explicit-proxy listener.
//!
//! One TCP port serves HTTP `CONNECT`, absolute-form HTTP, and SOCKS5. Every accepted
//! connection follows the same path regardless of which: resolve a session, evaluate the
//! policy chain against the requested authority, and only then touch the network. Nothing
//! upstream is contacted before a verdict exists.

use std::sync::Arc;
use std::time::Instant;

use marshal_core::{
    Action, AuditRecord, AuditSink, Authority, BodyHandle, Evidence, IngressMode, Reason,
    RequestContext, SessionId,
};
use marshal_policy::Chain;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::guard::{GuardError, UpstreamGuard};
use crate::httpfront::{self, ProxyRequest};
use crate::mitm::{self, MitmHandler, TlsEngine};
use crate::rewind::Rewind;
use crate::sniff::{self, Protocol};
use crate::socks5::{self, Reply};
use crate::tunnel;

#[derive(Clone)]
pub struct ServerConfig {
    pub listen: String,
    /// Which profile applies. Real session resolution arrives in M4; until then every
    /// connection is explicitly *unattributed*, and the audit record says so rather than
    /// implying an identity the proxy cannot yet establish.
    pub profile: Arc<str>,
    /// Present when a CA is configured. Without it the proxy still runs, but sees only the
    /// tunnel destination — which is the honest behaviour when no CA has been created, not a
    /// degraded mode to hide.
    pub tls: Option<Arc<TlsEngine>>,
    /// Hosts tunnelled without interception. Certificate-pinned clients belong here, as does
    /// anything whose traffic must demonstrably not be read.
    pub passthrough: marshal_policy::HostMatcher,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("profile", &self.profile)
            .field("intercepting", &self.tls.is_some())
            .finish()
    }
}

pub struct Server {
    config: ServerConfig,
    chain: Arc<Chain>,
    guard: Arc<UpstreamGuard>,
    audit: Arc<dyn AuditSink>,
    request_transforms: Vec<Arc<dyn marshal_core::RequestTransform>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Server {
    pub fn new(
        config: ServerConfig,
        chain: Arc<Chain>,
        guard: Arc<UpstreamGuard>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self { config, chain, guard, audit, request_transforms: Vec::new() }
    }

    /// Transforms applied to allowed requests. Only reachable when TLS is intercepted: a
    /// tunnelled connection has no request to rewrite.
    pub fn with_request_transforms(
        mut self,
        transforms: Vec<Arc<dyn marshal_core::RequestTransform>>,
    ) -> Self {
        self.request_transforms = transforms;
        self
    }

    /// Bind and serve until cancelled. Returns the bound address via `on_bind`, which lets
    /// tests use port 0 and discover what they got.
    pub async fn run(self, on_bind: impl FnOnce(std::net::SocketAddr)) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.config.listen).await?;
        let local = listener.local_addr()?;
        tracing::info!(
            listen = %local,
            profile = %self.config.profile,
            layers = ?self.chain.layer_names(),
            intercepting = self.config.tls.is_some(),
            "explicit proxy listening"
        );
        if self.config.tls.is_none() {
            tracing::warn!(
                "no CA configured: TLS is tunnelled, so policy sees the destination host but \
                 not the request. Run `marshal ca init` to intercept."
            );
            let skipped = self.chain.request_only_layers();
            if !skipped.is_empty() {
                // Silently not enforcing a configured layer is the worst available outcome:
                // the operator believes the rule is live.
                tracing::warn!(
                    layers = ?skipped,
                    "these layers need a decrypted request and will NEVER evaluate without a CA"
                );
            }
        }
        on_bind(local);

        let this = Arc::new(self);
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                }
            };
            let this = Arc::clone(&this);
            tokio::spawn(async move {
                if let Err(e) = this.serve_connection(stream, peer).await {
                    tracing::debug!(peer = %peer, error = %e, "connection ended");
                }
            });
        }
    }

    async fn serve_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        let _ = stream.set_nodelay(true);
        let mut client = BufReader::new(stream);

        // One byte tells us which protocol we are speaking. It is handed on rather than
        // pushed back, so no un-read buffer has to be threaded through the front-ends.
        let mut first = [0u8; 1];
        if client.read_exact(&mut first).await.is_err() {
            return Ok(()); // client hung up before saying anything
        }

        match sniff::detect(first[0]) {
            Protocol::Socks5 => self.serve_socks5(client, peer).await,
            Protocol::Socks4 => {
                tracing::debug!(peer = %peer, "refused SOCKS4; only SOCKS5 is supported");
                Ok(())
            }
            Protocol::Http => self.serve_http(client, peer, first[0]).await,
        }
    }

    async fn serve_socks5(
        self: Arc<Self>,
        mut client: BufReader<TcpStream>,
        peer: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        let started = Instant::now();

        let authority = match socks5::handshake(&mut client).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "socks5 handshake failed");
                return Ok(());
            }
        };

        let cx = self.context(peer, authority.clone(), "CONNECT", "", marshal_core::Phase::Connect);
        let outcome = self.chain.evaluate(&cx).await;

        if outcome.action == Action::Deny {
            let _ = socks5::reply(&mut client, Reply::NotAllowed).await;
            self.emit(&cx, &outcome.reason, Action::Deny, outcome.evidence, None, started).await;
            return Ok(());
        }

        let mut upstream = match self.guard.connect(&authority).await {
            Ok(s) => s,
            Err(e) => {
                let _ = socks5::reply(&mut client, guard_reply(&e)).await;
                self.emit_guard_failure(&cx, &e, outcome.evidence, started).await;
                return Ok(());
            }
        };

        socks5::reply(&mut client, Reply::Succeeded).await.ok();
        self.emit(&cx, &outcome.reason, Action::Allow, outcome.evidence, None, started).await;

        let _ = tunnel::relay(&mut client, &mut upstream).await;
        Ok(())
    }

    async fn serve_http(
        self: Arc<Self>,
        mut client: BufReader<TcpStream>,
        peer: std::net::SocketAddr,
        first_byte: u8,
    ) -> std::io::Result<()> {
        let started = Instant::now();

        let request: ProxyRequest = match httpfront::read_request(&mut client, first_byte).await {
            Ok(r) => r,
            Err(e) => {
                let _ =
                    httpfront::write_status(&mut client, "400 Bad Request", &e.to_string()).await;
                return Ok(());
            }
        };

        let cx = self.context(
            peer,
            request.authority.clone(),
            &request.method,
            if request.is_connect { "" } else { &request.path },
            if request.is_connect {
                marshal_core::Phase::Connect
            } else {
                // Plaintext absolute-form: method and path are visible, so request-level
                // layers do apply. The body is not parsed on this path, so a layer that
                // scans bodies applies its own oversize rule rather than seeing nothing.
                marshal_core::Phase::Request
            },
        );
        let mut outcome = self.chain.evaluate(&cx).await;

        // A CONNECT is a pre-filter, not the decision.
        //
        // When TLS will be intercepted, a destination that no host-level layer *refused*
        // proceeds to interception, where the request-level layers make the real call. The
        // alternative makes the natural configuration impossible: a short-circuiting chain
        // means an allowlist with `on_match: allow` terminates before `dlp` or `rules` ever
        // run, while `on_match: pass` leaves nothing to permit the tunnel. Reading `pass` as
        // "not decided yet, keep going" is faithful to what it says.
        //
        // Default-deny is not weakened: no request is forwarded to the upstream until the
        // request-level chain allows one. In tunnel mode the CONNECT *is* the only decision
        // point, so `default_action` governs it strictly.
        if request.is_connect
            && outcome.action == Action::Deny
            && outcome.reason.layer == "default_action"
            && self.intercepts(&request.authority)
            && !self.chain.request_only_layers().is_empty()
        {
            outcome.action = Action::Allow;
            outcome.reason = Reason::new(
                "default_action",
                "connect_provisional",
                format!(
                    "no host-level layer refused `{}`; the decision is deferred to the \
                     request-level layers {:?} once TLS is intercepted",
                    request.authority.host,
                    self.chain.request_only_layers()
                ),
            );
        }

        if outcome.action == Action::Deny {
            let _ = httpfront::write_denial(
                &mut client,
                &outcome.reason,
                &cx.session.to_string(),
                &self.config.profile,
            )
            .await;
            self.emit(&cx, &outcome.reason, Action::Deny, outcome.evidence, None, started).await;
            return Ok(());
        }

        let mut upstream = match self.guard.connect(&request.authority).await {
            Ok(s) => s,
            Err(e) => {
                let _ =
                    httpfront::write_status(&mut client, "502 Bad Gateway", &e.to_string()).await;
                self.emit_guard_failure(&cx, &e, outcome.evidence, started).await;
                return Ok(());
            }
        };

        if request.is_connect {
            client
                .get_mut()
                .write_all(
                    b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: bot-marshal\r\n\r\n",
                )
                .await?;

            // Anything the buffered reader pulled in past the request head has to lead the
            // tunnel, or a pipelining client's first TLS record arrives truncated.
            let leftover = client.buffer().to_vec();
            let mut stream = Rewind::new(client.into_inner(), leftover);
            let authority = request.authority.clone();

            let intercept = self
                .intercepts(&authority)
                .then(|| Arc::clone(self.config.tls.as_ref().expect("checked by intercepts")));

            if let Some(engine) = intercept {
                // The CONNECT itself is allowed here; each request inside the tunnel is
                // evaluated separately once decrypted, and audited on its own.
                self.emit(&cx, &outcome.reason, Action::Allow, outcome.evidence, None, started)
                    .await;

                let handler = Arc::new(MitmHandler {
                    chain: Arc::clone(&self.chain),
                    audit: Arc::clone(&self.audit),
                    authority: authority.clone(),
                    session: cx.session.clone(),
                    profile: Arc::clone(&self.config.profile),
                    client_addr: peer,
                    request_transforms: self.request_transforms.clone(),
                });

                if let Err(e) = mitm::intercept(stream, upstream, engine, handler).await {
                    tracing::debug!(peer = %peer, authority = %authority, error = %e,
                        "intercepted tunnel ended");
                }
                return Ok(());
            }

            // Not intercepting. Cross-check the TLS SNI against the authority the client
            // asked us to allow: a tunnel opened to an allowlisted host that then presents
            // SNI for a different one is an attempt to launder a denied destination through
            // an allowed CONNECT.
            //
            // The check runs on the relay's first client chunk rather than by peeking before
            // the relay starts, so a server-speaks-first protocol is not held up waiting for
            // a client that has nothing to say yet.
            self.emit(&cx, &outcome.reason, Action::Allow, outcome.evidence, None, started).await;

            let result = tunnel::relay_inspected(&mut stream, &mut upstream, |opening| {
                check_sni(opening, &authority)
            })
            .await;

            if let Err(tunnel::RelayError::Rejected(why)) = result {
                tracing::warn!(peer = %peer, authority = %authority, "{why}");
                let reason = Reason::new("allowlist", "sni_authority_mismatch", why);
                self.emit(&cx, &reason, Action::Deny, Evidence::new(), None, started).await;
            }
            return Ok(());
        } else {
            // Replay the head verbatim, rewritten to origin-form. The proxy has promised only
            // to observe plaintext at M1, so it must not normalise headers on the way past.
            let head = rewrite_to_origin_form(&request);
            upstream.write_all(&head).await?;
        }

        self.emit(&cx, &outcome.reason, Action::Allow, outcome.evidence, None, started).await;
        let _ = tunnel::relay(&mut client, &mut upstream).await;
        Ok(())
    }

    /// Whether this destination will have its TLS intercepted.
    fn intercepts(&self, authority: &Authority) -> bool {
        self.config.tls.is_some() && self.config.passthrough.matches(&authority.host).is_none()
    }

    fn context(
        &self,
        peer: std::net::SocketAddr,
        authority: Authority,
        method: &str,
        path: &str,
        phase: marshal_core::Phase,
    ) -> RequestContext {
        RequestContext {
            session: SessionId::unidentified(),
            profile: Arc::clone(&self.config.profile),
            ingress: IngressMode::Explicit,
            phase,
            client_addr: peer,
            authority,
            method: http::Method::from_bytes(method.as_bytes()).unwrap_or(http::Method::CONNECT),
            uri: path.parse().unwrap_or_else(|_| http::Uri::from_static("/")),
            headers: http::HeaderMap::new(),
            body: BodyHandle::Empty,
            evidence: Evidence::new(),
        }
    }

    async fn emit(
        &self,
        cx: &RequestContext,
        reason: &Reason,
        action: Action,
        evidence: Evidence,
        status_code: Option<u16>,
        started: Instant,
    ) {
        self.audit
            .emit(AuditRecord {
                session: cx.session.to_string(),
                // M1 has no session resolution, so nothing is attributed. Saying so is more
                // useful than implying an identity we cannot establish.
                attributed: false,
                resolver: None,
                profile: cx.profile.to_string(),
                ingress: "explicit".into(),
                host: cx.authority.host.clone(),
                method: cx.method.to_string(),
                path: cx.uri.to_string(),
                action,
                reason: reason.clone(),
                trail: evidence.trail,
                status_code,
                duration_ms: started.elapsed().as_millis() as u64,
            })
            .await;
    }

    async fn emit_guard_failure(
        &self,
        cx: &RequestContext,
        e: &GuardError,
        evidence: Evidence,
        started: Instant,
    ) {
        // A guard rejection is a denial, not a transport hiccup: it must appear in the audit
        // trail as something the proxy refused.
        let code = match e {
            GuardError::Blocked { .. } => "upstream_blocked",
            GuardError::Resolve { .. } | GuardError::NoAddresses { .. } => "upstream_unresolvable",
            GuardError::Connect { .. } => "upstream_unreachable",
        };
        let reason = Reason::new("upstream_guard", code, e.to_string());
        self.emit(cx, &reason, Action::Deny, evidence, None, started).await;
    }
}

/// Compare the TLS SNI in the client's opening bytes with the CONNECT authority.
///
/// Bytes that are not a ClientHello, or a ClientHello with no SNI, are not a lie — a bare-IP
/// CONNECT legitimately has neither — so only a present-and-different name is refused.
fn check_sni(opening: &[u8], authority: &Authority) -> Result<(), String> {
    let Some(sni) = sniff::sni_from_client_hello(opening) else {
        return Ok(());
    };
    if sni == authority.host.to_ascii_lowercase() {
        Ok(())
    } else {
        Err(format!(
            "CONNECT authority `{}` does not match TLS SNI `{sni}`; refusing to relay",
            authority.host
        ))
    }
}

fn guard_reply(e: &GuardError) -> Reply {
    match e {
        GuardError::Blocked { .. } => Reply::NotAllowed,
        GuardError::Resolve { .. } | GuardError::NoAddresses { .. } => Reply::HostUnreachable,
        GuardError::Connect { .. } => Reply::ConnectionRefused,
    }
}

/// Turn `GET http://host/path HTTP/1.1` into `GET /path HTTP/1.1`, leaving every other byte
/// of the head untouched.
fn rewrite_to_origin_form(request: &ProxyRequest) -> Vec<u8> {
    let Some(line_end) = request.raw_head.windows(2).position(|w| w == b"\r\n") else {
        return request.raw_head.clone();
    };
    let (line, rest) = request.raw_head.split_at(line_end);
    let line = String::from_utf8_lossy(line);
    let mut parts = line.split_whitespace();
    let (method, _target, version) = (
        parts.next().unwrap_or("GET"),
        parts.next().unwrap_or("/"),
        parts.next().unwrap_or("HTTP/1.1"),
    );

    let mut out = format!("{method} {} {version}", request.path).into_bytes();
    out.extend_from_slice(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_absolute_form_to_origin_form_preserving_headers() {
        let req = ProxyRequest {
            authority: Authority { host: "example.com".into(), port: 80 },
            method: "GET".into(),
            path: "/a?b=1".into(),
            raw_head:
                b"GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nX-K: v\r\n\r\n"
                    .to_vec(),
            is_connect: false,
        };
        let out = String::from_utf8(rewrite_to_origin_form(&req)).unwrap();
        assert!(out.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com\r\n"), "headers must pass through untouched");
        assert!(out.contains("X-K: v\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }
}
