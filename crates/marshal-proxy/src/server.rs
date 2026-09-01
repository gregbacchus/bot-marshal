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
use crate::sniff::{self, Protocol};
use crate::socks5::{self, Reply};
use crate::tunnel;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub listen: String,
    /// Which profile applies. Real session resolution arrives in M4; until then every
    /// connection is explicitly *unattributed*, and the audit record says so rather than
    /// implying an identity the proxy cannot yet establish.
    pub profile: Arc<str>,
}

pub struct Server {
    config: ServerConfig,
    chain: Arc<Chain>,
    guard: Arc<UpstreamGuard>,
    audit: Arc<dyn AuditSink>,
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
        Self { config, chain, guard, audit }
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
            "explicit proxy listening"
        );
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

        let cx = self.context(peer, authority.clone(), "CONNECT", "");
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
        );
        let outcome = self.chain.evaluate(&cx).await;

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

            // Cross-check the TLS SNI against the authority the client asked us to allow.
            // A tunnel opened to an allowlisted host that then presents SNI for a different
            // one is either a broken client or an attempt to launder a denied destination
            // through an allowed CONNECT; neither should be relayed.
            //
            // The check runs on the relay's first client chunk rather than by peeking before
            // the relay starts, so a server-speaks-first protocol is not held up waiting for
            // a client that has nothing to say yet.
            let authority = request.authority.clone();
            self.emit(&cx, &outcome.reason, Action::Allow, outcome.evidence, None, started).await;

            let result = tunnel::relay_inspected(&mut client, &mut upstream, |opening| {
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

    fn context(
        &self,
        peer: std::net::SocketAddr,
        authority: Authority,
        method: &str,
        path: &str,
    ) -> RequestContext {
        RequestContext {
            session: SessionId::unidentified(),
            profile: Arc::clone(&self.config.profile),
            ingress: IngressMode::Explicit,
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
