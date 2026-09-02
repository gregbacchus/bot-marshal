//! The explicit-proxy listener.
//!
//! One TCP port serves HTTP `CONNECT`, absolute-form HTTP, and SOCKS5. Every accepted
//! connection follows the same path regardless of which: resolve a session, evaluate the
//! policy chain against the requested authority, and only then touch the network. Nothing
//! upstream is contacted before a verdict exists.

use std::sync::Arc;
use std::time::Instant;

use std::collections::HashMap;

use marshal_core::{
    Action, AuditRecord, AuditSink, Authority, BodyHandle, ConnInfo, Evidence, IngressMode, Reason,
    RequestContext, Resolved,
};
use marshal_policy::Chain;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::guard::{GuardError, UpstreamGuard};
use crate::httpfront::{self, ProxyRequest};
use crate::mitm::{self, MitmHandler, TlsEngine};
use crate::rewind::Rewind;
use crate::sessions::SessionRegistry;
use crate::sniff::{self, Protocol};
use crate::socks5::{self, Reply};
use crate::stats::SessionStats;
use crate::tunnel;

#[derive(Clone)]
pub struct ServerConfig {
    pub listen: String,
    /// Optional Unix-domain listener. Worth having because `SO_PEERCRED` on it is the only
    /// unspoofable, race-free identity available on a single host.
    pub unix_socket: Option<std::path::PathBuf>,
    /// Present when a CA is configured. Without it the proxy still runs, but sees only the
    /// tunnel destination — which is the honest behaviour when no CA has been created, not a
    /// degraded mode to hide.
    pub tls: Option<Arc<TlsEngine>>,
    /// Transparent listeners. Each carries its own address so `listener_port` identity —
    /// nftables steering different uids or cgroups to different ports — has something to key
    /// on.
    pub transparent: Vec<String>,
    /// Hosts tunnelled without interception. Certificate-pinned clients belong here, as does
    /// anything whose traffic must demonstrably not be read.
    pub passthrough: marshal_policy::HostMatcher,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("unix_socket", &self.unix_socket)
            .field("intercepting", &self.tls.is_some())
            .finish()
    }
}

/// A resolved connection: who it is, and the chain that therefore applies.
#[derive(Clone)]
struct Session {
    resolved: Resolved,
    chain: Arc<Chain>,
    /// Response transforms for this profile. Per-session rather than per-server, because
    /// which tools are visible depends on which profile applies.
    response_transforms: Vec<Arc<dyn marshal_core::ResponseTransform>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("session", &self.resolved.session)
            .field("profile", &self.resolved.profile)
            .field("attributed", &self.resolved.attributed)
            .finish()
    }
}

pub struct Server {
    config: ServerConfig,
    /// One chain per profile. Which one applies is decided per connection.
    chains: HashMap<Arc<str>, Arc<Chain>>,
    /// Response transforms per profile, alongside the chains.
    response_transforms: HashMap<Arc<str>, Vec<Arc<dyn marshal_core::ResponseTransform>>>,
    sessions: Arc<SessionRegistry>,
    guard: Arc<UpstreamGuard>,
    audit: Arc<dyn AuditSink>,
    request_transforms: Vec<Arc<dyn marshal_core::RequestTransform>>,
    stats: Arc<SessionStats>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Server {
    pub fn new(
        config: ServerConfig,
        chains: HashMap<Arc<str>, Arc<Chain>>,
        sessions: Arc<SessionRegistry>,
        guard: Arc<UpstreamGuard>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            config,
            chains,
            response_transforms: HashMap::new(),
            sessions,
            guard,
            audit,
            request_transforms: Vec::new(),
            stats: Arc::new(SessionStats::default()),
        }
    }

    pub fn stats(&self) -> Arc<SessionStats> {
        Arc::clone(&self.stats)
    }

    /// Resolve a connection to a session and the chain that applies to it.
    ///
    /// A resolver naming a profile that does not exist is a configuration error caught at
    /// startup; reaching it here means falling back rather than serving an arbitrary chain.
    async fn session_for(&self, conn: &ConnInfo) -> Option<Session> {
        let resolved = self.sessions.resolve(conn).await;
        match self.chains.get(&resolved.profile) {
            Some(chain) => {
                let response_transforms =
                    self.response_transforms.get(&resolved.profile).cloned().unwrap_or_default();
                Some(Session { resolved, chain: Arc::clone(chain), response_transforms })
            }
            None => {
                tracing::error!(
                    profile = %resolved.profile,
                    "a session resolver named a profile with no chain; refusing the connection"
                );
                None
            }
        }
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

    /// Response transforms, keyed by profile.
    pub fn with_response_transforms(
        mut self,
        transforms: HashMap<Arc<str>, Vec<Arc<dyn marshal_core::ResponseTransform>>>,
    ) -> Self {
        self.response_transforms = transforms;
        self
    }

    /// Bind and serve until cancelled. Returns the bound address via `on_bind`, which lets
    /// tests use port 0 and discover what they got.
    pub async fn run(self, on_bind: impl FnOnce(std::net::SocketAddr)) -> std::io::Result<()> {
        let listener = TcpListener::bind(&self.config.listen).await?;
        let local = listener.local_addr()?;
        tracing::info!(
            listen = %local,
            profiles = ?self.chains.keys().map(|k| &**k).collect::<Vec<_>>(),
            resolvers = ?self.sessions.resolver_names(),
            intercepting = self.config.tls.is_some(),
            "explicit proxy listening"
        );
        if self.config.tls.is_none() {
            tracing::warn!(
                "no CA configured: TLS is tunnelled, so policy sees the destination host but \
                 not the request. Run `marshal ca init` to intercept."
            );
            let skipped: Vec<&str> =
                self.chains.values().flat_map(|c| c.request_only_layers()).collect();
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

        let transparent_addrs = self.config.transparent.clone();
        let this = Arc::new(self);

        // Transparent listeners run alongside the explicit one. A connection arriving here
        // was redirected by the firewall and does not know it is proxied, so the destination
        // has to be recovered from conntrack rather than asked for.
        let mut transparent = Vec::new();
        for addr in &transparent_addrs {
            match TcpListener::bind(addr).await {
                Ok(l) => {
                    tracing::info!(listen = %l.local_addr()?, "transparent listener ready");
                    transparent.push(l);
                }
                Err(e) => {
                    tracing::error!(listen = %addr, error = %e,
                        "could not bind a transparent listener");
                }
            }
        }
        for listener in transparent {
            let this = Arc::clone(&this);
            tokio::spawn(async move {
                loop {
                    let Ok((stream, peer)) = listener.accept().await else { continue };
                    let this = Arc::clone(&this);
                    tokio::spawn(async move {
                        if let Err(e) = this.serve_transparent(stream, peer).await {
                            tracing::debug!(peer = %peer, error = %e,
                                "transparent connection ended");
                        }
                    });
                }
            });
        }

        // The Unix listener exists for `SO_PEERCRED`, which is the only identity on a single
        // host that is both unspoofable and free of a lookup race.
        let unix = match &this.config.unix_socket {
            Some(path) => match bind_unix(path) {
                Ok(l) => {
                    tracing::info!(path = %path.display(), "unix listener ready (SO_PEERCRED)");
                    Some(l)
                }
                Err(e) => {
                    tracing::error!(path = %path.display(), error = %e,
                        "could not bind the unix listener; continuing without it");
                    None
                }
            },
            None => None,
        };

        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
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
                accepted = accept_unix(unix.as_ref()) => {
                    let Some(stream) = accepted else { continue };
                    let this = Arc::clone(&this);
                    tokio::spawn(async move {
                        if let Err(e) = this.serve_unix_connection(stream).await {
                            tracing::debug!(error = %e, "unix connection ended");
                        }
                    });
                }
            }
        }
    }

    /// A transparently redirected connection.
    ///
    /// The client believes it is talking to the origin, so there is no CONNECT and no proxy
    /// header. The destination comes from `SO_ORIGINAL_DST` and the hostname from the TLS SNI
    /// or the HTTP `Host` header; policy is evaluated on the name, because an address is only
    /// what the client's DNS happened to return.
    async fn serve_transparent(
        self: Arc<Self>,
        stream: TcpStream,
        peer: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        let started = Instant::now();
        let local = stream.local_addr()?;
        let _ = stream.set_nodelay(true);

        let destination = match crate::transparent::original_dst(&stream) {
            Ok(d) => d,
            Err(e) => {
                // Without a destination there is nowhere to send the connection, and guessing
                // would mean connecting somewhere the client never asked for.
                tracing::warn!(peer = %peer, error = %e,
                    "dropping a connection whose original destination could not be recovered");
                return Ok(());
            }
        };

        // Read the opening bytes to recover the hostname, then replay them upstream.
        let mut opening = vec![0u8; 4096];
        let n = match stream.try_read(&mut opening) {
            Ok(n) => n,
            Err(_) => {
                stream.readable().await?;
                stream.try_read(&mut opening).unwrap_or(0)
            }
        };
        opening.truncate(n);

        let intercepted = crate::transparent::classify(destination, &opening);
        let authority = intercepted.authority();
        let mut client = Rewind::new(stream, opening);

        let mut conn = self.conn_info(peer, local);
        conn.ingress = IngressMode::Transparent;
        self.sessions.attach_peer_cred(&mut conn);

        let Some(session) = self.session_for(&conn).await else { return Ok(()) };
        if !session.resolved.attributed && self.sessions.deny_unidentified() {
            return Ok(());
        }

        // Phase::Request: unlike a CONNECT, a transparent connection already carries the
        // hostname, so host-level layers can decide properly. Request-level layers still need
        // interception to see method and path.
        let cx = self.context(
            &session,
            peer,
            authority.clone(),
            if intercepted.tls { "CONNECT" } else { "GET" },
            "/",
            marshal_core::Phase::Connect,
        );
        let outcome = session.chain.evaluate(&cx).await;

        if outcome.action == Action::Deny {
            // There is no proxy protocol to answer with, so a refusal is a closed connection.
            // Recording it is the only way anyone learns it happened.
            self.emit_session(
                &session,
                &cx,
                &outcome.reason,
                Action::Deny,
                outcome.evidence,
                None,
                started,
            )
            .await;
            return Ok(());
        }

        // Connect to the address the client itself resolved, checked by the guard. Resolving
        // the name again here would let a hostile DNS answer differ between the check and
        // the connect.
        let literal = Authority { host: destination.ip().to_string(), port: destination.port() };
        let mut upstream = match self.guard.connect(&literal).await {
            Ok(s) => s,
            Err(e) => {
                self.emit_guard_failure(&session, &cx, &e, outcome.evidence, started).await;
                return Ok(());
            }
        };

        self.emit_session(
            &session,
            &cx,
            &outcome.reason,
            Action::Allow,
            outcome.evidence,
            None,
            started,
        )
        .await;

        let _ = tunnel::relay(&mut client, &mut upstream).await;
        Ok(())
    }

    /// A Unix-domain connection. Identity comes from `SO_PEERCRED` rather than from any
    /// lookup, so it is attached before anything is read.
    async fn serve_unix_connection(
        self: Arc<Self>,
        stream: tokio::net::UnixStream,
    ) -> std::io::Result<()> {
        let cred = crate::sessions::peercred::peer_cred_for_unix(
            &stream,
            self.sessions.needs_enrichment(),
        );

        // A Unix socket has no meaningful addresses; synthetic loopback ones keep the rest of
        // the pipeline uniform, and the credential is what actually identifies the peer.
        let peer: std::net::SocketAddr = "127.0.0.1:0".parse().expect("literal");
        let mut client = BufReader::new(stream);

        let mut first = [0u8; 1];
        if client.read_exact(&mut first).await.is_err() {
            return Ok(());
        }
        if sniff::detect(first[0]) != Protocol::Http {
            tracing::debug!("only HTTP proxying is supported on the unix listener");
            return Ok(());
        }

        self.serve_http_generic(client, peer, peer, first[0], cred).await
    }

    async fn serve_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        let local = stream.local_addr()?;
        let _ = stream.set_nodelay(true);
        let mut client = BufReader::new(stream);

        // One byte tells us which protocol we are speaking. It is handed on rather than
        // pushed back, so no un-read buffer has to be threaded through the front-ends.
        let mut first = [0u8; 1];
        if client.read_exact(&mut first).await.is_err() {
            return Ok(()); // client hung up before saying anything
        }

        match sniff::detect(first[0]) {
            Protocol::Socks5 => self.serve_socks5(client, peer, local).await,
            Protocol::Socks4 => {
                tracing::debug!(peer = %peer, "refused SOCKS4; only SOCKS5 is supported");
                Ok(())
            }
            Protocol::Http => self.serve_http(client, peer, local, first[0]).await,
        }
    }

    async fn serve_socks5(
        self: Arc<Self>,
        mut client: BufReader<TcpStream>,
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        let started = Instant::now();

        let request = match socks5::handshake(&mut client).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(peer = %peer, error = %e, "socks5 handshake failed");
                return Ok(());
            }
        };
        let authority = request.authority;

        let mut conn = self.conn_info(peer, local);
        conn.proxy_auth = request.credential;
        self.sessions.attach_peer_cred(&mut conn);

        let Some(session) = self.session_for(&conn).await else {
            let _ = socks5::reply(&mut client, Reply::GeneralFailure).await;
            return Ok(());
        };
        if !session.resolved.attributed && self.sessions.deny_unidentified() {
            let _ = socks5::reply(&mut client, Reply::NotAllowed).await;
            return Ok(());
        }

        let cx = self.context(
            &session,
            peer,
            authority.clone(),
            "CONNECT",
            "",
            marshal_core::Phase::Connect,
        );
        let outcome = session.chain.evaluate(&cx).await;

        if outcome.action == Action::Deny {
            let _ = socks5::reply(&mut client, Reply::NotAllowed).await;
            self.emit_session(
                &session,
                &cx,
                &outcome.reason,
                Action::Deny,
                outcome.evidence,
                None,
                started,
            )
            .await;
            return Ok(());
        }

        let mut upstream = match self.guard.connect(&authority).await {
            Ok(s) => s,
            Err(e) => {
                let _ = socks5::reply(&mut client, guard_reply(&e)).await;
                self.emit_guard_failure(&session, &cx, &e, outcome.evidence, started).await;
                return Ok(());
            }
        };

        socks5::reply(&mut client, Reply::Succeeded).await.ok();
        self.emit_session(
            &session,
            &cx,
            &outcome.reason,
            Action::Allow,
            outcome.evidence,
            None,
            started,
        )
        .await;

        let _ = tunnel::relay(&mut client, &mut upstream).await;
        Ok(())
    }

    async fn serve_http(
        self: Arc<Self>,
        client: BufReader<TcpStream>,
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
        first_byte: u8,
    ) -> std::io::Result<()> {
        self.serve_http_generic(client, peer, local, first_byte, None).await
    }

    async fn serve_http_generic<S>(
        self: Arc<Self>,
        mut client: BufReader<S>,
        peer: std::net::SocketAddr,
        local: std::net::SocketAddr,
        first_byte: u8,
        peer_cred: Option<marshal_core::PeerCred>,
    ) -> std::io::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let started = Instant::now();

        let request: ProxyRequest = match httpfront::read_request(&mut client, first_byte).await {
            Ok(r) => r,
            Err(e) => {
                let _ =
                    httpfront::write_status(&mut client, "400 Bad Request", &e.to_string()).await;
                return Ok(());
            }
        };

        let mut conn = self.conn_info(peer, local);
        conn.proxy_auth = request.proxy_auth.clone();
        conn.peer_cred = peer_cred;
        self.sessions.attach_peer_cred(&mut conn);

        let Some(session) = self.session_for(&conn).await else {
            let _ = httpfront::write_status(
                &mut client,
                "500 Internal Server Error",
                "session resolution failed",
            )
            .await;
            return Ok(());
        };
        if !session.resolved.attributed && self.sessions.deny_unidentified() {
            let reason = Reason::new(
                "sessions",
                "unidentified",
                "this connection could not be attributed to a session, and the proxy is \
                 configured to refuse unattributed traffic",
            );
            let _ = httpfront::write_denial(
                &mut client,
                &reason,
                &session.resolved.session.to_string(),
                &session.resolved.profile,
            )
            .await;
            return Ok(());
        }

        let cx = self.context(
            &session,
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
        let mut outcome = session.chain.evaluate(&cx).await;

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
            && !session.chain.request_only_layers().is_empty()
        {
            outcome.action = Action::Allow;
            outcome.reason = Reason::new(
                "default_action",
                "connect_provisional",
                format!(
                    "no host-level layer refused `{}`; the decision is deferred to the \
                     request-level layers {:?} once TLS is intercepted",
                    request.authority.host,
                    session.chain.request_only_layers()
                ),
            );
        }

        if outcome.action == Action::Deny {
            let _ = httpfront::write_denial(
                &mut client,
                &outcome.reason,
                &cx.session.to_string(),
                &session.resolved.profile,
            )
            .await;
            self.emit_session(
                &session,
                &cx,
                &outcome.reason,
                Action::Deny,
                outcome.evidence,
                None,
                started,
            )
            .await;
            return Ok(());
        }

        let mut upstream = match self.guard.connect(&request.authority).await {
            Ok(s) => s,
            Err(e) => {
                let _ =
                    httpfront::write_status(&mut client, "502 Bad Gateway", &e.to_string()).await;
                self.emit_guard_failure(&session, &cx, &e, outcome.evidence, started).await;
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
                self.emit_session(
                    &session,
                    &cx,
                    &outcome.reason,
                    Action::Allow,
                    outcome.evidence,
                    None,
                    started,
                )
                .await;

                let handler = Arc::new(MitmHandler {
                    chain: Arc::clone(&session.chain),
                    audit: Arc::clone(&self.audit),
                    authority: authority.clone(),
                    session: cx.session.clone(),
                    profile: Arc::clone(&session.resolved.profile),
                    client_addr: peer,
                    request_transforms: self.request_transforms.clone(),
                    response_transforms: session.response_transforms.clone(),
                    attributed: session.resolved.attributed,
                    resolver: session.resolved.resolver.clone(),
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
            self.emit_session(
                &session,
                &cx,
                &outcome.reason,
                Action::Allow,
                outcome.evidence,
                None,
                started,
            )
            .await;

            let result = tunnel::relay_inspected(&mut stream, &mut upstream, |opening| {
                check_sni(opening, &authority)
            })
            .await;

            if let Err(tunnel::RelayError::Rejected(why)) = result {
                tracing::warn!(peer = %peer, authority = %authority, "{why}");
                let reason = Reason::new("allowlist", "sni_authority_mismatch", why);
                self.emit_session(
                    &session,
                    &cx,
                    &reason,
                    Action::Deny,
                    Evidence::new(),
                    None,
                    started,
                )
                .await;
            }
            return Ok(());
        } else {
            // Replay the head verbatim, rewritten to origin-form. The proxy has promised only
            // to observe plaintext at M1, so it must not normalise headers on the way past.
            let head = rewrite_to_origin_form(&request);
            upstream.write_all(&head).await?;
        }

        self.emit_session(
            &session,
            &cx,
            &outcome.reason,
            Action::Allow,
            outcome.evidence,
            None,
            started,
        )
        .await;
        let _ = tunnel::relay(&mut client, &mut upstream).await;
        Ok(())
    }

    /// Whether this destination will have its TLS intercepted.
    fn intercepts(&self, authority: &Authority) -> bool {
        self.config.tls.is_some() && self.config.passthrough.matches(&authority.host).is_none()
    }

    /// What a resolver gets to look at. Kernel credentials are attached separately, since
    /// obtaining them depends on the transport.
    fn conn_info(&self, peer: std::net::SocketAddr, local: std::net::SocketAddr) -> ConnInfo {
        ConnInfo {
            ingress: IngressMode::Explicit,
            client_addr: peer,
            local_addr: local,
            proxy_auth: None,
            peer_cred: None,
        }
    }

    fn context(
        &self,
        session: &Session,
        peer: std::net::SocketAddr,
        authority: Authority,
        method: &str,
        path: &str,
        phase: marshal_core::Phase,
    ) -> RequestContext {
        RequestContext {
            session: session.resolved.session.clone(),
            profile: Arc::clone(&session.resolved.profile),
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

    #[allow(clippy::too_many_arguments)]
    async fn emit_session(
        &self,
        session: &Session,
        cx: &RequestContext,
        reason: &Reason,
        action: Action,
        evidence: Evidence,
        status_code: Option<u16>,
        started: Instant,
    ) {
        self.stats.record(&cx.session, action == Action::Allow);
        self.audit
            .emit(AuditRecord {
                session: cx.session.to_string(),
                attributed: session.resolved.attributed,
                resolver: session.resolved.resolver.clone(),
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
        session: &Session,
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
        self.emit_session(session, cx, &reason, Action::Deny, evidence, None, started).await;
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

/// Bind a Unix listener, clearing a stale socket file first.
fn bind_unix(path: &std::path::Path) -> std::io::Result<tokio::net::UnixListener> {
    if path.exists() {
        // A leftover socket from a previous run would otherwise make binding fail forever.
        std::fs::remove_file(path)?;
    }
    if let Some(dir) = path.parent()
        && !dir.as_os_str().is_empty()
    {
        std::fs::create_dir_all(dir)?;
    }
    tokio::net::UnixListener::bind(path)
}

/// Accept from an optional Unix listener, or wait forever when there is none, so the
/// `select!` arm is well-formed either way.
async fn accept_unix(
    listener: Option<&tokio::net::UnixListener>,
) -> Option<tokio::net::UnixStream> {
    match listener {
        Some(l) => l.accept().await.ok().map(|(s, _)| s),
        None => std::future::pending().await,
    }
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
            proxy_auth: None,
        };
        let out = String::from_utf8(rewrite_to_origin_form(&req)).unwrap();
        assert!(out.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com\r\n"), "headers must pass through untouched");
        assert!(out.contains("X-K: v\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }
}
