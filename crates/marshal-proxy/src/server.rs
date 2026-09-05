//! The explicit-proxy listener.
//!
//! One TCP port serves HTTP `CONNECT`, absolute-form HTTP, and SOCKS5. Every accepted
//! connection follows the same path regardless of which: resolve an identity, evaluate the
//! policy chain against the requested authority, and only then touch the network. Nothing
//! upstream is contacted before a verdict exists.

use std::sync::Arc;
use std::time::Instant;

use marshal_core::{
    Action, AuditRecord, AuditSink, Authority, BodyHandle, ConnInfo, Evidence, IngressMode, Reason,
    RequestContext, Resolved,
};
use marshal_policy::Chain;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::httpfront::{self, ProxyRequest};
use crate::mitm::{self, MitmHandler};
use crate::rewind::Rewind;
use crate::runtime::{Runtime, RuntimeHandle};
use crate::sniff::{self, Protocol};
use crate::socks5::{self, Reply};
use crate::stats::IdentityStats;
use crate::tunnel;
use marshal_http::{GuardError, UpstreamGuard};

#[derive(Clone)]
pub struct ServerConfig {
    /// One or more addresses, all serving identical CONNECT/SOCKS5/absolute-form HTTP. More
    /// than one exists for the `listener_port` identity resolver: agents that share a uid but
    /// are each told to use a different one of these addresses get told apart by which
    /// listener accepted them — no firewall redirect involved, just multiple explicit ports.
    pub listen: Vec<String>,
    /// Optional Unix-domain listener. Worth having because `SO_PEERCRED` on it is the only
    /// unspoofable, race-free identity available on a single host.
    pub unix_socket: Option<std::path::PathBuf>,
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConfig")
            .field("listen", &self.listen)
            .field("unix_socket", &self.unix_socket)
            .finish()
    }
}

/// A resolved connection: who it is, and the chain that therefore applies.
#[derive(Clone)]
struct Attribution {
    resolved: Resolved,
    chain: Arc<Chain>,
    /// Response transforms for this profile. Per-identity rather than per-server, because
    /// which tools are visible depends on which profile applies.
    response_transforms: Vec<Arc<dyn marshal_core::ResponseTransform>>,
    /// Request transforms for this profile, most importantly secret injection — a swap
    /// declared under one profile must never fire for an identity resolved into another.
    request_transforms: Vec<Arc<dyn marshal_core::RequestTransform>>,
    /// Responders for this profile — see [`marshal_core::RequestResponder`]. Only consulted
    /// on intercepted traffic: answering a request requires having parsed it, which the plain
    /// relay path deliberately does not do.
    responders: Vec<Arc<dyn marshal_core::RequestResponder>>,
}

impl std::fmt::Debug for Attribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attribution")
            .field("identity", &self.resolved.identity)
            .field("profile", &self.resolved.profile_label())
            .field("attributed", &self.resolved.attributed)
            .finish()
    }
}

pub struct Server {
    config: ServerConfig,
    /// Everything derived from configuration, swappable as a unit so a reload cannot be
    /// observed half-applied.
    runtime: Arc<RuntimeHandle>,
    guard: Arc<UpstreamGuard>,
    audit: Arc<dyn AuditSink>,
    stats: Arc<IdentityStats>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Server {
    pub fn new(
        config: ServerConfig,
        runtime: Arc<RuntimeHandle>,
        guard: Arc<UpstreamGuard>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self { config, runtime, guard, audit, stats: Arc::new(IdentityStats::default()) }
    }

    /// The handle a reload writes through.
    pub fn runtime(&self) -> Arc<RuntimeHandle> {
        Arc::clone(&self.runtime)
    }

    pub fn stats(&self) -> Arc<IdentityStats> {
        Arc::clone(&self.stats)
    }

    /// Resolve a connection to an identity and the chain that applies to it.
    ///
    /// A resolver naming a profile that does not exist is a configuration error caught at
    /// startup; reaching it here means falling back rather than serving an arbitrary chain.
    async fn resolve_attribution(&self, conn: &ConnInfo, runtime: &Runtime) -> Option<Attribution> {
        let resolved = runtime.identities.resolve(conn).await;

        // No profile named — an unattributed connection with no `identities.unidentified.
        // profile` override, or `marshal run` without `--profile`. The embedded `profile:`
        // applies, which has no name and so isn't in `chains` at all.
        if resolved.profile.is_none() {
            return Some(Attribution {
                resolved,
                chain: Arc::clone(&runtime.default_chain),
                response_transforms: runtime.default_response_transforms.clone(),
                request_transforms: runtime.default_request_transforms.clone(),
                responders: runtime.default_responders.clone(),
            });
        }

        let name = resolved.profile.clone().expect("the unnamed profile is handled above");
        match runtime.chains.get(&name) {
            Some(chain) => {
                let response_transforms =
                    runtime.response_transforms.get(&name).cloned().unwrap_or_default();
                let request_transforms =
                    runtime.request_transforms.get(&name).cloned().unwrap_or_default();
                let responders = runtime.responders.get(&name).cloned().unwrap_or_default();
                Some(Attribution {
                    resolved,
                    chain: Arc::clone(chain),
                    response_transforms,
                    request_transforms,
                    responders,
                })
            }
            None => {
                tracing::error!(
                    profile = %name,
                    "an identity resolver named a profile with no chain; refusing the connection"
                );
                None
            }
        }
    }

    /// Bind and serve until cancelled. Returns the *first* configured address via `on_bind`,
    /// which lets tests use port 0 on a single-address config and discover what they got.
    pub async fn run(self, on_bind: impl FnOnce(std::net::SocketAddr)) -> std::io::Result<()> {
        let Some((first_addr, rest_addrs)) = self.config.listen.split_first() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no explicit listen address configured",
            ));
        };
        let rest_addrs = rest_addrs.to_vec();

        let listener = TcpListener::bind(first_addr).await?;
        let local = listener.local_addr()?;
        let runtime = self.runtime.load();
        tracing::info!(
            listen = %local,
            profiles = ?runtime.chains.keys().map(|k| &**k).collect::<Vec<_>>(),
            resolvers = ?runtime.identities.resolver_names(),
            intercepting = true,
            "explicit proxy listening"
        );

        // Warn mode is already reported per profile by `validate()`'s diagnostics, which
        // `build_runtime` logs at every startup (including for the embedded fallback, which
        // has no name to appear in `runtime.chains` and so cannot be listed here) — a second,
        // coarser summary here would just restate that, incompletely. `warn_only_profiles()`
        // remains for the management API (`/v1/status`), which has no equivalent already.

        // Interception is mandatory (see `Runtime::tls`), so the only way a request-level
        // layer is skipped is a host deliberately listed in `tls.passthrough`. Worth saying
        // once at startup, since it is otherwise silent per-connection.
        if !runtime.passthrough.is_empty() {
            let skipped: Vec<&str> =
                runtime.chains.values().flat_map(|c| c.request_only_layers()).collect();
            if !skipped.is_empty() {
                tracing::warn!(
                    layers = ?skipped,
                    passthrough_hosts = "see tls.passthrough",
                    "these layers need a decrypted request and will not evaluate for hosts \
                     in tls.passthrough"
                );
            }
        }
        on_bind(local);

        let this = Arc::new(self);

        // Additional explicit addresses, if configured, run exactly the same
        // CONNECT/SOCKS5/HTTP pipeline as the primary listener — the only thing that differs
        // is which port accepted the connection, which is what `listener_port` identity keys
        // on. Each gets its own accept loop rather than a shared one, so a slow accept on one
        // address can never block another's.
        for addr in &rest_addrs {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    tracing::info!(listen = %listener.local_addr()?, "explicit listener ready");
                    let this = Arc::clone(&this);
                    tokio::spawn(async move {
                        loop {
                            let Ok((stream, peer)) = listener.accept().await else { continue };
                            let this = Arc::clone(&this);
                            tokio::spawn(async move {
                                if let Err(e) = this.serve_connection(stream, peer).await {
                                    tracing::debug!(peer = %peer, error = %e, "connection ended");
                                }
                            });
                        }
                    });
                }
                Err(e) => {
                    tracing::error!(listen = %addr, error = %e,
                        "could not bind an additional explicit listener");
                }
            }
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

    /// A Unix-domain connection. Identity comes from `SO_PEERCRED` rather than from any
    /// lookup, so it is attached before anything is read.
    async fn serve_unix_connection(
        self: Arc<Self>,
        stream: tokio::net::UnixStream,
    ) -> std::io::Result<()> {
        let cred = crate::identity::peercred::peer_cred_for_unix(
            &stream,
            self.runtime.load().identities.needs_enrichment(),
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

        let runtime = self.runtime.load();
        let mut conn = self.conn_info(peer, local);
        conn.proxy_auth = request.credential;
        runtime.identities.attach_peer_cred(&mut conn);

        let Some(attribution) = self.resolve_attribution(&conn, &runtime).await else {
            let _ = socks5::reply(&mut client, Reply::GeneralFailure).await;
            return Ok(());
        };
        if !attribution.resolved.attributed && runtime.identities.deny_unidentified() {
            let _ = socks5::reply(&mut client, Reply::NotAllowed).await;
            return Ok(());
        }

        let cx = self.context(
            &attribution,
            IngressMode::Explicit,
            peer,
            authority.clone(),
            "CONNECT",
            "",
            marshal_core::Phase::Connect,
        );
        let outcome = attribution.chain.evaluate(&cx).await;

        if outcome.action == Action::Deny {
            let _ = socks5::reply(&mut client, Reply::NotAllowed).await;
            self.emit_audit(
                &attribution,
                &cx,
                &outcome.reason,
                Action::Deny,
                outcome.evidence,
                None,
                started,
                outcome.would_deny,
            )
            .await;
            return Ok(());
        }

        let mut upstream = match self.guard.connect(&authority).await {
            Ok(s) => s,
            Err(e) => {
                let _ = socks5::reply(&mut client, guard_reply(&e)).await;
                self.emit_guard_failure(&attribution, &cx, &e, outcome.evidence, started).await;
                return Ok(());
            }
        };

        socks5::reply(&mut client, Reply::Succeeded).await.ok();

        // SOCKS5 gets exactly the same treatment as HTTP CONNECT: intercepted unless the
        // host is a deliberate `tls.passthrough` exception, in which case the plain relay
        // still runs the SNI cross-check. A SOCKS5 tunnel is exactly as capable of the
        // shared-IP/SNI trick as an HTTP CONNECT tunnel, so it gets exactly the same defence.
        if self.intercepts(&authority, &runtime) {
            self.emit_audit(
                &attribution,
                &cx,
                &outcome.reason,
                Action::Allow,
                outcome.evidence,
                None,
                started,
                outcome.would_deny,
            )
            .await;

            let handler = Arc::new(MitmHandler {
                chain: Arc::clone(&attribution.chain),
                audit: Arc::clone(&self.audit),
                authority: authority.clone(),
                ingress: cx.ingress,
                identity: cx.identity.clone(),
                profile: attribution.resolved.profile_label(),
                client_addr: peer,
                request_transforms: attribution.request_transforms.clone(),
                responders: attribution.responders.clone(),
                stats: Arc::clone(&self.stats),
                response_transforms: attribution.response_transforms.clone(),
                attributed: attribution.resolved.attributed,
                resolver: attribution.resolved.resolver.clone(),
            });

            if let Err(e) =
                mitm::intercept(client.into_inner(), upstream, Arc::clone(&runtime.tls), handler)
                    .await
            {
                tracing::debug!(peer = %peer, authority = %authority, error = %e,
                    "intercepted socks5 tunnel ended");
            }
            return Ok(());
        }

        self.emit_audit(
            &attribution,
            &cx,
            &outcome.reason,
            Action::Allow,
            outcome.evidence,
            None,
            started,
            outcome.would_deny,
        )
        .await;

        let result = tunnel::relay_inspected(&mut client, &mut upstream, |opening| {
            check_sni(opening, &authority)
        })
        .await;

        if let Err(tunnel::RelayError::Rejected(why)) = result {
            tracing::warn!(peer = %peer, authority = %authority, "{why}");
            let reason = Reason::new("allowlist", "sni_authority_mismatch", why);
            self.emit_audit(
                &attribution,
                &cx,
                &reason,
                Action::Deny,
                Evidence::new(),
                None,
                started,
                false,
            )
            .await;
        }
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

        // The absolute-form target's authority is what policy evaluates and what the guard
        // connects to; a `Host` header naming something else is either a confused client or
        // an attempt to have policy check one virtual host while a shared-IP upstream serves
        // another. Refuse rather than silently trusting whichever of the two picks the
        // connection — the same reasoning `check_sni` applies to CONNECT/SNI disagreement.
        if !request.is_connect
            && let Some(host_header) = &request.host_header
            && !host_matches_authority(host_header, &request.authority)
        {
            let _ = httpfront::write_status(
                &mut client,
                "400 Bad Request",
                &format!(
                    "request target `{}` and Host header `{host_header}` name different hosts",
                    request.authority.host
                ),
            )
            .await;
            return Ok(());
        }

        let runtime = self.runtime.load();
        let mut conn = self.conn_info(peer, local);
        conn.proxy_auth = request.proxy_auth.clone();
        conn.peer_cred = peer_cred;
        runtime.identities.attach_peer_cred(&mut conn);

        let Some(attribution) = self.resolve_attribution(&conn, &runtime).await else {
            let _ = httpfront::write_status(
                &mut client,
                "500 Internal Server Error",
                "attribution resolution failed",
            )
            .await;
            return Ok(());
        };
        if !attribution.resolved.attributed && runtime.identities.deny_unidentified() {
            let reason = Reason::new(
                "identities",
                "unidentified",
                "this connection could not be attributed to an identity, and the proxy is \
                 configured to refuse unattributed traffic",
            );
            let _ = httpfront::write_denial(
                &mut client,
                &reason,
                &attribution.resolved.identity.to_string(),
                &attribution.resolved.profile_label(),
            )
            .await;
            return Ok(());
        }

        let mut cx = self.context(
            &attribution,
            IngressMode::Explicit,
            peer,
            request.authority.clone(),
            &request.method,
            if request.is_connect { "" } else { &request.path },
            if request.is_connect {
                marshal_core::Phase::Connect
            } else {
                // Plaintext absolute-form: method, path and headers are visible, so
                // request-level layers do apply to them. The body is not parsed on this path,
                // so a layer that scans bodies applies its own oversize rule rather than
                // seeing nothing.
                marshal_core::Phase::Request
            },
        );
        if !request.is_connect {
            cx.headers = request.headers.clone();
        }
        let mut outcome = attribution.chain.evaluate(&cx).await;

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
            && self.intercepts(&request.authority, &runtime)
            && !attribution.chain.request_only_layers().is_empty()
        {
            outcome.action = Action::Allow;
            outcome.reason = Reason::new(
                "default_action",
                "connect_provisional",
                format!(
                    "no host-level layer refused `{}`; the decision is deferred to the \
                     request-level layers {:?} once TLS is intercepted",
                    request.authority.host,
                    attribution.chain.request_only_layers()
                ),
            );
        }

        if outcome.action == Action::Deny {
            let _ = httpfront::write_denial(
                &mut client,
                &outcome.reason,
                &cx.identity.to_string(),
                &attribution.resolved.profile_label(),
            )
            .await;
            self.emit_audit(
                &attribution,
                &cx,
                &outcome.reason,
                Action::Deny,
                outcome.evidence,
                None,
                started,
                outcome.would_deny,
            )
            .await;
            return Ok(());
        }

        if !request.is_connect {
            for transform in &attribution.request_transforms {
                if let Err(e) = transform.apply(&mut cx).await {
                    let reason = Reason::new(transform.name(), "transform_failed", e.to_string());
                    let _ = httpfront::write_denial(
                        &mut client,
                        &reason,
                        &cx.identity.to_string(),
                        &attribution.resolved.profile_label(),
                    )
                    .await;
                    self.emit_audit(
                        &attribution,
                        &cx,
                        &reason,
                        Action::Deny,
                        outcome.evidence,
                        None,
                        started,
                        false,
                    )
                    .await;
                    return Ok(());
                }
            }
            // Unconditional, not gated on a transform being configured: a proxy credential
            // must never reach the upstream regardless of whether the matched profile
            // happens to declare any request_transforms.
            mitm::strip_hop_by_hop(&mut cx.headers, false);
        }

        let mut upstream = match self.guard.connect(&request.authority).await {
            Ok(s) => s,
            Err(e) => {
                let _ =
                    httpfront::write_status(&mut client, "502 Bad Gateway", &e.to_string()).await;
                self.emit_guard_failure(&attribution, &cx, &e, outcome.evidence, started).await;
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

            let intercept = self.intercepts(&authority, &runtime).then(|| Arc::clone(&runtime.tls));

            if let Some(engine) = intercept {
                // The CONNECT itself is allowed here; each request inside the tunnel is
                // evaluated separately once decrypted, and audited on its own.
                self.emit_audit(
                    &attribution,
                    &cx,
                    &outcome.reason,
                    Action::Allow,
                    outcome.evidence,
                    None,
                    started,
                    outcome.would_deny,
                )
                .await;

                let handler = Arc::new(MitmHandler {
                    chain: Arc::clone(&attribution.chain),
                    audit: Arc::clone(&self.audit),
                    authority: authority.clone(),
                    ingress: cx.ingress,
                    identity: cx.identity.clone(),
                    profile: attribution.resolved.profile_label(),
                    client_addr: peer,
                    request_transforms: attribution.request_transforms.clone(),
                    responders: attribution.responders.clone(),
                    stats: Arc::clone(&self.stats),
                    response_transforms: attribution.response_transforms.clone(),
                    attributed: attribution.resolved.attributed,
                    resolver: attribution.resolved.resolver.clone(),
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
            self.emit_audit(
                &attribution,
                &cx,
                &outcome.reason,
                Action::Allow,
                outcome.evidence,
                None,
                started,
                outcome.would_deny,
            )
            .await;

            let result = tunnel::relay_inspected(&mut stream, &mut upstream, |opening| {
                check_sni(opening, &authority)
            })
            .await;

            if let Err(tunnel::RelayError::Rejected(why)) = result {
                tracing::warn!(peer = %peer, authority = %authority, "{why}");
                let reason = Reason::new("allowlist", "sni_authority_mismatch", why);
                self.emit_audit(
                    &attribution,
                    &cx,
                    &reason,
                    Action::Deny,
                    Evidence::new(),
                    None,
                    started,
                    false,
                )
                .await;
            }
            return Ok(());
        } else {
            // Always rebuilt from `cx.headers`, never replayed from the raw bytes the client
            // sent: hop-by-hop headers (including `Proxy-Authorization`) were stripped above
            // regardless of whether a transform is configured, and replaying the original
            // bytes here would put them back.
            let head = transformed_origin_form(&request, &cx);
            upstream.write_all(&head).await?;
        }

        self.emit_audit(
            &attribution,
            &cx,
            &outcome.reason,
            Action::Allow,
            outcome.evidence,
            None,
            started,
            outcome.would_deny,
        )
        .await;
        let _ = tunnel::relay(&mut client, &mut upstream).await;
        Ok(())
    }

    /// Whether this destination will have its TLS intercepted.
    /// Whether this destination is intercepted, i.e. everything except a host deliberately
    /// listed in `tls.passthrough`. There is no "no CA" case any more: interception is
    /// mandatory (see `Runtime::tls`).
    fn intercepts(&self, authority: &Authority, runtime: &Runtime) -> bool {
        runtime.passthrough.matches(&authority.host).is_none()
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

    #[allow(clippy::too_many_arguments)]
    fn context(
        &self,
        attribution: &Attribution,
        ingress: IngressMode,
        peer: std::net::SocketAddr,
        authority: Authority,
        method: &str,
        path: &str,
        phase: marshal_core::Phase,
    ) -> RequestContext {
        RequestContext {
            identity: attribution.resolved.identity.clone(),
            profile: attribution.resolved.profile_label(),
            ingress,
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
    async fn emit_audit(
        &self,
        attribution: &Attribution,
        cx: &RequestContext,
        reason: &Reason,
        action: Action,
        mut evidence: Evidence,
        status_code: Option<u16>,
        started: Instant,
        would_deny: bool,
    ) {
        // Same two halves as the intercepted path: the chain works from a clone, transforms
        // mutate the context's own. See `mitm::emit`.
        evidence.absorb(cx.evidence.clone());

        self.stats.record(&cx.identity, &cx.profile, action == Action::Allow, would_deny);
        self.audit
            .emit(AuditRecord {
                identity: cx.identity.to_string(),
                attributed: attribution.resolved.attributed,
                resolver: attribution.resolved.resolver.clone(),
                profile: cx.profile.to_string(),
                ingress: match cx.ingress {
                    IngressMode::Explicit => "explicit",
                    IngressMode::Dns => "dns",
                }
                .into(),
                host: cx.authority.host.clone(),
                method: cx.method.to_string(),
                path: cx.uri.to_string(),
                action,
                reason: reason.clone(),
                would_deny,
                trail: evidence.trail,
                facts: evidence.facts,
                flags: evidence.flags,
                status_code,
                duration_ms: started.elapsed().as_millis() as u64,
            })
            .await;
    }

    async fn emit_guard_failure(
        &self,
        attribution: &Attribution,
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
        self.emit_audit(attribution, cx, &reason, Action::Deny, evidence, None, started, false)
            .await;
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

/// Whether a `Host` header value names the same host as the authority already resolved from
/// the request target. The header may carry its own port (`example.com:8080`, `[::1]:8080`);
/// only the host component is compared, via the same parser the request target itself uses,
/// since the authority's port is the one the guard actually connects to and is not what a
/// laundering attempt would try to disagree on. A `Host` header malformed enough that it
/// cannot even be parsed as an authority is treated as a mismatch rather than ignored.
fn host_matches_authority(host_header: &str, authority: &Authority) -> bool {
    httpfront::parse_authority(host_header, authority.port)
        .is_ok_and(|parsed| parsed.host.eq_ignore_ascii_case(&authority.host))
}

fn guard_reply(e: &GuardError) -> Reply {
    match e {
        GuardError::Blocked { .. } => Reply::NotAllowed,
        GuardError::Resolve { .. } | GuardError::NoAddresses { .. } => Reply::HostUnreachable,
        GuardError::Connect { .. } => Reply::ConnectionRefused,
    }
}

/// Turn `GET http://host/path HTTP/1.1` into `GET /path HTTP/1.1` with `cx`'s headers —
/// possibly rewritten by a transform, always with hop-by-hop headers already stripped —
/// rather than the client's original bytes.
fn transformed_origin_form(request: &ProxyRequest, cx: &RequestContext) -> Vec<u8> {
    let version = request
        .raw_head
        .split(|b| *b == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .and_then(|line| line.split_whitespace().nth(2))
        .unwrap_or("HTTP/1.1");
    let mut out = format!("{} {} {version}\r\n", cx.method, cx.uri).into_bytes();
    for (name, value) in &cx.headers {
        out.extend_from_slice(name.as_str().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
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

    fn test_request(headers: http::HeaderMap) -> ProxyRequest {
        ProxyRequest {
            authority: Authority { host: "example.com".into(), port: 80 },
            method: "GET".into(),
            path: "/a?b=1".into(),
            raw_head: b"GET http://example.com/a?b=1 HTTP/1.1\r\n\r\n".to_vec(),
            headers: headers.clone(),
            host_header: Some("example.com".into()),
            is_connect: false,
            proxy_auth: None,
        }
    }

    fn test_context(headers: http::HeaderMap) -> RequestContext {
        RequestContext {
            identity: marshal_core::Identity::new("test"),
            profile: Arc::from("p"),
            ingress: IngressMode::Explicit,
            phase: marshal_core::Phase::Request,
            client_addr: "127.0.0.1:1".parse().unwrap(),
            authority: Authority { host: "example.com".into(), port: 80 },
            method: http::Method::GET,
            uri: "/a?b=1".parse().unwrap(),
            headers,
            body: BodyHandle::Empty,
            evidence: Evidence::new(),
        }
    }

    #[test]
    fn transformed_origin_form_serialises_from_context_headers_not_raw_bytes() {
        let mut headers = http::HeaderMap::new();
        headers.insert("host", "example.com".parse().unwrap());
        headers.insert("x-k", "v".parse().unwrap());
        let req = test_request(http::HeaderMap::new());
        let cx = test_context(headers);

        let out = String::from_utf8(transformed_origin_form(&req, &cx)).unwrap();
        assert!(out.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(out.contains("host: example.com\r\n"));
        assert!(out.contains("x-k: v\r\n"));
        assert!(out.ends_with("\r\n\r\n"));
    }

    #[test]
    fn strip_hop_by_hop_then_transformed_origin_form_never_carries_proxy_authorization() {
        // This is the exact sequence serve_http_generic runs on the plaintext path,
        // unconditionally, regardless of whether the profile configures a transform: strip
        // first, then serialise from `cx.headers` rather than the client's raw bytes.
        let mut headers = http::HeaderMap::new();
        headers.insert("proxy-authorization", "Basic x".parse().unwrap());
        mitm::strip_hop_by_hop(&mut headers, false);
        let req = test_request(http::HeaderMap::new());
        let cx = test_context(headers);

        let out = String::from_utf8(transformed_origin_form(&req, &cx)).unwrap();
        assert!(
            !out.to_ascii_lowercase().contains("proxy-authorization"),
            "must never reach the upstream: {out:?}"
        );
    }

    #[test]
    fn host_header_matching_the_authority_is_accepted() {
        let authority = Authority { host: "example.com".into(), port: 80 };
        assert!(host_matches_authority("example.com", &authority));
        assert!(host_matches_authority("EXAMPLE.COM", &authority));
        assert!(host_matches_authority("example.com:80", &authority));
    }

    #[test]
    fn host_header_naming_a_different_host_is_rejected() {
        let authority = Authority { host: "example.com".into(), port: 80 };
        assert!(!host_matches_authority("evil.example", &authority));
        assert!(!host_matches_authority("example.com.evil.example", &authority));
    }
}
