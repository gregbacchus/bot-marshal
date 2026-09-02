//! `marshal` — the bot-marshal command line.

use std::path::PathBuf;
use std::process::ExitCode;

use std::collections::HashMap;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use marshal_audit::{JsonSink, MultiSink, RequestDetail, RequestTracingSink};
use marshal_config::{Severity, validate};
use marshal_core::{AuditSink, DenyingDecider};
use marshal_policy::build_chain;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use marshal_secrets::{MatchSites, SecretInjector, SecretSwap};

#[derive(Debug, Parser)]
#[command(name = "marshal", version, about = "Egress firewall for agents and bots")]
struct Cli {
    /// Path to the configuration file. Defaults to `$XDG_CONFIG_HOME/bot-marshal/config.yaml`
    /// (usually `~/.config/bot-marshal/config.yaml`) when not given.
    #[arg(long, short, global = true, env = "MARSHAL_CONFIG")]
    config: Option<PathBuf>,

    /// Verbosity of the base operational messages (`error`, `warn`, `info`, `debug`,
    /// `trace`). Doesn't affect per-request lines — those fire at their own fixed level
    /// whenever `--log-detail` has them on, regardless of this.
    #[arg(long, global = true, env = "MARSHAL_LOG", default_value = "info")]
    log: String,

    /// How much detail per-request lines carry, on top of the base `log` messages (startup,
    /// warnings, shutdown), which are always on. `access` (default) is one summary line per
    /// request: session, host, method, profile, deciding layer, duration. `audit` is the
    /// same line with everything else added: status code, cache/would-deny flags, and the
    /// full evidence trail — noticeably bulkier, so reach for it while a policy is still
    /// being worked out, not as a standing default. `log` turns per-request lines off
    /// entirely, leaving only the base messages.
    #[arg(long, global = true, env = "MARSHAL_LOG_DETAIL", default_value = "access")]
    log_detail: LogDetail,

    /// Where the log goes. `auto` (default) picks the first of journald, syslog, or stdout
    /// that's actually reachable; the others force one, failing if it isn't available rather
    /// than silently falling back — useful for debugging under a supervisor that sets
    /// `JOURNAL_STREAM` but where you want plain stdout anyway.
    #[arg(long, global = true, env = "MARSHAL_LOG_SINK", default_value = "auto")]
    log_sink: LogSink,

    /// How stdout renders every log line, consistently (journald and syslog format
    /// themselves and ignore this). `auto` (default) is `pretty` on a terminal and `json`
    /// otherwise — piping to a file, `docker logs`, or anything else non-interactive gets
    /// the machine-readable form automatically, with no flag needed.
    #[arg(long, global = true, env = "MARSHAL_LOG_FORMAT", default_value = "auto")]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum LogDetail {
    Log,
    Access,
    Audit,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum LogSink {
    Auto,
    Stdout,
    Journald,
    Syslog,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum LogFormat {
    Auto,
    Pretty,
    Json,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Configuration inspection.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Certificate authority management.
    #[command(subcommand)]
    Ca(CaCommand),

    /// Launch an agent so the proxy can identify it.
    Run {
        /// Profile the agent runs under.
        #[arg(long)]
        profile: String,

        /// How the agent is isolated:
        /// `netns` (no route out except the proxy — enforces, not just identifies),
        /// `cgroup` (identity by cgroup, inherited by children),
        /// or `none` (identity by a proxy credential the agent holds).
        #[arg(long, default_value = "netns")]
        isolation: String,

        /// Proxy address the agent should use.
        #[arg(long, default_value = "http://127.0.0.1:8080")]
        proxy: String,

        /// Print the command and environment instead of running anything.
        #[arg(long)]
        dry_run: bool,

        /// The command to launch.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Internal: the half of `--isolation netns` that runs inside the namespace.
    ///
    /// Not intended to be invoked directly; `marshal run` re-executes this binary with it.
    #[command(hide = true)]
    Sandbox {
        /// The proxy's Unix socket, as visible inside the namespace.
        #[arg(long)]
        socket: PathBuf,
        /// Where to listen inside the namespace.
        #[arg(long, default_value = marshal_launch::SANDBOX_LISTEN)]
        listen: String,
        /// CA certificate for the agent's trust environment.
        #[arg(long)]
        ca: Option<PathBuf>,
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Run the proxy.
    Serve {
        /// Fallback profile for connections no resolver attributes. Overrides
        /// `sessions.unidentified.profile`.
        #[arg(long)]
        profile: Option<String>,

        /// Override the listen address from the config file.
        #[arg(long)]
        listen: Option<String>,

        /// Also write the full structured JSON audit record (the one line per allow/deny
        /// already going to the log always carries a summary, not the full evidence trail
        /// or status code) to this file, in addition. Append mode, created if missing.
        #[arg(long)]
        audit_log: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Load and validate the configuration without starting the proxy.
    Check,
}

#[derive(Debug, Subcommand)]
enum CaCommand {
    /// Generate a new CA. Refuses to overwrite an existing one.
    Init {
        #[arg(long, default_value = "bot-marshal local CA")]
        common_name: String,
        /// How long the CA is valid for.
        #[arg(long, default_value_t = 825)]
        days: u32,
    },
    /// Print the CA certificate and how to trust it.
    Export {
        /// Print only the PEM, for piping into a file or a trust store.
        #[arg(long)]
        pem_only: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(e) = init_tracing(&cli.log, cli.log_detail, cli.log_sink, cli.log_format) {
        eprintln!("error: {e}");
        return ExitCode::FAILURE;
    }

    // `Sandbox` needs no config file at all — it gets everything through its own flags — so
    // resolution happens for every other subcommand rather than unconditionally, and a
    // missing HOME does not block the one path that never needed it.
    let was_explicit = cli.config.is_some();
    let config_path = if matches!(cli.command, Command::Sandbox { .. }) {
        PathBuf::new()
    } else {
        match resolve_config_path(cli.config.clone()) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: {e:#}");
                return ExitCode::FAILURE;
            }
        }
    };

    // The config has to exist before any subcommand can do anything — including `ca init`,
    // which reads `tls.ca_cert` / `tls.ca_key` from it. That makes "the file is missing" the
    // universal first-run state, worth one clear message here rather than a generic I/O error
    // from whichever subcommand happens to load it first — especially when the path was never
    // typed by the user and they may not know where to look.
    if !matches!(cli.command, Command::Sandbox { .. }) && !config_path.exists() {
        if was_explicit {
            eprintln!("error: no config file at {}", config_path.display());
        } else {
            eprintln!(
                "error: no config file at {} (the default location; pass --config to use a \
                 different one)\n\nCreate one there — see the Quickstart in the README — then \
                 re-run this command.",
                config_path.display()
            );
        }
        return ExitCode::FAILURE;
    }

    match cli.command {
        Command::Config(ConfigCommand::Check) => config_check(&config_path),
        Command::Ca(cmd) => ca_command(&config_path, cmd),
        Command::Run { profile, isolation, proxy, dry_run, command } => {
            run_command(&config_path, &profile, &isolation, &proxy, dry_run, &command)
        }
        Command::Sandbox { socket, listen, ca, command } => {
            let listen = match listen.parse() {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("error: invalid --listen: {e}");
                    return ExitCode::FAILURE;
                }
            };
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: cannot start the async runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(marshal_launch::sandbox::run(
                marshal_launch::sandbox::SandboxConfig { socket, listen, ca_cert: ca, command },
            )) {
                Ok(code) => ExitCode::from(code as u8),
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Serve { profile, listen, audit_log } => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: cannot start the async runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(serve(&config_path, profile, listen, cli.log_detail, audit_log)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}

async fn serve(
    config_path: &std::path::Path,
    profile_override: Option<String>,
    listen: Option<String>,
    log_detail: LogDetail,
    audit_log: Option<PathBuf>,
) -> anyhow::Result<()> {
    // Startup and reload go through the same builder, so a reload cannot succeed on a
    // config the proxy would have refused to start with — or the reverse.
    let build = {
        let config_path = config_path.to_path_buf();
        move || build_runtime(&config_path, profile_override.clone())
    };
    let build = Arc::new(build);

    let (runtime, cfg, injectors) = build()?;
    let handle = Arc::new(marshal_proxy::runtime::RuntimeHandle::new(runtime));

    let guard = UpstreamGuard::new(&cfg.upstream.deny_cidrs, cfg.upstream.allow_private)?;

    // Resolve every profile's secrets once, up front, so the redactor knows every real value
    // before a single record can be written. This has to be the union across all profiles,
    // not just whichever one a given connection resolves into: an audit line about profile
    // B's request could in principle sit next to a log line mentioning profile A's secret,
    // and redaction has to protect against a value appearing anywhere in output, not just in
    // the records belonging to its own profile. Seeding after the first request would also
    // leave a window in which a secret could reach the audit log.
    let mut secret_names: Vec<String> = Vec::new();
    let mut secret_values: Vec<String> = Vec::new();
    for injector in &injectors {
        for (name, value) in injector.resolve_all().await {
            secret_names.push(name);
            secret_values.push(value.expose().to_owned());
        }
    }
    if !secret_names.is_empty() {
        tracing::info!(secrets = ?secret_names, "boundary secret injection active");
    }
    let redactor = marshal_core::Redactor::new(secret_values);

    // Per-request lines go through the log at whatever detail `--log-detail` asks for — see
    // `init_tracing`, which also pins the "access" target's level so the general `--log`
    // verbosity can't accidentally suppress them. `--audit-log` is separate: a durable,
    // natively-nested copy of the full record, independent of what's active on the console.
    let mut sinks: Vec<Arc<dyn AuditSink>> = Vec::new();
    match log_detail {
        LogDetail::Log => {}
        LogDetail::Access => {
            sinks.push(Arc::new(RequestTracingSink::redacting(
                RequestDetail::Access,
                redactor.clone(),
            )));
        }
        LogDetail::Audit => {
            sinks.push(Arc::new(RequestTracingSink::redacting(
                RequestDetail::Audit,
                redactor.clone(),
            )));
        }
    }
    if let Some(path) = &audit_log {
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .map_err(|e| anyhow::anyhow!("opening audit log {}: {e}", path.display()))?;
        sinks.push(Arc::new(JsonSink::new(file).redacting(redactor)));
    }
    let audit: Arc<dyn AuditSink> = Arc::new(MultiSink::new(sinks));

    let listen = listen
        .or_else(|| cfg.listeners.explicit.as_ref().map(|e| e.listen.clone()))
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned());
    let unix_socket = cfg
        .listeners
        .explicit
        .as_ref()
        .and_then(|e| e.unix_socket.as_ref())
        .map(|p| expand_tilde(p));
    let transparent = cfg
        .listeners
        .transparent
        .as_ref()
        .filter(|t| t.enabled)
        .map(|t| t.listen.clone())
        .unwrap_or_default();

    let server = Server::new(
        ServerConfig { listen, unix_socket, transparent },
        Arc::clone(&handle),
        Arc::new(guard),
        audit,
    );
    let stats = server.stats();

    // The management API rebuilds through the same closure, and only swaps on success.
    let management = match cfg.listeners.management.clone() {
        Some(m) => {
            let token = std::env::var(&m.api_key_env).ok();
            if token.is_none() {
                tracing::warn!(
                    var = %m.api_key_env,
                    "management.api_key_env is not set; the management API will be open"
                );
            }
            let builder: marshal_proxy::management::RuntimeBuilder = {
                let build = build.clone();
                Arc::new(move || build().map(|(rt, _, _)| rt).map_err(|e| format!("{e:#}")))
            };
            Some((m.listen.clone(), builder, token))
        }
        None => None,
    };

    let management_task = async {
        match management {
            Some((listen, builder, token)) => marshal_proxy::management::serve(
                &listen,
                Arc::clone(&handle),
                stats,
                builder,
                token,
            )
            .await
            .map_err(anyhow::Error::from),
            None => std::future::pending().await,
        }
    };

    // DNS interception, when configured. Started alongside the proxy rather than as a
    // separate process, because a resolver pointing at a proxy that is not running turns
    // every lookup into a timeout.
    let dns = match cfg.listeners.dns.as_ref().filter(|d| d.enabled) {
        Some(dns_cfg) => Some(start_dns(dns_cfg).await?),
        None => None,
    };
    let dns_task = async move {
        match dns {
            Some(mut server) => server.block_until_done().await.map_err(anyhow::Error::from),
            None => std::future::pending().await,
        }
    };

    tokio::select! {
        r = server.run(|_| {}) => r.map_err(Into::into),
        r = dns_task => r,
        r = management_task => r,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
}

/// Load the config and build everything derived from it.
///
/// Fallible as a unit: the runtime is complete before it is returned, so a caller swapping it
/// in can never half-apply a broken configuration.
#[allow(clippy::type_complexity)]
fn build_runtime(
    config_path: &std::path::Path,
    profile_override: Option<String>,
) -> anyhow::Result<(
    marshal_proxy::runtime::Runtime,
    marshal_config::model::Config,
    Vec<Arc<SecretInjector>>,
)> {
    let cfg = marshal_config::load(config_path)?;

    // Refuse to start on an invalid config. A proxy that boots with a chain the operator did
    // not write is worse than one that does not boot.
    let diagnostics = validate(&cfg);
    let mut errors = Vec::new();
    for d in &diagnostics {
        match d.severity {
            Severity::Error => errors.push(d.to_string()),
            Severity::Warning => tracing::warn!("{d}"),
        }
    }
    anyhow::ensure!(errors.is_empty(), "configuration has errors:\n{}", errors.join("\n"));

    // Every profile gets a chain, because which one applies is decided per connection.
    // Building them all up front means a broken profile fails here rather than when the
    // first agent that uses it connects. The embedded `profile:` goes through the exact same
    // builder as every named one — it just has nowhere to be keyed by name, so its artifacts
    // land in dedicated `default_*` fields on `Runtime` instead of these maps.
    let mut chains: HashMap<Arc<str>, Arc<marshal_policy::Chain>> = HashMap::new();
    let mut response_transforms: HashMap<Arc<str>, Vec<Arc<dyn marshal_core::ResponseTransform>>> =
        HashMap::new();
    // Per profile, same as chains and response_transforms: a secret swap declared under one
    // profile must never fire for a session resolved into a different one. Kept alongside as
    // `injectors` too, because the redactor below needs the union of every profile's real
    // secret values, not just whichever profile a given connection happens to resolve into —
    // a value belonging to any profile can end up in a log line regardless of which session
    // produced it.
    let mut request_transforms: HashMap<Arc<str>, Vec<Arc<dyn marshal_core::RequestTransform>>> =
        HashMap::new();
    let mut injectors: Vec<Arc<SecretInjector>> = Vec::new();

    let build_one = |label: &str,
                     profile: &marshal_config::model::Profile|
     -> anyhow::Result<(
        Arc<marshal_policy::Chain>,
        Vec<Arc<dyn marshal_core::ResponseTransform>>,
        Vec<Arc<dyn marshal_core::RequestTransform>>,
        Option<Arc<SecretInjector>>,
    )> {
        let chain = Arc::new(build_chain(&cfg, label, profile, Arc::new(DenyingDecider))?);
        let response = marshal_policy::build_response_transforms(&cfg, label, profile)?;
        let resolved = marshal_policy::resolve_profile(&cfg, profile)?;
        let injector = Arc::new(build_injector(&resolved, &cfg)?);
        let (request, injector) = if injector.is_empty() {
            (Vec::new(), None)
        } else {
            (vec![Arc::clone(&injector) as Arc<dyn marshal_core::RequestTransform>], Some(injector))
        };
        Ok((chain, response, request, injector))
    };

    let (default_chain, default_response_transforms, default_request_transforms, default_injector) =
        build_one("profile", &cfg.profile)?;
    if let Some(injector) = default_injector {
        injectors.push(injector);
    }

    for (name, profile) in &cfg.profiles {
        let (chain, response, request, injector) = build_one(name, profile)?;
        chains.insert(Arc::from(name.as_str()), chain);
        if !response.is_empty() {
            response_transforms.insert(Arc::from(name.as_str()), response);
        }
        if let Some(injector) = injector {
            request_transforms.insert(Arc::from(name.as_str()), request);
            injectors.push(injector);
        }
    }

    // `None` means "the embedded `profile:`" — always valid, since it's required to exist;
    // `Some(name)` is an explicit override that must actually name a built profile.
    let fallback_override: Option<Arc<str>> = profile_override
        .or_else(|| cfg.sessions.unidentified.as_ref().and_then(|u| u.profile.clone()))
        .map(|s| Arc::from(s.as_str()));
    if let Some(name) = &fallback_override {
        anyhow::ensure!(chains.contains_key(name), "unknown profile `{name}`");
    }

    let sessions = Arc::new(build_sessions(&cfg, fallback_override)?);

    // Interception is mandatory, not a fallback. A plain relay cannot enforce per-request
    // policy, and — the reason this is a hard requirement rather than a convenience — it
    // cannot even guarantee the client reaches the host it claimed: shared-IP hosting routes
    // by the TLS SNI inside the tunnel, which a relay never inspects. Refusing to start
    // without a CA is the only way to avoid silently offering a weaker mode of operation.
    let (cert_path, key_path) = ca_paths(config_path).map_err(|e| {
        anyhow::anyhow!(
            "{e} — bot-marshal only supports intercepted egress and needs `tls.ca_cert` and \
             `tls.ca_key` set, plus `marshal ca init` to create them. (Certificate-pinned \
             clients that must bypass interception belong in `tls.passthrough`, not this.)"
        )
    })?;
    anyhow::ensure!(
        cert_path.exists() && key_path.exists(),
        "no CA found at {} — bot-marshal only supports intercepted egress; run `marshal ca \
         init` first. (Certificate-pinned clients that must bypass interception belong in \
         `tls.passthrough`, not this.)",
        cert_path.display()
    );
    let ca = marshal_tls::CertificateAuthority::load(&cert_path, &key_path)?;
    let minter = Arc::new(marshal_tls::LeafMinter::new(
        Arc::new(ca),
        cfg.tls.cert_cache_size,
        cfg.tls.leaf_expiry_hours,
    ));
    let mut extra_roots = Vec::new();
    for path in &cfg.tls.upstream_ca_certs {
        let path = expand_tilde(path);
        extra_roots.push(std::fs::read_to_string(&path).map_err(|e| {
            anyhow::anyhow!("reading tls.upstream_ca_certs entry {}: {e}", path.display())
        })?);
    }
    let tls = Arc::new(marshal_proxy::mitm::TlsEngine::with_extra_roots(minter, &extra_roots)?);

    let passthrough = marshal_policy::HostMatcher::new(&cfg.tls.passthrough, Vec::<&str>::new())?;

    Ok((
        marshal_proxy::runtime::Runtime {
            chains,
            response_transforms,
            request_transforms,
            default_chain,
            default_response_transforms,
            default_request_transforms,
            sessions,
            passthrough,
            tls,
        },
        cfg,
        injectors,
    ))
}

/// Build and bind the DNS interceptor.
async fn start_dns(
    cfg: &marshal_config::model::DnsListener,
) -> anyhow::Result<hickory_server::Server<marshal_dns::DnsServer>> {
    let proxy_ip: std::net::IpAddr = cfg
        .proxy_ip
        .parse()
        .map_err(|e| anyhow::anyhow!("listeners.dns.proxy_ip `{}`: {e}", cfg.proxy_ip))?;

    let records = cfg.records.iter().map(|r| {
        let ips: Vec<std::net::IpAddr> = r.values.iter().filter_map(|v| v.parse().ok()).collect();
        (r.name.clone(), ips)
    });

    let policy = marshal_dns::DnsPolicy::new(proxy_ip, &cfg.passthrough, records)?;

    // The system resolver handles passthrough names, so "passthrough" genuinely means what
    // the host itself would have answered.
    let upstream = Arc::new(
        hickory_resolver::Resolver::builder_tokio()
            .map_err(|e| anyhow::anyhow!("reading the system resolver configuration: {e}"))?
            .build()
            .map_err(|e| anyhow::anyhow!("building the upstream resolver: {e}"))?,
    );

    tracing::info!(
        listen = %cfg.listen,
        %proxy_ip,
        passthrough = ?cfg.passthrough,
        "dns interception listening"
    );
    tracing::warn!(
        "DNS interception is a convenience for clients that cannot be configured, not a \
         containment boundary: anything with its own resolver never asks us"
    );

    Ok(marshal_dns::serve(marshal_dns::DnsServer::new(Arc::new(policy), upstream), &cfg.listen)
        .await?)
}

/// Build the resolver chain from config.
fn build_sessions(
    cfg: &marshal_config::model::Config,
    fallback: Option<Arc<str>>,
) -> anyhow::Result<marshal_proxy::sessions::SessionRegistry> {
    use marshal_config::model::ResolverConfig;
    use marshal_proxy::sessions::{
        LaunchedResolver, PeerCredResolver, ProxyAuthResolver, SessionRegistry, SourceIpResolver,
    };

    let mut resolvers: Vec<Arc<dyn marshal_core::SessionResolver>> = Vec::new();
    let mut enrich = false;

    for resolver in &cfg.sessions.resolvers {
        match resolver {
            ResolverConfig::ProxyAuth { credentials } => {
                let mut entries = Vec::new();
                for c in credentials {
                    // A credential whose environment variable is unset is a configuration
                    // error, not an entry to skip: skipping it would silently downgrade that
                    // agent to the fallback profile.
                    let password = std::env::var(&c.password_env).map_err(|_| {
                        anyhow::anyhow!(
                            "sessions.resolvers: `{}` is not set, so the credential for `{}` \
                             cannot be built",
                            c.password_env,
                            c.user
                        )
                    })?;
                    entries.push((c.user.clone(), password, c.session.clone(), c.profile.clone()));
                }
                let r = ProxyAuthResolver::new(entries);
                if !r.is_empty() {
                    resolvers.push(Arc::new(r));
                }
            }
            ResolverConfig::SourceIp { map } => {
                resolvers.push(Arc::new(SourceIpResolver::new(
                    map.iter().map(|e| (e.cidr.clone(), e.session.clone(), e.profile.clone())),
                )?));
            }
            ResolverConfig::PeerCred { enrich: e, map } => {
                enrich |= *e;
                // `username`/`groupname` are resolved to a uid/gid here, once, via NSS —
                // config validation already rejected setting both `uid` and `username` (or
                // `gid` and `groupname`) on the same entry, so at most one of each pair is
                // ever present. A name that fails to resolve is a config error, not an entry
                // to silently drop: dropping it would leave that agent unidentified without
                // saying why.
                let mut uids = Vec::new();
                let mut gids = Vec::new();
                let mut cgroups = Vec::new();
                for m in map {
                    let uid = match (m.uid, &m.username) {
                        (Some(uid), _) => Some(uid),
                        (None, Some(name)) => Some(
                            marshal_proxy::sessions::peercred::resolve_username(name).map_err(
                                |e| {
                                    anyhow::anyhow!(
                                        "sessions.resolvers: peer_cred username `{name}` \
                                         could not be resolved to a uid: {e}"
                                    )
                                },
                            )?,
                        ),
                        (None, None) => None,
                    };
                    if let Some(uid) = uid {
                        uids.push((uid, m.session.clone(), m.profile.clone()));
                    }
                    let gid = match (m.gid, &m.groupname) {
                        (Some(gid), _) => Some(gid),
                        (None, Some(name)) => Some(
                            marshal_proxy::sessions::peercred::resolve_groupname(name).map_err(
                                |e| {
                                    anyhow::anyhow!(
                                        "sessions.resolvers: peer_cred groupname `{name}` \
                                         could not be resolved to a gid: {e}"
                                    )
                                },
                            )?,
                        ),
                        (None, None) => None,
                    };
                    if let Some(gid) = gid {
                        gids.push((gid, m.session.clone(), m.profile.clone()));
                    }
                    if let Some(cgroup) = &m.cgroup {
                        cgroups.push((cgroup.clone(), m.session.clone(), m.profile.clone()));
                    }
                }
                resolvers.push(Arc::new(PeerCredResolver::new(uids, gids, cgroups)?));
            }
            ResolverConfig::Launched => {
                // The launcher's identity lives in the cgroup name, so this resolver only
                // works with enrichment on.
                enrich = true;
                resolvers.push(Arc::new(LaunchedResolver::new(cfg.profiles.keys().cloned())));
            }
            ResolverConfig::ListenerPort { map } => {
                resolvers.push(Arc::new(marshal_proxy::sessions::ListenerPortResolver::new(
                    map.iter().map(|e| (e.port, e.session.clone(), e.profile.clone())),
                )));
            }
        }
    }

    let deny_unidentified = matches!(
        cfg.sessions.unidentified.as_ref().map(|u| u.action),
        Some(marshal_config::model::UnidentifiedAction::Deny)
    );

    Ok(SessionRegistry::new(resolvers, fallback, deny_unidentified, enrich))
}

/// `marshal run`: launch an agent under a profile.
fn run_command(
    config_path: &std::path::Path,
    profile: &str,
    isolation: &str,
    proxy: &str,
    dry_run: bool,
    command: &[String],
) -> ExitCode {
    let isolation: marshal_launch::Isolation = match isolation.parse() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let cfg = match marshal_config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    if !cfg.profiles.contains_key(profile) {
        eprintln!(
            "error: unknown profile `{profile}`; {} is configured with: {}",
            config_path.display(),
            cfg.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
        );
        return ExitCode::FAILURE;
    }

    // Preflight every dependency the chosen mode needs, with a message that names the
    // working alternative. Discovering a missing namespace by watching the agent fail every
    // request is a miserable way to learn it.
    use marshal_launch::Isolation;
    if matches!(isolation, Isolation::Cgroup | Isolation::Netns)
        && !marshal_launch::systemd_available()
    {
        eprintln!(
            "error: `--isolation {}` needs systemd-run, which is not available here. Use \
             `--isolation none` to launch with proxy environment variables only, accepting \
             that identity then rests on a credential the agent holds.",
            if isolation == Isolation::Netns { "netns" } else { "cgroup" }
        );
        return ExitCode::FAILURE;
    }
    if isolation == Isolation::Netns {
        if !marshal_launch::bwrap_available() {
            eprintln!(
                "error: `--isolation netns` needs bubblewrap (`bwrap`), which is not \
                 installed. Install it, or use `--isolation cgroup` — which identifies the \
                 agent but does not stop it routing around the proxy."
            );
            return ExitCode::FAILURE;
        }
        if !marshal_launch::netns_available() {
            eprintln!(
                "error: bwrap cannot create a network namespace here, which usually means \
                 unprivileged user namespaces are disabled \
                 (`sysctl kernel.unprivileged_userns_clone`). Use `--isolation cgroup`."
            );
            return ExitCode::FAILURE;
        }
    }

    let (cert_path, _) = ca_paths(config_path).unwrap_or_default();
    let endpoint = marshal_launch::ProxyEndpoint {
        url: proxy.to_owned(),
        ca_cert: cert_path.exists().then_some(cert_path),
        credential: None,
    };

    let unix_socket = cfg
        .listeners
        .explicit
        .as_ref()
        .and_then(|e| e.unix_socket.as_ref())
        .map(|p| expand_tilde(p));

    let id = std::process::id();
    let mut cmd = match marshal_launch::build_command_with(
        isolation,
        profile,
        id,
        &endpoint,
        command,
        unix_socket.as_deref(),
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if dry_run {
        println!("isolation: {isolation:?}");
        println!("scope:     {}", marshal_launch::scope_name(profile, id));
        println!(
            "command:   {} {:?}",
            cmd.get_program().to_string_lossy(),
            cmd.get_args().collect::<Vec<_>>()
        );
        if isolation == Isolation::Netns {
            // The proxy env is set by the sandbox from inside, pointing at the forwarder
            // rather than at the host address — printing the host one here would mislead.
            println!(
                "note:      the agent reaches the proxy at {} inside its namespace, which is \
                 forwarded to {}. It has no other route out.",
                marshal_launch::SANDBOX_LISTEN,
                unix_socket.as_ref().map(|p| p.display().to_string()).unwrap_or_default()
            );
        } else {
            for (k, v) in marshal_launch::proxy_env(&endpoint) {
                println!("env:       {k}={v}");
            }
        }
        return ExitCode::SUCCESS;
    }

    tracing::info!(
        profile,
        scope = %marshal_launch::scope_name(profile, id),
        "launching agent"
    );

    match cmd.status() {
        Ok(status) => {
            // Propagate the agent's exit code: `marshal run` should be transparent to
            // whatever launched it.
            ExitCode::from(status.code().unwrap_or(1) as u8)
        }
        Err(e) => {
            eprintln!("error: launching {}: {e}", cmd.get_program().to_string_lossy());
            ExitCode::FAILURE
        }
    }
}

/// Where the config lives when `--config` / `MARSHAL_CONFIG` was not given.
///
/// The XDG user config directory — `$XDG_CONFIG_HOME/bot-marshal/config.yaml`, or
/// `~/.config/bot-marshal/config.yaml` when `XDG_CONFIG_HOME` is unset — because that is the
/// sane default for a normal user running this interactively, which is the common case: `ca
/// init` and `marshal run` are inherently things a person types. A long-running system
/// service should not rely on this default at all and should pass `--config` explicitly
/// (see the README's "Running as a service") — this function is never consulted when it does.
fn default_config_path() -> anyhow::Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot determine a default config location: neither XDG_CONFIG_HOME nor HOME                  is set. Pass --config explicitly."
            )
        })?;
    Ok(base.join("bot-marshal").join("config.yaml"))
}

fn resolve_config_path(explicit: Option<PathBuf>) -> anyhow::Result<PathBuf> {
    match explicit {
        Some(p) => Ok(p),
        None => default_config_path(),
    }
}

/// Sends every event to the local syslog daemon over `/dev/log` (or `/var/run/syslog`),
/// mapping `tracing` level to syslog severity so `err`/`warning` show up as such to whatever
/// is consuming syslog (journald-on-top-of-syslog, `rsyslog`, a SIEM forwarder).
#[cfg(target_os = "linux")]
struct SyslogLayer(std::sync::Mutex<syslog::Logger<syslog::LoggerBackend, syslog::Formatter3164>>);

#[cfg(target_os = "linux")]
struct SyslogVisitor(String);

#[cfg(target_os = "linux")]
impl tracing::field::Visit for SyslogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        if field.name() == "message" {
            let _ = write!(self.0, "{value:?} ");
        } else {
            let _ = write!(self.0, "{}={value:?} ", field.name());
        }
    }
}

#[cfg(target_os = "linux")]
impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for SyslogLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = SyslogVisitor(String::new());
        event.record(&mut visitor);
        let Ok(mut logger) = self.0.lock() else { return };
        let _ = match *event.metadata().level() {
            tracing::Level::ERROR => logger.err(&visitor.0),
            tracing::Level::WARN => logger.warning(&visitor.0),
            tracing::Level::INFO => logger.info(&visitor.0),
            tracing::Level::DEBUG | tracing::Level::TRACE => logger.debug(&visitor.0),
        };
    }
}

/// Tries to install a journald layer. `Ok(false)` means journald just isn't reachable here
/// (not running under systemd, or the socket refused the connection) — the caller decides
/// whether that's a fallback trigger or a hard error depending on whether the sink was forced.
#[cfg(target_os = "linux")]
fn try_journald(filter: tracing_subscriber::EnvFilter) -> bool {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    match tracing_journald::layer() {
        Ok(journald) => {
            tracing_subscriber::registry().with(filter).with(journald).init();
            true
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
fn try_syslog(filter: tracing_subscriber::EnvFilter) -> bool {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let formatter = syslog::Formatter3164 {
        facility: syslog::Facility::LOG_DAEMON,
        hostname: None,
        process: "marshal".to_owned(),
        pid: std::process::id(),
    };
    match syslog::unix(formatter) {
        Ok(logger) => {
            let layer = SyslogLayer(std::sync::Mutex::new(logger));
            tracing_subscriber::registry().with(filter).with(layer).init();
            true
        }
        Err(_) => false,
    }
}

/// `auto` is the whole point: a human at a terminal gets colour and short lines, and
/// anything reading the stream programmatically — `docker logs`, a file redirect, a
/// supervisor that doesn't set `JOURNAL_STREAM` — gets one JSON object per line with no
/// flag required. journald and syslog format themselves and never reach this function.
fn init_stdout(filter: tracing_subscriber::EnvFilter, format: LogFormat) {
    use std::io::IsTerminal;
    let json = match format {
        LogFormat::Json => true,
        LogFormat::Pretty => false,
        LogFormat::Auto => !std::io::stdout().is_terminal(),
    };
    if json {
        tracing_subscriber::fmt().with_env_filter(filter).json().init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
    }
}

/// Turns the `--log` level plus `--log-detail` into one `EnvFilter` directive string. Both
/// `RequestDetail` levels emit on `target: "access"` — see `RequestTracingSink` — so a single
/// per-target directive turns per-request lines on or off, independently of whatever
/// verbosity `--log` asks for everything else (`RequestTracingSink` always emits at
/// info/warn); *which* detail level shows up is a property of which sink `serve` constructs,
/// not of this filter.
fn filter_directive(level: &str, detail: LogDetail) -> String {
    let access = if detail == LogDetail::Log { "off" } else { "info" };
    format!("{level},access={access}")
}

fn init_tracing(
    filter: &str,
    detail: LogDetail,
    sink: LogSink,
    format: LogFormat,
) -> anyhow::Result<()> {
    use tracing_subscriber::EnvFilter;
    let directive = filter_directive(filter, detail);
    let parsed = || EnvFilter::try_new(&directive).unwrap_or_else(|_| EnvFilter::new("info"));

    // `auto` prefers whatever OS-level log system is already there over inventing our own
    // file management: journald (structured fields, no re-parsing) first, then classic
    // syslog (still gets rotation/forwarding for free on non-systemd Linux), then plain
    // stdout — which is itself already captured by Docker, most init scripts, or an
    // interactive terminal. Each tier is a real connection attempt, not a guess from
    // `/proc`, so a machine that merely looks like it has journald but doesn't actually
    // accept the connection still falls through correctly. A forced sink (`--log-sink`)
    // skips the fallback chain entirely and errors out if that one sink isn't reachable,
    // rather than silently landing somewhere else — the point of forcing it.
    match sink {
        LogSink::Auto => {
            #[cfg(target_os = "linux")]
            {
                // systemd sets JOURNAL_STREAM for any unit whose stdout/stderr is connected
                // to the journal — a signal worth checking before spending a connection
                // attempt, since journald is otherwise indistinguishable from "not running"
                // this early in a container.
                if std::env::var_os("JOURNAL_STREAM").is_some() && try_journald(parsed()) {
                    return Ok(());
                }
                if try_syslog(parsed()) {
                    return Ok(());
                }
            }
            init_stdout(parsed(), format);
        }
        LogSink::Stdout => init_stdout(parsed(), format),
        #[cfg(target_os = "linux")]
        LogSink::Journald => {
            if !try_journald(parsed()) {
                anyhow::bail!(
                    "--log-sink journald was requested but the journal socket isn't reachable \
                     (not running under systemd, or JOURNAL_STREAM's target rejected the \
                     connection)"
                );
            }
        }
        #[cfg(target_os = "linux")]
        LogSink::Syslog => {
            if !try_syslog(parsed()) {
                anyhow::bail!(
                    "--log-sink syslog was requested but neither /dev/log nor /var/run/syslog \
                     is reachable"
                );
            }
        }
        #[cfg(not(target_os = "linux"))]
        LogSink::Journald | LogSink::Syslog => {
            anyhow::bail!("--log-sink journald/syslog are only supported on Linux");
        }
    }
    Ok(())
}

fn config_check(path: &std::path::Path) -> ExitCode {
    let cfg = match marshal_config::load(path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let diagnostics = validate(&cfg);
    let errors = diagnostics.iter().filter(|d| d.severity == Severity::Error).count();
    let warnings = diagnostics.len() - errors;

    for d in &diagnostics {
        eprintln!("{d}");
    }

    if errors > 0 {
        eprintln!("\n{errors} error(s), {warnings} warning(s)");
        return ExitCode::FAILURE;
    }

    println!(
        // +1 for the embedded `profile:`, always present but not part of `cfg.profiles` —
        // that map is exclusively the *named* ones under `profiles_path`.
        "{} ok: {} profile(s), {} bundle(s), {warnings} warning(s)",
        path.display(),
        cfg.profiles.len() + 1,
        cfg.bundles.len()
    );
    ExitCode::SUCCESS
}

/// Resolve the configured CA paths, expanding a leading `~`.
fn ca_paths(config_path: &std::path::Path) -> anyhow::Result<(PathBuf, PathBuf)> {
    let cfg = marshal_config::load(config_path)?;
    let cert =
        cfg.tls.ca_cert.clone().ok_or_else(|| {
            anyhow::anyhow!("tls.ca_cert is not set in {}", config_path.display())
        })?;
    let key = cfg
        .tls
        .ca_key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("tls.ca_key is not set in {}", config_path.display()))?;
    Ok((expand_tilde(&cert), expand_tilde(&key)))
}

fn expand_tilde(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => match std::env::var_os("HOME") {
            Some(home) => PathBuf::from(home).join(rest),
            None => PathBuf::from(p),
        },
        None => PathBuf::from(p),
    }
}

fn ca_command(config_path: &std::path::Path, cmd: CaCommand) -> ExitCode {
    let (cert_path, key_path) = match ca_paths(config_path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::FAILURE;
        }
    };

    match cmd {
        CaCommand::Init { common_name, days } => {
            let generated = match marshal_tls::CertificateAuthority::generate(&common_name, days) {
                Ok(g) => g,
                Err(e) => {
                    eprintln!("error: {e}");
                    return ExitCode::FAILURE;
                }
            };
            if let Err(e) =
                marshal_tls::CertificateAuthority::write(&generated, &cert_path, &key_path)
            {
                eprintln!("error: {e}");
                return ExitCode::FAILURE;
            }
            println!("wrote {}", cert_path.display());
            println!("wrote {} (mode 0600)", key_path.display());
            println!();
            println!("{}", marshal_tls::trust::instructions(&cert_path.display().to_string()));
            ExitCode::SUCCESS
        }
        CaCommand::Export { pem_only } => {
            let pem = match std::fs::read_to_string(&cert_path) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("error: reading {}: {e}", cert_path.display());
                    eprintln!("hint: run `marshal ca init` first");
                    return ExitCode::FAILURE;
                }
            };
            if pem_only {
                print!("{pem}");
            } else {
                print!("{pem}");
                println!();
                println!("{}", marshal_tls::trust::instructions(&cert_path.display().to_string()));
            }
            ExitCode::SUCCESS
        }
    }
}

/// Build the secret swaps declared by a profile's `request_transforms.secrets`.
fn build_injector(
    profile: &marshal_config::model::Profile,
    cfg: &marshal_config::model::Config,
) -> anyhow::Result<SecretInjector> {
    use marshal_core::SecretSource;

    let mut swaps = Vec::new();
    for (i, raw) in profile.request_transforms.secrets.iter().enumerate() {
        let spec: SecretSpec = serde_json::from_value(raw.clone())
            .map_err(|e| anyhow::anyhow!("request_transforms.secrets[{i}]: {e}"))?;

        let source: Arc<dyn SecretSource> = match &spec.source {
            SecretSourceSpec::Env { var } => Arc::new(marshal_secrets::EnvSource::new(var)),
            SecretSourceSpec::File { path, ttl, json_key } => {
                Arc::new(marshal_secrets::FileSource::new(
                    expand_tilde(path),
                    ttl.unwrap_or(std::time::Duration::from_secs(300)),
                    json_key.clone(),
                ))
            }
        };

        let name = spec.name.clone().unwrap_or_else(|| source.name().to_owned());
        let hosts = build_host_matcher(&spec.rules, cfg)?;

        swaps.push(SecretSwap {
            name,
            source,
            proxy_value: spec.proxy_value,
            sites: MatchSites {
                headers: if spec.match_headers.is_empty() {
                    vec!["authorization".into()]
                } else {
                    spec.match_headers
                },
                query: spec.match_query,
                body: spec.match_body,
            },
            require: spec.require,
            hosts,
        });
    }
    Ok(SecretInjector::new(swaps))
}

fn build_host_matcher(
    rules: &[HostRule],
    _cfg: &marshal_config::model::Config,
) -> anyhow::Result<marshal_policy::HostMatcher> {
    let domains: Vec<String> = rules.iter().filter_map(|r| r.host.clone()).collect();
    let cidrs: Vec<String> = rules.iter().filter_map(|r| r.cidr.clone()).collect();
    Ok(marshal_policy::HostMatcher::new(&domains, &cidrs)?)
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SecretSpec {
    /// Label used in the audit trail. Defaults to the source's own name.
    #[serde(default)]
    name: Option<String>,
    source: SecretSourceSpec,
    /// What the agent sends in place of the credential.
    proxy_value: String,
    #[serde(default)]
    match_headers: Vec<String>,
    #[serde(default)]
    match_body: bool,
    #[serde(default)]
    match_query: bool,
    #[serde(default)]
    require: bool,
    #[serde(default)]
    rules: Vec<HostRule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum SecretSourceSpec {
    Env {
        var: String,
    },
    File {
        path: String,
        #[serde(default, with = "humantime_serde")]
        ttl: Option<std::time::Duration>,
        #[serde(default)]
        json_key: Option<String>,
    },
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostRule {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    cidr: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two profiles, each with its own secret swap for the same host. This is the exact
    /// shape that used to break: `build_runtime` resolved only the fallback profile's
    /// `request_transforms.secrets`, so a non-fallback profile's swap was either silently
    /// never built, or — worse, if both profiles targeted the same host — the fallback
    /// profile's real credential could be injected into a session that resolved into the
    /// other profile entirely.
    fn write_two_profile_config(dir: &std::path::Path) -> std::path::PathBuf {
        let ca_dir = dir.join("ca");
        std::fs::create_dir_all(&ca_dir).unwrap();
        let generated = marshal_tls::CertificateAuthority::generate("test", 1).unwrap();
        marshal_tls::CertificateAuthority::write(
            &generated,
            &ca_dir.join("ca.crt"),
            &ca_dir.join("ca.key"),
        )
        .unwrap();

        // File sources rather than env vars, so the test needs no unsafe `set_var` and
        // cannot race with anything else in the same process.
        let secret_a = dir.join("secret-a.txt");
        std::fs::write(&secret_a, "real-value-a").unwrap();
        let secret_b = dir.join("secret-b.txt");
        std::fs::write(&secret_b, "real-value-b").unwrap();

        let profiles_dir = dir.join("profiles");
        std::fs::create_dir_all(&profiles_dir).unwrap();
        std::fs::write(
            profiles_dir.join("profile-a.yaml"),
            format!(
                r#"
default_action: deny
request_transforms:
  secrets:
    - name: SECRET_A
      source: {{ type: file, path: "{secret_a}" }}
      proxy_value: "placeholder-a"
      require: false
      rules: [{{ host: "api.example.com" }}]
"#,
                secret_a = secret_a.display(),
            ),
        )
        .unwrap();
        std::fs::write(
            profiles_dir.join("profile-b.yaml"),
            format!(
                r#"
default_action: deny
request_transforms:
  secrets:
    - name: SECRET_B
      source: {{ type: file, path: "{secret_b}" }}
      proxy_value: "placeholder-b"
      require: false
      rules: [{{ host: "api.example.com" }}]
"#,
                secret_b = secret_b.display(),
            ),
        )
        .unwrap();

        let config = dir.join("marshal.yaml");
        std::fs::write(
            &config,
            format!(
                r#"
tls:
  ca_cert: "{ca_dir}/ca.crt"
  ca_key: "{ca_dir}/ca.key"

profile:
  default_action: deny
"#,
                ca_dir = ca_dir.display(),
            ),
        )
        .unwrap();
        config
    }

    #[tokio::test]
    async fn each_profile_gets_only_its_own_secret_swap() {
        let dir =
            std::env::temp_dir().join(format!("marshal-build-runtime-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = write_two_profile_config(&dir);

        let (runtime, _, injectors) =
            build_runtime(&config, Some("profile-a".to_string())).expect("config builds");

        // The mechanical bug: request_transforms used to be a flat Vec built from one
        // profile, so it either lacked profile-b's swap entirely, or (worse, when hosts
        // overlapped, as they do here) applied profile-a's real secret to profile-b's
        // sessions. Both profiles must now have their own, independent entry.
        assert!(
            runtime.request_transforms.contains_key("profile-a"),
            "profile-a's own swap is missing"
        );
        assert!(
            runtime.request_transforms.contains_key("profile-b"),
            "profile-b's swap was dropped because it was not the fallback profile — this is \
             exactly the bug"
        );

        // And the redactor-seeding side of the same bug: every profile's real value must be
        // resolved, not just the fallback's, because a value belonging to any profile could
        // appear in a log line regardless of which session produced it.
        let mut all_values = Vec::new();
        for injector in &injectors {
            for (_, v) in injector.resolve_all().await {
                all_values.push(v.expose().to_owned());
            }
        }
        assert!(all_values.contains(&"real-value-a".to_string()), "{all_values:?}");
        assert!(
            all_values.contains(&"real-value-b".to_string()),
            "profile-b's secret value was never resolved, so it can never be redacted: \
             {all_values:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
