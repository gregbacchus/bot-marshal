//! `marshal` — the bot-marshal command line.

use std::path::PathBuf;
use std::process::ExitCode;

use std::collections::HashMap;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use marshal_audit::{JsonSink, MultiSink, TracingSink};
use marshal_config::{Severity, validate};
use marshal_core::{AuditSink, DenyingDecider};
use marshal_policy::build_chain;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};
use marshal_secrets::{MatchSites, SecretInjector, SecretSwap};

#[derive(Debug, Parser)]
#[command(name = "marshal", version, about = "Egress firewall for agents and bots")]
struct Cli {
    /// Path to the configuration file.
    #[arg(
        long,
        short,
        global = true,
        env = "MARSHAL_CONFIG",
        default_value = "config/marshal.yaml"
    )]
    config: PathBuf,

    /// Log level filter (`error`, `warn`, `info`, `debug`, `trace`).
    #[arg(long, global = true, env = "MARSHAL_LOG", default_value = "info")]
    log: String,

    #[command(subcommand)]
    command: Command,
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

        /// Write JSON audit records to this file instead of stdout.
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
    init_tracing(&cli.log);

    match cli.command {
        Command::Config(ConfigCommand::Check) => config_check(&cli.config),
        Command::Ca(cmd) => ca_command(&cli.config, cmd),
        Command::Run { profile, isolation, proxy, dry_run, command } => {
            run_command(&cli.config, &profile, &isolation, &proxy, dry_run, &command)
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
            match rt.block_on(serve(&cli.config, profile, listen, audit_log)) {
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
    audit_log: Option<PathBuf>,
) -> anyhow::Result<()> {
    let cfg = marshal_config::load(config_path)?;

    // Refuse to start on an invalid config. A proxy that boots with a chain the operator did
    // not write is worse than one that does not boot.
    let diagnostics = validate(&cfg);
    let mut fatal = false;
    for d in &diagnostics {
        match d.severity {
            Severity::Error => {
                eprintln!("{d}");
                fatal = true;
            }
            Severity::Warning => tracing::warn!("{d}"),
        }
    }
    if fatal {
        anyhow::bail!("configuration has errors; refusing to start");
    }

    // Every profile gets a chain, because which one applies is now decided per connection.
    // Building them all up front means a broken profile fails at startup rather than when the
    // first agent that uses it connects.
    let mut chains: HashMap<Arc<str>, Arc<marshal_policy::Chain>> = HashMap::new();
    let mut response_transforms: HashMap<Arc<str>, Vec<Arc<dyn marshal_core::ResponseTransform>>> =
        HashMap::new();
    for name in cfg.profiles.keys() {
        let chain = build_chain(&cfg, name, Arc::new(DenyingDecider))?;
        chains.insert(Arc::from(name.as_str()), Arc::new(chain));
        let transforms = marshal_policy::build_response_transforms(&cfg, name)?;
        if !transforms.is_empty() {
            response_transforms.insert(Arc::from(name.as_str()), transforms);
        }
    }

    let fallback = profile_override
        .or_else(|| cfg.sessions.unidentified.as_ref().map(|u| u.profile.clone()))
        .or_else(|| cfg.profiles.keys().next().cloned())
        .ok_or_else(|| anyhow::anyhow!("no profiles are defined"))?;
    anyhow::ensure!(chains.contains_key(fallback.as_str()), "unknown profile `{fallback}`");

    let sessions = Arc::new(build_sessions(&cfg, &fallback)?);

    let guard = UpstreamGuard::new(&cfg.upstream.deny_cidrs, cfg.upstream.allow_private)?;

    // Interception needs a CA. If none has been created, run as a tunnel and say so rather
    // than refusing to start — a proxy that sees destinations is still enforcing policy.
    let (cert_path, key_path) = ca_paths(config_path).unwrap_or_default();
    let tls = if cert_path.exists() && key_path.exists() {
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
        Some(Arc::new(marshal_proxy::mitm::TlsEngine::with_extra_roots(minter, &extra_roots)?))
    } else {
        None
    };

    let passthrough = marshal_policy::HostMatcher::new(&cfg.tls.passthrough, Vec::<&str>::new())?;

    // Secret swaps are built from the fallback profile. Per-profile transforms need the
    // transform set to be selected alongside the chain, which is a wider change than M4.
    let effective = marshal_policy::resolve_profile(&cfg, &fallback)?;
    let injector = build_injector(&effective, &cfg)?;
    let resolved = injector.resolve_all().await;
    let secret_names: Vec<String> = resolved.iter().map(|(n, _)| n.clone()).collect();
    if !resolved.is_empty() {
        tracing::info!(secrets = ?secret_names, "boundary secret injection active");
    }
    let secret_values: Vec<String> =
        resolved.into_iter().map(|(_, v)| v.expose().to_owned()).collect();
    let redactor = marshal_core::Redactor::new(secret_values.clone());
    let tracing_redactor = marshal_core::Redactor::new(secret_values);

    let json: Arc<dyn AuditSink> = match &audit_log {
        Some(path) => {
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .map_err(|e| anyhow::anyhow!("opening audit log {}: {e}", path.display()))?;
            Arc::new(JsonSink::new(file).redacting(redactor))
        }
        None => Arc::new(JsonSink::new(tokio::io::stdout()).redacting(redactor)),
    };
    let audit: Arc<dyn AuditSink> =
        Arc::new(MultiSink::new(vec![json, Arc::new(TracingSink::redacting(tracing_redactor))]));

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

    let mut transforms: Vec<Arc<dyn marshal_core::RequestTransform>> = Vec::new();
    if !injector.is_empty() {
        transforms.push(Arc::new(injector));
    }

    let server = Server::new(
        ServerConfig { listen, unix_socket, transparent, tls, passthrough },
        chains,
        sessions,
        Arc::new(guard),
        audit,
    )
    .with_request_transforms(transforms)
    .with_response_transforms(response_transforms);

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
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
        }
    }
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

    // The system resolver handles passthrough names. Reading the host's own configuration
    // means "passthrough" genuinely means what the host would have answered.
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
    fallback: &str,
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
                let uids = map
                    .iter()
                    .filter_map(|m| m.uid.map(|u| (u, m.session.clone(), m.profile.clone())));
                let cgroups = map.iter().filter_map(|m| {
                    m.cgroup.clone().map(|c| (c, m.session.clone(), m.profile.clone()))
                });
                resolvers.push(Arc::new(PeerCredResolver::new(uids, cgroups)?));
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

fn init_tracing(filter: &str) {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
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
        "{} ok: {} profile(s), {} bundle(s), {warnings} warning(s)",
        path.display(),
        cfg.profiles.len(),
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
