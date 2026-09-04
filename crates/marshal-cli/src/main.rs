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
use marshal_secrets::{SecretInjector, SecretSwap};

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
    /// request: identity, host, method, profile, deciding layer, duration. `audit` is the
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

    /// Credential management.
    #[command(subcommand)]
    Secrets(SecretsCommand),

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

        /// Extra path to bind read-write inside `--isolation netns`'s namespace, beyond the
        /// workspace and the standard system directories — a package manager cache outside
        /// the workspace, for instance. Repeatable. Ignored by every other isolation mode.
        #[arg(long = "bind")]
        binds: Vec<PathBuf>,

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
        /// `identities.unidentified.profile`.
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

/// Credentials marshal holds or obtains.
#[derive(Debug, Subcommand)]
enum SecretsCommand {
    /// Enrol and inspect OAuth2 credentials.
    #[command(subcommand)]
    Oauth(OauthCommand),
}

#[derive(Debug, Subcommand)]
enum OauthCommand {
    /// Authorise a credential once, interactively, so the proxy can use it unattended.
    ///
    /// Which flow runs is decided by the swap's `grant`: `authorization_code` opens a browser
    /// and captures the redirect on a loopback listener marshal binds itself; `device_code`
    /// prints a URL and a code to enter on any other device, and polls. Either way what is
    /// kept is a refresh token, under `state_dir` — never the access token, which is
    /// short-lived and re-minted on demand.
    Login {
        /// The `name` of the swap whose `source` is `{ type: oauth2, ... }`.
        ///
        /// With `--wait` or `--run` this is not a swap reference at all — bootstrap runs
        /// precisely when no such swap exists yet — but the storage key the captured
        /// credential is filed under, for a swap written afterwards.
        name: String,
        /// Open the authorization URL in a browser instead of only printing it.
        #[arg(long)]
        open: bool,
        /// Give up if the flow is not completed in this long.
        #[arg(long, default_value = "5m", value_parser = humantime::parse_duration)]
        timeout: std::time::Duration,

        /// Bootstrap: start an intercepting proxy and wait for somebody else's login.
        ///
        /// For a provider whose `client_id` and endpoints are not known — a vendor's own CLI
        /// subscription login. Point that tool's `HTTPS_PROXY` at the address printed here and
        /// log in as usual; marshal learns the credential from the token exchange the tool
        /// itself performs. Nothing needs to be configured for it beforehand.
        #[arg(long, conflicts_with = "run")]
        wait: bool,

        /// Bootstrap, running the command itself in a network sandbox.
        ///
        /// As `--wait`, but marshal launches the command itself, with no route out except its
        /// own proxy, so the exchange cannot avoid being seen.
        ///
        /// The command follows `--`, and everything after it is passed through verbatim —
        /// including the command's own flags.
        #[arg(long, conflicts_with = "wait")]
        run: bool,

        /// What bootstrap does with the exchange it captures.
        #[arg(long, default_value = "observe")]
        mode: BootstrapModeArg,

        /// Only capture exchanges to this host. Rarely needed — a bootstrap session usually
        /// has exactly one thing in flight.
        #[arg(long)]
        host: Option<String>,

        /// How `--run` confines the command. `netns` is the only one that actually prevents it
        /// routing around the proxy; the others identify without enforcing.
        #[arg(long, default_value = "netns")]
        isolation: String,

        /// The command `--run` launches. Everything after `--` reaches it untouched.
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },
    /// Show which OAuth2 credentials are enrolled, and since when.
    Status {
        /// Limit to one swap. Defaults to every OAuth2 swap in the config.
        name: Option<String>,
    },
    /// Forget a stored grant. The next request for it is refused until it is enrolled again.
    Logout { name: String },
    /// Discard the cached access token and mint a new one now, to check the credential works.
    Refresh { name: String },
}

/// What bootstrap capture does with the token exchange it observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum BootstrapModeArg {
    /// Forward it untouched. The tool's own login succeeds and it keeps a working credential
    /// too; marshal simply also has one. Right for a deliberate, supervised bootstrap.
    Observe,
    /// Redeem it out of band and answer the tool with a sentinel, so it never holds a working
    /// credential. Consistent with the rest of this proxy's design, at the cost of the tool
    /// reporting that the login failed — which, from its point of view, it did.
    Steal,
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

    // Before any subcommand runs, so every config-named variable resolves the same way no
    // matter which one needs it. `Sandbox` reaches here with an empty path and simply finds
    // nothing to load, which is right: it takes no config and injects no secrets.
    let env_file = match load_env_file(&config_path) {
        Ok(applied) => applied,
        Err(e) => {
            eprintln!("error: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(applied) = &env_file {
        // Counts, never names or values — this file is where the credentials are.
        tracing::debug!(
            path = %applied.path.display(),
            applied = applied.applied,
            already_set = applied.shadowed,
            "loaded env file"
        );
    }

    match cli.command {
        Command::Config(ConfigCommand::Check) => config_check(&config_path, env_file.as_ref()),
        Command::Ca(cmd) => ca_command(&config_path, cmd),
        Command::Secrets(SecretsCommand::Oauth(cmd)) => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: cannot start the async runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(oauth_command(&config_path, cmd)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("error: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Run { profile, isolation, proxy, binds, dry_run, command } => {
            run_command(&config_path, &profile, &isolation, &proxy, &binds, dry_run, &command)
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
    // Created before anything that could produce a secret, and never replaced — every audit
    // sink below holds a clone, and a credential minted at runtime teaches *this* redactor,
    // which is what makes it reach those clones (ADR-0029). A reload rebuilds the runtime
    // around the same redactor for the same reason.
    let redactor = marshal_core::Redactor::default();

    // Startup and reload go through the same builder, so a reload cannot succeed on a
    // config the proxy would have refused to start with — or the reverse.
    let build = {
        let config_path = config_path.to_path_buf();
        let redactor = redactor.clone();
        move || build_runtime(&config_path, profile_override.clone(), &redactor)
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
    for injector in &injectors {
        for (name, value) in injector.resolve_all().await {
            redactor.learn(&name, value.expose());
            secret_names.push(name);
        }
    }
    if !secret_names.is_empty() {
        tracing::info!(secrets = ?secret_names, "boundary secret injection active");
    }

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
        // Every record carries identities, destinations, paths and policy decisions — mode
        // 0600 on creation so another local user can't read it off a shared umask. This only
        // sets the mode on a file that doesn't exist yet; an existing file keeps whatever
        // permissions it already had.
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .await
            .map_err(|e| anyhow::anyhow!("opening audit log {}: {e}", path.display()))?;
        sinks.push(Arc::new(JsonSink::new(file).redacting(redactor)));
    }
    let audit: Arc<dyn AuditSink> = Arc::new(MultiSink::new(sinks));

    // `--listen` replaces the configured address list entirely rather than adding to it —
    // the same override semantics `--profile` uses for the unidentified fallback.
    let listen = match listen {
        Some(addr) => vec![addr],
        None => cfg
            .listeners
            .explicit
            .as_ref()
            .map(|e| e.listen.clone())
            .filter(|l| !l.is_empty())
            .unwrap_or_else(|| vec!["127.0.0.1:8080".to_owned()]),
    };
    let unix_socket = cfg
        .listeners
        .explicit
        .as_ref()
        .and_then(|e| e.unix_socket.as_ref())
        .map(|p| expand_tilde(p));

    let server = Server::new(
        ServerConfig { listen, unix_socket },
        Arc::clone(&handle),
        Arc::new(guard),
        audit,
    );
    let stats = server.stats();

    // The management API rebuilds through the same closure, and only swaps on success.
    let management = match cfg.listeners.management.clone() {
        Some(m) => {
            let token = marshal_core::env::var(&m.api_key_env);
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
    redactor: &marshal_core::Redactor,
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
    // profile must never fire for an identity resolved into a different one. Kept alongside as
    // `injectors` too, because the redactor below needs the union of every profile's real
    // secret values, not just whichever profile a given connection happens to resolve into —
    // a value belonging to any profile can end up in a log line regardless of which identity
    // produced it.
    let mut request_transforms: HashMap<Arc<str>, Vec<Arc<dyn marshal_core::RequestTransform>>> =
        HashMap::new();
    let mut responders: HashMap<Arc<str>, Vec<Arc<dyn marshal_core::RequestResponder>>> =
        HashMap::new();
    let mut injectors: Vec<Arc<SecretInjector>> = Vec::new();

    let deps = secret_deps(config_path, &cfg, redactor)?;

    type Built = (
        Arc<marshal_policy::Chain>,
        Vec<Arc<dyn marshal_core::ResponseTransform>>,
        Vec<Arc<dyn marshal_core::RequestTransform>>,
        Vec<Arc<dyn marshal_core::RequestResponder>>,
        Option<Arc<SecretInjector>>,
    );
    let build_one =
        |label: &str, profile: &marshal_config::model::Profile| -> anyhow::Result<Built> {
            let chain = Arc::new(build_chain(&cfg, label, profile, Arc::new(DenyingDecider))?);
            let mut response = marshal_policy::build_response_transforms(&cfg, label, profile)?;
            let mut request = marshal_policy::build_request_transforms(&cfg, label, profile)?;
            let resolved = marshal_policy::resolve_profile(&cfg, profile)?;
            let (injector, brokers) = build_secrets(&resolved, &cfg, &deps)?;

            // Before the injector: the broker rewrites an authorization request, and injecting a
            // credential into that request first would be setting a header on the one request in
            // the flow that is specifically not authenticated yet.
            let mut responders: Vec<Arc<dyn marshal_core::RequestResponder>> = Vec::new();
            for broker in brokers {
                request.push(Arc::clone(&broker) as Arc<dyn marshal_core::RequestTransform>);
                response.push(Arc::clone(&broker) as Arc<dyn marshal_core::ResponseTransform>);
                responders.push(broker as Arc<dyn marshal_core::RequestResponder>);
            }

            let injector = Arc::new(injector);
            let injector = if injector.is_empty() {
                None
            } else {
                request.push(Arc::clone(&injector) as Arc<dyn marshal_core::RequestTransform>);
                Some(injector)
            };
            Ok((chain, response, request, responders, injector))
        };

    let (
        default_chain,
        default_response_transforms,
        default_request_transforms,
        default_responders,
        default_injector,
    ) = build_one("profile", &cfg.profile)?;
    if let Some(injector) = default_injector {
        injectors.push(injector);
    }

    for (name, profile) in &cfg.profiles {
        let (chain, response, request, profile_responders, injector) = build_one(name, profile)?;
        chains.insert(Arc::from(name.as_str()), chain);
        if !response.is_empty() {
            response_transforms.insert(Arc::from(name.as_str()), response);
        }
        if !profile_responders.is_empty() {
            responders.insert(Arc::from(name.as_str()), profile_responders);
        }
        // Keyed on the transforms, not on the injector: a profile with `set_headers` and no
        // secrets still has request transforms, and gating the insert on the injector dropped
        // them silently.
        if !request.is_empty() {
            request_transforms.insert(Arc::from(name.as_str()), request);
        }
        if let Some(injector) = injector {
            injectors.push(injector);
        }
    }

    // `None` means "the embedded `profile:`" — always valid, since it's required to exist;
    // `Some(name)` is an explicit override that must actually name a built profile.
    let fallback_override: Option<Arc<str>> = profile_override
        .or_else(|| cfg.identities.unidentified.as_ref().and_then(|u| u.profile.clone()))
        .map(|s| Arc::from(s.as_str()));
    if let Some(name) = &fallback_override {
        anyhow::ensure!(chains.contains_key(name), "unknown profile `{name}`");
    }

    let identities = Arc::new(build_identities(&cfg, fallback_override)?);

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
    let extra_roots = read_extra_roots(&cfg)?;
    let tls = Arc::new(marshal_proxy::mitm::TlsEngine::with_extra_roots(minter, &extra_roots)?);

    let passthrough = marshal_policy::HostMatcher::new(&cfg.tls.passthrough, Vec::<&str>::new())?;

    Ok((
        marshal_proxy::runtime::Runtime {
            chains,
            response_transforms,
            responders,
            request_transforms,
            default_chain,
            default_response_transforms,
            default_responders,
            default_request_transforms,
            identities,
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
fn build_identities(
    cfg: &marshal_config::model::Config,
    fallback: Option<Arc<str>>,
) -> anyhow::Result<marshal_proxy::identity::IdentityRegistry> {
    use marshal_config::model::ResolverConfig;
    use marshal_proxy::identity::{
        IdentityRegistry, LaunchedResolver, PeerCredResolver, ProxyAuthResolver, SourceIpResolver,
    };

    let mut resolvers: Vec<Arc<dyn marshal_core::IdentityResolver>> = Vec::new();
    let mut enrich = false;

    for resolver in &cfg.identities.resolvers {
        match resolver {
            ResolverConfig::ProxyAuth { credentials } => {
                let mut entries = Vec::new();
                for c in credentials {
                    // A credential whose environment variable is unset is a configuration
                    // error, not an entry to skip: skipping it would silently downgrade that
                    // agent to the fallback profile.
                    let password = marshal_core::env::var(&c.password_env).ok_or_else(|| {
                        anyhow::anyhow!(
                            "identities.resolvers: `{}` is not set, so the credential for `{}` \
                             cannot be built",
                            c.password_env,
                            c.user
                        )
                    })?;
                    entries.push((c.user.clone(), password, c.identity.clone(), c.profile.clone()));
                }
                let r = ProxyAuthResolver::new(entries);
                if !r.is_empty() {
                    resolvers.push(Arc::new(r));
                }
            }
            ResolverConfig::SourceIp { map } => {
                resolvers.push(Arc::new(SourceIpResolver::new(
                    map.iter().map(|e| (e.cidr.clone(), e.identity.clone(), e.profile.clone())),
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
                            marshal_proxy::identity::peercred::resolve_username(name).map_err(
                                |e| {
                                    anyhow::anyhow!(
                                        "identities.resolvers: peer_cred username `{name}` \
                                         could not be resolved to a uid: {e}"
                                    )
                                },
                            )?,
                        ),
                        (None, None) => None,
                    };
                    if let Some(uid) = uid {
                        uids.push((uid, m.identity.clone(), m.profile.clone()));
                    }
                    let gid = match (m.gid, &m.groupname) {
                        (Some(gid), _) => Some(gid),
                        (None, Some(name)) => Some(
                            marshal_proxy::identity::peercred::resolve_groupname(name).map_err(
                                |e| {
                                    anyhow::anyhow!(
                                        "identities.resolvers: peer_cred groupname `{name}` \
                                         could not be resolved to a gid: {e}"
                                    )
                                },
                            )?,
                        ),
                        (None, None) => None,
                    };
                    if let Some(gid) = gid {
                        gids.push((gid, m.identity.clone(), m.profile.clone()));
                    }
                    if let Some(cgroup) = &m.cgroup {
                        cgroups.push((cgroup.clone(), m.identity.clone(), m.profile.clone()));
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
                resolvers.push(Arc::new(marshal_proxy::identity::ListenerPortResolver::new(
                    map.iter().map(|e| (e.port, e.identity.clone(), e.profile.clone())),
                )));
            }
        }
    }

    let deny_unidentified = matches!(
        cfg.identities.unidentified.as_ref().map(|u| u.action),
        Some(marshal_config::model::UnidentifiedAction::Deny)
    );

    Ok(IdentityRegistry::new(resolvers, fallback, deny_unidentified, enrich))
}

/// `marshal run`: launch an agent under a profile.
fn run_command(
    config_path: &std::path::Path,
    profile: &str,
    isolation: &str,
    proxy: &str,
    binds: &[PathBuf],
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
        binds,
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

/// What `load_env_file` actually did, for the one caller that reports it.
struct AppliedEnv {
    path: PathBuf,
    /// How many variables the file contributed — the ones the environment did not already
    /// have.
    applied: usize,
    /// How many the environment already had, and so were left alone.
    shadowed: usize,
}

/// Read `env_file:` and install it as the environment overlay.
///
/// This does *not* touch the process environment: see [`marshal_core::env`] for why not — in
/// short, the real environment must keep winning, and an agent launched by `marshal run` must
/// not inherit credentials the config went to the trouble of injecting at the boundary
/// instead. Everything that reads a config-named variable reads it through
/// `marshal_core::env::var`, so the overlay reaches all of them.
fn load_env_file(config_path: &std::path::Path) -> anyhow::Result<Option<AppliedEnv>> {
    let requested = marshal_config::env_file::requested_for(config_path);
    let Some((path, vars)) = marshal_config::env_file::read(&requested)? else {
        return Ok(None);
    };

    // A warning, not a refusal, unlike `state_dir` — that directory is one marshal creates and
    // owns, whereas an env file is often an existing file the operator already manages (and
    // may deliberately share with something else). Worth saying once, at startup, all the
    // same: it holds credentials.
    warn_if_world_readable(&path);

    let shadowed = vars.iter().filter(|(k, _)| std::env::var_os(k).is_some()).count();
    let applied = AppliedEnv { path, applied: vars.len() - shadowed, shadowed };
    marshal_core::env::install_overlay(vars);
    Ok(Some(applied))
}

fn warn_if_world_readable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(meta) = std::fs::metadata(path) else {
        return;
    };
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        tracing::warn!(
            path = %path.display(),
            mode = format!("{mode:o}"),
            "env file is readable by other local users; chmod 600 it"
        );
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

fn config_check(path: &std::path::Path, env_file: Option<&AppliedEnv>) -> ExitCode {
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

    // `validate` works on the config model, in which `request_transforms.secrets` is an
    // untyped `serde_json::Value` — the real schema lives in `SecretSpec` and is only applied
    // when the injector is built. Build them here too, so a misspelled field is caught by the
    // command whose whole job is to catch it rather than at the next start.
    if let Err(e) = check_secret_specs(path, &cfg) {
        eprintln!("error: {e:#}");
        eprintln!("\n1 error(s), {warnings} warning(s)");
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
    // The env file was already read and applied before this command ran — its syntax errors
    // and a missing named file have therefore already failed the check. Report what it
    // contributed, because "the variable is set" is otherwise invisible from the config alone,
    // and a variable the environment already had is a real reason a rotated file has no
    // effect.
    if let Some(env) = env_file {
        println!(
            "{}: {} variable(s) set, {} already in the environment",
            env.path.display(),
            env.applied,
            env.shadowed
        );
    }
    ExitCode::SUCCESS
}

/// Deserialise and build every profile's secret swaps, discarding the result.
///
/// Nothing here touches the network or the filesystem: constructing a source parses its
/// configuration, it does not resolve it. So this stays as side-effect-free as the rest of
/// `config check`, while covering a schema the validator cannot see.
fn check_secret_specs(
    path: &std::path::Path,
    cfg: &marshal_config::model::Config,
) -> anyhow::Result<()> {
    let deps = secret_deps(path, cfg, &marshal_core::Redactor::default())?;
    let check = |label: &str, profile: &marshal_config::model::Profile| -> anyhow::Result<()> {
        let resolved = marshal_policy::resolve_profile(cfg, profile)?;
        build_injector(&resolved, cfg, &deps)
            .map_err(|e| anyhow::anyhow!("profiles.{label}.request_transforms: {e}"))?;
        Ok(())
    };
    check("<fallback>", &cfg.profile)?;
    for (name, profile) in &cfg.profiles {
        check(name, profile)?;
    }
    Ok(())
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

/// One OAuth2 swap found in the config, ready to enrol or inspect.
struct OauthSwap {
    name: String,
    profile: String,
    grant: GrantSpec,
    source: marshal_secrets::Oauth2Source,
}

/// Every OAuth2 swap in the config, across every profile including the embedded fallback.
///
/// A swap name is scoped to its profile, so two profiles *can* declare the same name. They
/// then share one entry in the token store, which is deliberate — the same credential enrolled
/// once and used by both — and is why this collapses duplicates rather than reporting them.
fn oauth_swaps(
    config_path: &std::path::Path,
    cfg: &marshal_config::model::Config,
    deps: &SecretDeps,
) -> anyhow::Result<Vec<OauthSwap>> {
    let _ = config_path;
    let mut found: Vec<OauthSwap> = Vec::new();
    let mut collect =
        |label: &str, profile: &marshal_config::model::Profile| -> anyhow::Result<()> {
            let resolved = marshal_policy::resolve_profile(cfg, profile)?;
            for (i, raw) in resolved.request_transforms.secrets.iter().enumerate() {
                let spec: SecretSpec = serde_json::from_value(raw.clone()).map_err(|e| {
                    anyhow::anyhow!("profiles.{label}.request_transforms.secrets[{i}]: {e}")
                })?;
                let Some(SecretSourceSpec::Oauth2(oauth)) = &spec.source else { continue };
                let name = spec.name.clone().unwrap_or_else(|| format!("secrets[{i}]"));
                if found.iter().any(|f| f.name == name) {
                    continue;
                }
                found.push(OauthSwap {
                    source: build_oauth2_source(oauth, deps, &name)?,
                    name,
                    profile: label.to_owned(),
                    grant: oauth.grant,
                });
            }
            Ok(())
        };
    collect("<fallback>", &cfg.profile)?;
    for (name, profile) in &cfg.profiles {
        collect(name, profile)?;
    }
    Ok(found)
}

fn find_oauth_swap(swaps: Vec<OauthSwap>, name: &str) -> anyhow::Result<OauthSwap> {
    let known: Vec<&str> = swaps.iter().map(|s| s.name.as_str()).collect();
    let known = if known.is_empty() {
        "this config declares no OAuth2 credentials".to_owned()
    } else {
        format!("known: {}", known.join(", "))
    };
    swaps
        .into_iter()
        .find(|s| s.name == name)
        .ok_or_else(|| anyhow::anyhow!("no OAuth2 credential named `{name}` — {known}"))
}

async fn oauth_command(config_path: &std::path::Path, cmd: OauthCommand) -> anyhow::Result<()> {
    let cfg = marshal_config::load(config_path)?;
    // Shared, not throwaway: bootstrap runs an audit sink, and the capture object teaches this
    // same redactor before anything it captured can be logged (ADR-0029).
    let deps = secret_deps(config_path, &cfg, &marshal_core::Redactor::default())?;

    // Built lazily. Bootstrap runs when no swap is configured yet, and must not be blocked by
    // an unrelated one elsewhere in the config failing to build.
    let swaps = || oauth_swaps(config_path, &cfg, &deps);

    match cmd {
        OauthCommand::Status { name } => {
            let swaps: Vec<OauthSwap> = match name {
                Some(n) => vec![find_oauth_swap(swaps()?, &n)?],
                None => swaps()?,
            };
            if swaps.is_empty() {
                println!("no OAuth2 credentials are configured");
                return Ok(());
            }
            for swap in &swaps {
                let state = match swap.grant {
                    GrantSpec::ClientCredentials | GrantSpec::RefreshToken => {
                        "n/a — needs no enrolment".to_owned()
                    }
                    _ => match deps.store.grant(&swap.name) {
                        Ok(Some(g)) => format!("enrolled{}", describe_age(g.obtained_at)),
                        Ok(None) => format!(
                            "NOT enrolled — run `marshal secrets oauth login {}`",
                            swap.name
                        ),
                        Err(e) => format!("unreadable: {e}"),
                    },
                };
                println!(
                    "{:<24} profile={:<16} grant={:<20} {state}",
                    swap.name,
                    swap.profile,
                    swap.grant.label()
                );
            }
            Ok(())
        }

        OauthCommand::Logout { name } => {
            let swap = find_oauth_swap(swaps()?, &name)?;
            if deps.store.remove_grant(&swap.name)? {
                println!("forgot the stored grant for `{}`", swap.name);
                println!(
                    "note: this does not revoke anything at the provider — do that there too \
                     if the credential may have leaked"
                );
            } else {
                println!("`{}` had no stored grant", swap.name);
            }
            Ok(())
        }

        OauthCommand::Refresh { name } => {
            use marshal_core::SecretSource;
            let swap = find_oauth_swap(swaps()?, &name)?;
            deps.store.forget_access(&swap.name);
            // The value is deliberately not printed: the point is that it works, and putting
            // a live token on a terminal (and into a shell history, and a scrollback buffer)
            // undoes what this whole feature is for.
            swap.source.resolve().await?;
            println!("`{}`: minted a fresh access token successfully", swap.name);
            Ok(())
        }

        OauthCommand::Login { name, open, timeout, wait, run, mode, host, isolation, command } => {
            anyhow::ensure!(
                run || command.is_empty(),
                "`{}` was given as a command but there is no `--run` to launch it. Did you mean \
                 `marshal secrets oauth login {name} --run -- {}`?",
                command.join(" "),
                command.join(" ")
            );
            anyhow::ensure!(
                !run || !command.is_empty(),
                "`--run` needs a command to launch: \
                 `marshal secrets oauth login {name} --run -- <cmd> [args...]`"
            );

            // The bootstrap path forks here, before any swap lookup: it runs precisely when no
            // swap is configured for this credential yet, so `name` is a storage key rather
            // than a reference to anything.
            if wait || run {
                anyhow::ensure!(
                    deps.store.persists(),
                    "bootstrapping `{name}` needs a top-level `state_dir` to keep the captured \
                     refresh token in — set one before starting a login you would have to redo"
                );
                let opts = BootstrapOptions {
                    name,
                    mode: match mode {
                        BootstrapModeArg::Observe => marshal_secrets::CaptureMode::Observe,
                        BootstrapModeArg::Steal => marshal_secrets::CaptureMode::Steal,
                    },
                    host,
                    timeout,
                    run: command,
                    isolation,
                };
                return bootstrap_capture(config_path, &cfg, &deps, opts).await;
            }

            let swap = find_oauth_swap(swaps()?, &name)?;
            anyhow::ensure!(
                deps.store.persists(),
                "enrolling `{}` needs a top-level `state_dir` to keep the refresh token in",
                swap.name
            );
            let enrolled = match swap.grant {
                GrantSpec::ClientCredentials | GrantSpec::RefreshToken | GrantSpec::JwtBearer => {
                    anyhow::bail!(
                        "`{}` uses `grant: {}`, which needs no enrolment — it authenticates from \
                     configuration alone. `marshal secrets oauth refresh {}` checks it works.",
                        swap.name,
                        swap.grant.label(),
                        swap.name
                    )
                }
                GrantSpec::AuthorizationCode => {
                    login_authorization_code(&swap, open, timeout).await?
                }
                GrantSpec::DeviceCode => login_device_code(&swap, open, timeout).await?,
            };
            println!("\n`{}` is enrolled.", swap.name);
            if let Some(scope) = &enrolled.scope {
                println!("  granted scope: {scope}");
            }
            println!(
                "  the refresh token is stored under `state_dir`; the proxy mints access \
                 tokens from it as needed"
            );
            Ok(())
        }
    }
}

/// Everything `--wait`/`--run` needs, gathered so the driver signature stays readable.
struct BootstrapOptions {
    name: String,
    mode: marshal_secrets::CaptureMode,
    host: Option<String>,
    timeout: std::time::Duration,
    /// Empty for `--wait`; the command to sandbox for `--run`.
    run: Vec<String>,
    isolation: String,
}

/// An audit sink that keeps nothing.
///
/// `Server::new` requires a sink and there is no no-op one in the tree. A bootstrap session is
/// a foreground diagnostic that exists for one exchange, so there is nothing worth persisting —
/// and the one thing that must not happen is a captured credential reaching a durable record.
/// Records still carry no body content (`mitm::emit` never writes one), but discarding removes
/// the question entirely.
#[derive(Debug)]
struct DiscardingAudit;

#[async_trait::async_trait]
impl marshal_core::AuditSink for DiscardingAudit {
    async fn emit(&self, record: marshal_core::AuditRecord) {
        tracing::debug!(
            host = %record.host,
            method = %record.method,
            action = ?record.action,
            "bootstrap session request"
        );
    }
}

/// Run a bootstrap capture session: stand up an intercepting proxy, wait for somebody's token
/// exchange to pass through it, and keep what it yields.
async fn bootstrap_capture(
    config_path: &std::path::Path,
    cfg: &marshal_config::model::Config,
    deps: &SecretDeps,
    opts: BootstrapOptions,
) -> anyhow::Result<()> {
    use marshal_core::{DenyingDecider, RequestResponder, RequestTransform, ResponseTransform};

    let sandboxed = !opts.run.is_empty();
    let isolation: marshal_launch::Isolation =
        opts.isolation.parse().map_err(|e| anyhow::anyhow!("{e}"))?;
    if sandboxed {
        preflight_isolation(isolation)?;
    }

    // The real CA, not a throwaway: whatever the operator already trusts for `serve` covers
    // this too, and `proxy_env` points a sandboxed command's trust stores at the same file.
    let (cert_path, key_path) = ca_paths(config_path)?;
    anyhow::ensure!(
        cert_path.exists() && key_path.exists(),
        "bootstrap intercepts TLS, so it needs the CA at {} — run `marshal ca init` first",
        cert_path.display()
    );
    let ca = marshal_tls::CertificateAuthority::from_pem(
        &std::fs::read_to_string(&cert_path)?,
        &std::fs::read_to_string(&key_path)?,
    )?;
    let minter = Arc::new(marshal_tls::LeafMinter::new(
        Arc::new(ca),
        cfg.tls.cert_cache_size,
        cfg.tls.leaf_expiry_hours,
    ));
    let engine = Arc::new(marshal_proxy::mitm::TlsEngine::with_extra_roots(
        minter,
        &read_extra_roots(cfg)?,
    )?);

    let (capture, captured) = marshal_secrets::BootstrapCapture::new(
        opts.name.clone(),
        opts.mode,
        opts.host.clone(),
        Arc::clone(&deps.store),
        Arc::clone(&deps.tls),
        deps.guard.clone(),
        deps.redactor.clone(),
        opts.timeout,
    );

    // A permissive chain, deliberately. This listener is not policing an agent — it exists for
    // one exchange, in the foreground, under a timeout, and denying the provider traffic the
    // operator is trying to complete would defeat the point. The upstream guard still applies.
    // See ADR-0033 on why this does not go through `default_action`'s config gate.
    let chain = Arc::new(marshal_policy::Chain::new(
        "bootstrap",
        vec![],
        marshal_core::Decision::Allow,
        Arc::new(DenyingDecider),
    ));

    // Never derived from config or `state_dir`: `bind_unix` removes an existing path before
    // binding, so colliding with a running daemon's socket would delete it and silently take
    // over its traffic.
    let socket_dir = std::env::temp_dir().join(format!("marshal-bootstrap-{}", std::process::id()));
    std::fs::create_dir_all(&socket_dir)?;
    let socket = socket_dir.join("proxy.sock");

    let runtime = marshal_proxy::runtime::Runtime {
        chains: HashMap::new(),
        response_transforms: HashMap::new(),
        responders: HashMap::new(),
        request_transforms: HashMap::new(),
        default_chain: chain,
        default_response_transforms: vec![Arc::clone(&capture) as Arc<dyn ResponseTransform>],
        default_responders: vec![Arc::clone(&capture) as Arc<dyn RequestResponder>],
        default_request_transforms: vec![Arc::clone(&capture) as Arc<dyn RequestTransform>],
        identities: Arc::new(build_identities(cfg, None)?),
        passthrough: marshal_policy::HostMatcher::new(&cfg.tls.passthrough, Vec::<&str>::new())?,
        tls: engine,
    };

    let server = marshal_proxy::Server::new(
        marshal_proxy::ServerConfig {
            listen: vec!["127.0.0.1:0".into()],
            unix_socket: sandboxed.then(|| socket.clone()),
        },
        Arc::new(marshal_proxy::runtime::RuntimeHandle::new(runtime)),
        Arc::new(marshal_http::UpstreamGuard::new(
            &cfg.upstream.deny_cidrs,
            cfg.upstream.allow_private,
        )?),
        Arc::new(DiscardingAudit),
    );

    let (bound_tx, bound_rx) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async move {
        let mut tx = Some(bound_tx);
        server
            .run(move |addr| {
                let _ = tx.take().unwrap().send(addr);
            })
            .await
    });
    let addr =
        bound_rx.await.map_err(|_| anyhow::anyhow!("the bootstrap listener failed to bind"))?;

    let outcome = if sandboxed {
        run_sandboxed_bootstrap(&opts, isolation, addr, &socket, &cert_path, captured).await
    } else {
        println!("Bootstrapping `{}`. In another terminal, run the tool's login with:", opts.name);
        println!("\n  export HTTPS_PROXY=http://{addr}");
        println!("  export SSL_CERT_FILE={}\n", cert_path.display());
        println!("then log in as you normally would. Waiting up to {:?} ...", opts.timeout);
        tokio::time::timeout(opts.timeout, captured)
            .await
            .map_err(|_| {
                anyhow::anyhow!("no token exchange was captured within {:?}", opts.timeout)
            })?
            .map_err(|_| anyhow::anyhow!("the capture channel closed before anything was captured"))
    };

    serving.abort();
    let _ = std::fs::remove_dir_all(&socket_dir);
    report_bootstrap(&opts, outcome?)
}

/// Preflight exactly what `marshal run` does, with the same alternatives named.
fn preflight_isolation(isolation: marshal_launch::Isolation) -> anyhow::Result<()> {
    use marshal_launch::Isolation;
    if matches!(isolation, Isolation::Cgroup | Isolation::Netns)
        && !marshal_launch::systemd_available()
    {
        anyhow::bail!(
            "`--isolation {}` needs systemd-run, which is not available here. Use \
             `--isolation none` to launch with proxy environment variables only, accepting that \
             the command could then route around the proxy and the exchange would never be seen.",
            if isolation == Isolation::Netns { "netns" } else { "cgroup" }
        );
    }
    if isolation == Isolation::Netns {
        anyhow::ensure!(
            marshal_launch::bwrap_available(),
            "`--isolation netns` needs bubblewrap (`bwrap`), which is not installed. Install it, \
             or use `--isolation cgroup` — which does not stop the command routing around the \
             proxy, so the exchange may never be seen."
        );
        anyhow::ensure!(
            marshal_launch::netns_available(),
            "bwrap cannot create a network namespace here, which usually means unprivileged user \
             namespaces are disabled (`sysctl kernel.unprivileged_userns_clone`). Use \
             `--isolation cgroup`."
        );
    }
    Ok(())
}

/// `--run`: launch the command against the ephemeral proxy and race it against the capture.
async fn run_sandboxed_bootstrap(
    opts: &BootstrapOptions,
    isolation: marshal_launch::Isolation,
    addr: std::net::SocketAddr,
    socket: &std::path::Path,
    cert_path: &std::path::Path,
    captured: tokio::sync::oneshot::Receiver<marshal_secrets::Bootstrapped>,
) -> anyhow::Result<marshal_secrets::Bootstrapped> {
    let endpoint = marshal_launch::ProxyEndpoint {
        url: format!("http://{addr}"),
        ca_cert: Some(cert_path.to_path_buf()),
        credential: None,
    };
    // Only `netns` reaches the proxy through the Unix socket; the other modes use the proxy
    // environment variables and would be handed a path they never open.
    let socket = if isolation == marshal_launch::Isolation::Netns {
        // The listener binds asynchronously, so the file may not exist yet — and
        // `build_command_with` rejects a path that does not, which would otherwise be a race
        // that fails on a loaded machine and passes everywhere else.
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        anyhow::ensure!(
            socket.exists(),
            "the bootstrap listener did not bind its Unix socket at {}",
            socket.display()
        );
        Some(socket)
    } else {
        None
    };

    let mut cmd = marshal_launch::build_command_with(
        isolation,
        "bootstrap",
        std::process::id(),
        &endpoint,
        &opts.run,
        socket,
        &[],
    )?;

    println!("Bootstrapping `{}` by running: {}", opts.name, opts.run.join(" "));
    let mut child = tokio::process::Command::from(cmd_into_tokio(&mut cmd)).spawn()?;

    tokio::select! {
        // The capture is what matters; a command that exits afterwards is fine.
        result = captured => result
            .map_err(|_| anyhow::anyhow!("the capture channel closed before anything was captured")),
        status = child.wait() => {
            let status = status?;
            anyhow::bail!(
                "`{}` exited ({status}) without a token exchange being captured. If it opened a \
                 browser, the login may simply not have finished — `--wait` lets you drive it by \
                 hand instead. If it made no network calls through the proxy at all, check that \
                 it honours proxy environment variables.",
                opts.run.join(" ")
            )
        }
        _ = tokio::time::sleep(opts.timeout) => {
            let _ = child.start_kill();
            anyhow::bail!("no token exchange was captured within {:?}", opts.timeout)
        }
    }
}

/// `std::process::Command` carries everything `build_command_with` configured; this moves it
/// across without losing the program, args or environment.
fn cmd_into_tokio(cmd: &mut std::process::Command) -> std::process::Command {
    let mut out = std::process::Command::new(cmd.get_program());
    out.args(cmd.get_args());
    for (k, v) in cmd.get_envs() {
        match v {
            Some(v) => out.env(k, v),
            None => out.env_remove(k),
        };
    }
    if let Some(dir) = cmd.get_current_dir() {
        out.current_dir(dir);
    }
    out
}

/// Report what was learned — configuration, never a credential.
fn report_bootstrap(
    opts: &BootstrapOptions,
    learned: marshal_secrets::Bootstrapped,
) -> anyhow::Result<()> {
    if !learned.enrolled {
        println!(
            "\nCaptured a `{}` exchange, but the provider issued no refresh token.",
            opts.name
        );
        println!(
            "  Nothing was enrolled: an access token alone does not survive a restart. Most \n\
             \x20 providers need `offline_access` in the requested scope (Google wants \n\
             \x20 `access_type=offline`), which is the tool's own request to change, not \n\
             \x20 marshal's."
        );
        anyhow::bail!("nothing enrolled");
    }

    println!("\n`{}` is enrolled.", opts.name);
    if let Some(scope) = &learned.scope {
        println!("  granted scope: {scope}");
    }
    println!("  the refresh token is stored under `state_dir`; nothing else was kept.\n");
    println!("Discovered configuration — add this to a profile to use it unattended:\n");
    println!("  - name: {}", opts.name);
    println!("    source:");
    println!("      type: oauth2");
    println!("      grant: authorization_code");
    println!("      token_endpoint: {}", learned.token_endpoint);
    match &learned.client_id {
        Some(id) => println!("      client_id: {id}"),
        None => println!("      client_id: # the exchange sent none; check the provider's docs"),
    }
    if let Some(uri) = &learned.redirect_uri {
        println!("      redirect_uri: {uri}");
    }
    println!("      client_auth: none   # adjust if the provider needs a client secret");
    println!("    inject: {{ type: bearer }}");
    println!("    rules: [{{ host: \"...\" }}]   # scope this to the API it authenticates");
    Ok(())
}

fn describe_age(obtained_at: i64) -> String {
    if obtained_at == 0 {
        return String::new();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let days = (now - obtained_at) / 86_400;
    match days {
        d if d < 0 => String::new(),
        0 => " (today)".to_owned(),
        1 => " (1 day ago)".to_owned(),
        d => format!(" ({d} days ago)"),
    }
}

/// Try to open a URL in the operator's browser. Best effort: printing it is the contract.
fn try_open(url: &str) {
    let opener = if cfg!(target_os = "macos") { "open" } else { "xdg-open" };
    match std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(_) => println!("(opening it in your browser)"),
        Err(e) => println!("(could not run `{opener}`: {e} — open the URL above by hand)"),
    }
}

async fn login_authorization_code(
    swap: &OauthSwap,
    open: bool,
    timeout: std::time::Duration,
) -> anyhow::Result<marshal_secrets::Enrolled> {
    let flow = swap.source.begin_authorization_code()?;
    let listener = bind_redirect(&flow.redirect_uri).await?;

    println!("Authorise `{}` by opening:\n\n  {}\n", swap.name, flow.url);
    if open {
        try_open(&flow.url);
    }
    println!("Waiting for the redirect on {} ...", flow.redirect_uri);

    let (code, state) =
        tokio::time::timeout(timeout, await_callback(listener)).await.map_err(|_| {
            anyhow::anyhow!(
                "timed out after {} waiting for the redirect",
                humantime::format_duration(timeout)
            )
        })??;

    anyhow::ensure!(
        flow.state_matches(&state),
        "the redirect carried a `state` marshal did not issue, so it belongs to a different \
         authorization attempt. Nothing was exchanged. Run the command again."
    );

    println!("Got the authorization code; exchanging it ...");
    Ok(swap.source.complete_authorization_code(&code, &flow).await?)
}

/// Bind the loopback address named by `redirect_uri`.
///
/// Done before the URL is printed, so a port already in use fails immediately rather than
/// after the operator has authorised in a browser and the code is already spent.
async fn bind_redirect(redirect_uri: &str) -> anyhow::Result<tokio::net::TcpListener> {
    let authority = redirect_uri
        .strip_prefix("http://")
        .and_then(|rest| rest.split('/').next())
        .ok_or_else(|| anyhow::anyhow!("redirect_uri must be an http:// URL"))?;
    let addr = if authority.contains(':') {
        authority.replace("localhost", "127.0.0.1")
    } else {
        format!("{}:80", authority.replace("localhost", "127.0.0.1"))
    };
    tokio::net::TcpListener::bind(&addr).await.map_err(|e| {
        anyhow::anyhow!(
            "cannot bind {addr} to receive the redirect: {e}. The `redirect_uri` port must be \
             free, and must match what the provider has registered for this client."
        )
    })
}

/// Accept one redirect and read `code` and `state` out of its query string.
async fn await_callback(listener: tokio::net::TcpListener) -> anyhow::Result<(String, String)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    loop {
        let (mut stream, _) = listener.accept().await?;
        let mut buf = vec![0u8; 8192];
        let n = stream.read(&mut buf).await?;
        let request = String::from_utf8_lossy(&buf[..n]).into_owned();

        // "GET /callback?code=...&state=... HTTP/1.1"
        let Some(target) = request.split_whitespace().nth(1) else { continue };
        let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
        let mut code = None;
        let mut state = None;
        let mut error = None;
        for pair in query.split('&') {
            let Some((k, v)) = pair.split_once('=') else { continue };
            let v = percent_decode(v);
            match k {
                "code" => code = Some(v),
                "state" => state = Some(v),
                "error" => error = Some(v),
                "error_description" => {
                    error = Some(error.map_or(v.clone(), |e| format!("{e}: {v}")))
                }
                _ => {}
            }
        }

        // A browser fetching /favicon.ico on the same listener is normal; ignore anything
        // that is not the redirect and keep waiting.
        if code.is_none() && error.is_none() {
            let _ = stream.write_all(reply(404, "Not the redirect.").as_bytes()).await;
            continue;
        }

        let body = match (&code, &error) {
            (_, Some(e)) => format!("Authorisation failed: {e}. You can close this tab."),
            _ => "Authorised. marshal has the credential; you can close this tab.".to_owned(),
        };
        let _ = stream.write_all(reply(200, &body).as_bytes()).await;
        let _ = stream.flush().await;

        if let Some(e) = error {
            anyhow::bail!("the provider refused the authorization request: {e}");
        }
        return Ok((code.expect("checked above"), state.unwrap_or_default()));
    }
}

fn reply(status: u16, message: &str) -> String {
    // Plain text on purpose: this page is shown once, to one person, on loopback.
    format!(
        "HTTP/1.1 {status} X\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{message}",
        message.len()
    )
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn login_device_code(
    swap: &OauthSwap,
    open: bool,
    timeout: std::time::Duration,
) -> anyhow::Result<marshal_secrets::Enrolled> {
    let device = swap.source.begin_device_authorization().await?;

    println!("Authorise `{}` on any device:\n", swap.name);
    match &device.verification_uri_complete {
        Some(complete) => {
            println!("  {complete}\n");
            println!(
                "  (or go to {} and enter the code {})",
                device.verification_uri, device.user_code
            );
            if open {
                try_open(complete);
            }
        }
        None => {
            println!("  {}", device.verification_uri);
            println!("  code: {}\n", device.user_code);
            if open {
                try_open(&device.verification_uri);
            }
        }
    }

    // The provider's own expiry bounds the flow; --timeout only shortens it.
    let deadline = std::time::Instant::now() + device.expires_in.min(timeout);
    let mut interval = device.interval;
    println!("\nWaiting for authorisation ...");

    loop {
        tokio::time::sleep(interval).await;
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "the device code expired before it was authorised — run the command again"
            );
        }
        match swap.source.poll_device_token(&device.device_code).await? {
            marshal_secrets::DevicePoll::Done(enrolled) => return Ok(enrolled),
            marshal_secrets::DevicePoll::Pending => continue,
            marshal_secrets::DevicePoll::SlowDown => {
                // RFC 8628 §3.5: back off by 5 seconds and keep going, rather than failing.
                interval += std::time::Duration::from_secs(5);
                tracing::debug!(interval_secs = interval.as_secs(), "polling more slowly");
            }
        }
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
    deps: &SecretDeps,
) -> anyhow::Result<SecretInjector> {
    Ok(build_secrets(profile, cfg, deps)?.0)
}

/// Everything a profile's `secrets` produce: the swaps, and any in-band OAuth2 brokers.
///
/// A broker is not a swap — it is three hooks on the request path rather than a credential to
/// set — so it comes back separately rather than being folded into the injector.
fn build_secrets(
    profile: &marshal_config::model::Profile,
    cfg: &marshal_config::model::Config,
    deps: &SecretDeps,
) -> anyhow::Result<(SecretInjector, Vec<Arc<marshal_secrets::Oauth2Broker>>)> {
    use marshal_core::SecretSource;

    let mut brokers: Vec<Arc<marshal_secrets::Oauth2Broker>> = Vec::new();
    // An OAuth2 credential's own endpoints, which must never have that credential injected
    // into them — see `SecretInjector::excluding` for why.
    let mut exceptions: Vec<(String, String)> = Vec::new();

    let mut swaps = Vec::new();
    for (i, raw) in profile.request_transforms.secrets.iter().enumerate() {
        let spec: SecretSpec = serde_json::from_value(raw.clone())
            .map_err(|e| anyhow::anyhow!("request_transforms.secrets[{i}]: {e}"))?;

        let hosts = build_host_matcher(&spec.rules, cfg)?;

        // An `oauth2` source keys its token store and its redaction label on the swap name,
        // so it has to know that name at construction — before the `name.unwrap_or(default)`
        // below, which derives it from the source. A swap using one therefore has to say what
        // it is called; there is nothing sensible to derive it from.
        let swap_label = spec.name.clone().unwrap_or_else(|| format!("secrets[{i}]"));

        if let Some(SecretSourceSpec::Oauth2(oauth)) = &spec.source {
            for url in [Some(&oauth.token_endpoint), oauth.authorization_endpoint.as_ref()]
                .into_iter()
                .flatten()
            {
                if let Some(pair) = host_and_path(url) {
                    exceptions.push(pair);
                }
            }
            if oauth.capture == CaptureSpec::InBand {
                brokers.push(Arc::new(
                    build_broker(oauth, deps, &swap_label)
                        .map_err(|e| anyhow::anyhow!("request_transforms.secrets[{i}]: {e}"))?,
                ));
            }
        }

        // `source` is required for every kind except `sigv4`, which carries its own two (or
        // three) secrets instead — one `source:` value cannot express an access key pair.
        let require_source = || -> anyhow::Result<Arc<dyn SecretSource>> {
            let s = spec.source.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "request_transforms.secrets[{i}]: `source` is required for this `inject.type`"
                )
            })?;
            build_source(s, deps, &swap_label)
        };

        let injection = match &spec.inject {
            InjectSpec::Basic { username } => marshal_secrets::Injection::Basic {
                username: username.clone(),
                source: require_source()?,
            },
            InjectSpec::Bearer => marshal_secrets::Injection::Bearer { source: require_source()? },
            InjectSpec::Header { name } => {
                let header_name = http::HeaderName::try_from(name.as_str()).map_err(|e| {
                    anyhow::anyhow!(
                        "request_transforms.secrets[{i}].inject.name: invalid header name \
                         {name:?}: {e}"
                    )
                })?;
                marshal_secrets::Injection::Header { name: header_name, source: require_source()? }
            }
            InjectSpec::Query { name } => {
                marshal_secrets::Injection::Query { name: name.clone(), source: require_source()? }
            }
            InjectSpec::Sigv4(sigv4) => {
                let Sigv4Spec {
                    access_key_id,
                    secret_access_key,
                    session_token,
                    region,
                    service,
                    max_body_bytes,
                } = sigv4.as_ref();
                if spec.source.is_some() {
                    anyhow::bail!(
                        "request_transforms.secrets[{i}]: `source` has no effect with \
                         `inject.type: sigv4` — set `access_key_id` and `secret_access_key` \
                         on the sigv4 spec instead"
                    );
                }
                marshal_secrets::Injection::SigV4 {
                    access_key_id: build_source(access_key_id, deps, &swap_label)?,
                    secret_access_key: build_source(secret_access_key, deps, &swap_label)?,
                    session_token: session_token
                        .as_ref()
                        .map(|t| build_source(t, deps, &swap_label))
                        .transpose()?,
                    region: region.clone(),
                    service: service.clone(),
                    body_cap: max_body_bytes.unwrap_or(1_048_576),
                }
            }
        };

        let default_name = match &injection {
            marshal_secrets::Injection::Basic { source, .. }
            | marshal_secrets::Injection::Bearer { source }
            | marshal_secrets::Injection::Header { source, .. }
            | marshal_secrets::Injection::Query { source, .. } => source.name().to_owned(),
            marshal_secrets::Injection::SigV4 { access_key_id, .. } => {
                access_key_id.name().to_owned()
            }
        };
        let name = spec.name.clone().unwrap_or(default_name);

        swaps.push(SecretSwap { name, injection, hosts });
    }
    Ok((SecretInjector::new(swaps).excluding(exceptions), brokers))
}

/// `(host, path)` from a full URL, for the injection exclusion list.
fn host_and_path(url: &str) -> Option<(String, String)> {
    let (endpoint, path) = marshal_http::Endpoint::parse_with_path(url).ok()?;
    Some((endpoint.host, path))
}

/// Everything a secret source might need that is not in its own config: the shared token
/// store, the TLS config and guard for calls marshal makes as itself, and the redactor a
/// runtime-minted credential must teach before it can escape.
struct SecretDeps {
    store: Arc<marshal_secrets::TokenStore>,
    tls: Arc<rustls::ClientConfig>,
    guard: Option<Arc<marshal_http::UpstreamGuard>>,
    redactor: marshal_core::Redactor,
}

impl std::fmt::Debug for SecretDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretDeps").field("store", &self.store).finish_non_exhaustive()
    }
}

/// The PEMs named by `tls.upstream_ca_certs`.
///
/// Read once and used twice: by the MITM engine for proxied traffic, and by the client marshal
/// uses for its own outbound calls. An operator who trusts a CA means both.
fn read_extra_roots(cfg: &marshal_config::model::Config) -> anyhow::Result<Vec<String>> {
    cfg.tls
        .upstream_ca_certs
        .iter()
        .map(|path| {
            let path = expand_tilde(path);
            std::fs::read_to_string(&path).map_err(|e| {
                anyhow::anyhow!("reading tls.upstream_ca_certs entry {}: {e}", path.display())
            })
        })
        .collect()
}

fn secret_deps(
    config_path: &std::path::Path,
    cfg: &marshal_config::model::Config,
    redactor: &marshal_core::Redactor,
) -> anyhow::Result<SecretDeps> {
    let state_dir = cfg.state_dir.as_ref().map(|raw| {
        marshal_config::resolve_dir(
            config_path.parent().unwrap_or_else(|| std::path::Path::new(".")),
            raw,
        )
    });
    Ok(SecretDeps {
        // `global` so a reload does not discard live tokens: reloading is a configuration
        // operation, and re-minting every credential in the process is not one.
        store: marshal_secrets::TokenStore::global(state_dir),
        // The same roots the proxy trusts for upstream traffic. An internal auth server behind
        // a private CA is an ordinary deployment, and "trusted for proxied requests but not for
        // marshal's own" would be a distinction with nothing behind it.
        tls: marshal_http::with_extra_roots(&read_extra_roots(cfg)?)?,
        // The same denylist proxied traffic obeys. A token endpoint URL comes from config and
        // names a third party; one pointing at link-local is an SSRF, not a configuration.
        guard: Some(Arc::new(marshal_http::UpstreamGuard::new(
            &cfg.upstream.deny_cidrs,
            cfg.upstream.allow_private,
        )?)),
        redactor: redactor.clone(),
    })
}

fn build_source(
    spec: &SecretSourceSpec,
    deps: &SecretDeps,
    swap_label: &str,
) -> anyhow::Result<Arc<dyn marshal_core::SecretSource>> {
    Ok(match spec {
        SecretSourceSpec::Env { var } => Arc::new(marshal_secrets::EnvSource::new(var)),
        SecretSourceSpec::File { path, ttl, json_key } => {
            Arc::new(marshal_secrets::FileSource::new(
                expand_tilde(path),
                ttl.unwrap_or(std::time::Duration::from_secs(300)),
                json_key.clone(),
            ))
        }
        SecretSourceSpec::Oauth2(spec) => Arc::new(build_oauth2_source(spec, deps, swap_label)?),
    })
}

fn build_oauth2_source(
    spec: &Oauth2Spec,
    deps: &SecretDeps,
    swap_label: &str,
) -> anyhow::Result<marshal_secrets::Oauth2Source> {
    use marshal_secrets::{ClientAuth, Grant, Oauth2Config};

    let client_secret = |what: &str| -> anyhow::Result<Arc<dyn marshal_core::SecretSource>> {
        let src = spec.client_secret.as_ref().ok_or_else(|| {
            anyhow::anyhow!("source.client_secret is required for `client_auth: {what}`")
        })?;
        build_source(src, deps, swap_label)
    };
    // The signing key both RFC 7523 flows use. Resolved once so `grant: jwt_bearer` with
    // `client_auth: private_key_jwt` — a real combination — does not need two config keys for
    // the same key.
    let assertion_key = |what: &str| -> anyhow::Result<marshal_secrets::AssertionKey> {
        let src = spec
            .private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("source.private_key is required for `{what}`"))?;
        Ok(marshal_secrets::AssertionKey {
            source: build_source(src, deps, swap_label)?,
            algorithm: marshal_secrets::Algorithm::parse(
                spec.algorithm.as_deref().unwrap_or("RS256"),
            )
            .map_err(|e| anyhow::anyhow!("source.algorithm: {e}"))?,
            key_id: spec.key_id.clone(),
            lifetime: spec.assertion_lifetime.unwrap_or(std::time::Duration::from_secs(300)),
        })
    };

    let client_auth = match spec.client_auth {
        ClientAuthSpec::None => ClientAuth::None,
        ClientAuthSpec::PrivateKeyJwt => {
            ClientAuth::PrivateKeyJwt { key: assertion_key("client_auth: private_key_jwt")? }
        }
        ClientAuthSpec::ClientSecretBasic => {
            ClientAuth::ClientSecretBasic { secret: client_secret("client_secret_basic")? }
        }
        ClientAuthSpec::ClientSecretPost => {
            ClientAuth::ClientSecretPost { secret: client_secret("client_secret_post")? }
        }
    };

    let grant = match spec.grant {
        GrantSpec::ClientCredentials => {
            anyhow::ensure!(
                spec.refresh_token.is_none(),
                "source.refresh_token has no effect with `grant: client_credentials`"
            );
            Grant::ClientCredentials
        }
        GrantSpec::RefreshToken => {
            let src = spec.refresh_token.as_ref().ok_or_else(|| {
                anyhow::anyhow!("source.refresh_token is required for `grant: refresh_token`")
            })?;
            Grant::RefreshToken { source: build_source(src, deps, swap_label)? }
        }
        GrantSpec::JwtBearer => {
            // `client_id` is not part of an RFC 7523 §2.1 request at all, so `issuer` is what
            // identifies the caller. Defaulting it to `client_id` keeps the common case to one
            // key without inventing a meaning for the other.
            let issuer = spec.issuer.clone().unwrap_or_else(|| spec.client_id.clone());
            let subject = spec.subject.clone().unwrap_or_else(|| issuer.clone());
            Grant::JwtBearer {
                key: assertion_key("grant: jwt_bearer")?,
                issuer,
                subject,
                audience: spec
                    .assertion_audience
                    .clone()
                    .unwrap_or_else(|| spec.token_endpoint.clone()),
            }
        }
        GrantSpec::AuthorizationCode => {
            anyhow::ensure!(
                spec.authorization_endpoint.is_some(),
                "source.authorization_endpoint is required for `grant: authorization_code`"
            );
            // Not required under `capture: in_band`: there the redirect URI is the agent's,
            // taken from the request marshal is intercepting, and marshal binds nothing. It
            // is still required for `marshal secrets oauth login`, which does bind it — and
            // that command says so itself if it is missing.
            anyhow::ensure!(
                spec.redirect_uri.is_some() || spec.capture == CaptureSpec::InBand,
                "source.redirect_uri is required for `grant: authorization_code`, so that \
                 `marshal secrets oauth login` has a loopback address to receive the code on"
            );
            enrolled_grant(spec, deps)?
        }
        GrantSpec::DeviceCode => {
            anyhow::ensure!(
                spec.device_authorization_endpoint.is_some(),
                "source.device_authorization_endpoint is required for `grant: device_code`"
            );
            enrolled_grant(spec, deps)?
        }
    };

    #[allow(clippy::items_after_statements)]
    fn enrolled_grant(spec: &Oauth2Spec, deps: &SecretDeps) -> anyhow::Result<Grant> {
        // Both are interactive ways of obtaining a refresh token; once one exists, the
        // runtime behaviour is identical, so they share a variant.
        anyhow::ensure!(
            deps.store.persists(),
            "`grant: {}` keeps a refresh token obtained by `marshal secrets oauth login`, \
             which needs a top-level `state_dir` to keep it in",
            spec.grant.label()
        );
        anyhow::ensure!(
            spec.refresh_token.is_none(),
            "source.refresh_token has no effect with `grant: {}` — the refresh token comes \
             from `marshal secrets oauth login`, which keeps it under `state_dir`",
            spec.grant.label()
        );
        Ok(Grant::Enrolled)
    }

    marshal_secrets::Oauth2Source::new(
        swap_label,
        Oauth2Config {
            token_endpoint: spec.token_endpoint.clone(),
            client_id: spec.client_id.clone(),
            client_auth,
            grant,
            scope: spec.scope.clone(),
            audience: spec.audience.clone(),
            extra_params: spec.extra_params.clone(),
            expiry_skew: spec.expiry_skew.unwrap_or(std::time::Duration::from_secs(60)),
            timeout: spec.timeout.unwrap_or(std::time::Duration::from_secs(10)),
            authorization_endpoint: spec.authorization_endpoint.clone(),
            redirect_uri: spec.redirect_uri.clone(),
            device_authorization_endpoint: spec.device_authorization_endpoint.clone(),
        },
        Arc::clone(&deps.store),
        Arc::clone(&deps.tls),
        deps.guard.clone(),
        deps.redactor.clone(),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Build the in-band broker for a swap whose `capture` is `in_band`.
fn build_broker(
    spec: &Oauth2Spec,
    deps: &SecretDeps,
    swap_label: &str,
) -> anyhow::Result<marshal_secrets::Oauth2Broker> {
    anyhow::ensure!(
        matches!(spec.grant, GrantSpec::AuthorizationCode),
        "`capture: in_band` only applies to `grant: authorization_code` — it takes over an \
         authorization flow the agent starts, and the other grants have no such flow. \
         (`grant: {}` here.)",
        spec.grant.label()
    );
    let authorize = spec.authorization_endpoint.as_deref().ok_or_else(|| {
        anyhow::anyhow!("`capture: in_band` needs `source.authorization_endpoint`")
    })?;

    // Capture depends on marshal seeing the *response* — it lifts the code out of a redirect,
    // and answers the token request instead of forwarding it. Both require the connection to
    // be intercepted, which a plain `http://` request through the explicit proxy is not: it is
    // relayed. Refusing here is the difference between a configuration error and a capture
    // that silently never happens.
    for (key, url) in
        [("authorization_endpoint", authorize), ("token_endpoint", &spec.token_endpoint)]
    {
        anyhow::ensure!(
            url.starts_with("https://"),
            "`capture: in_band` needs `source.{key}` to be https — marshal captures the code \
             from the response, which requires the connection to be intercepted, and a plain \
             http request through the proxy is relayed rather than intercepted. \
             (`{url}` here.)"
        );
    }

    let source = Arc::new(build_oauth2_source(spec, deps, swap_label)?);
    marshal_secrets::Oauth2Broker::new(swap_label, source, authorize, &spec.token_endpoint)
        .map_err(|e| anyhow::anyhow!("{e}"))
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
    /// Label used in the audit trail. Defaults to the source's own name (or, for `sigv4`, the
    /// access key id source's name).
    #[serde(default)]
    name: Option<String>,
    /// Required for every `inject.type` except `sigv4`, which carries its own sources.
    #[serde(default)]
    source: Option<SecretSourceSpec>,
    /// What credential to set on every allowed request to `rules` — unconditionally,
    /// replacing whatever the client sent, regardless of whether it sent anything.
    inject: InjectSpec,
    #[serde(default)]
    rules: Vec<HostRule>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum InjectSpec {
    /// `Authorization: Basic base64("{username}:{secret}")` — what git, most package
    /// registries, and container registry logins use.
    Basic { username: String },
    /// `Authorization: Bearer {secret}` — a plain API token.
    Bearer,
    /// `{name}: {secret}` — an arbitrary header set to the raw secret value, for services
    /// that use their own API-key header instead of `Authorization`.
    Header { name: String },
    /// `?{name}={secret}` appended to the request's query string.
    Query { name: String },
    /// AWS Signature Version 4. Needs an access key pair rather than one secret, so it does
    /// not use the swap's top-level `source` — set `access_key_id` and `secret_access_key`
    /// here instead. Forces the request body to buffer (see
    /// [ADR-0028](../docs/adr/0028-sigv4-buffers-the-body.md)); `max_body_bytes` bounds that,
    /// defaulting to 1 MiB.
    Sigv4(Box<Sigv4Spec>),
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Sigv4Spec {
    access_key_id: SecretSourceSpec,
    secret_access_key: SecretSourceSpec,
    #[serde(default)]
    session_token: Option<SecretSourceSpec>,
    region: String,
    service: String,
    #[serde(default)]
    max_body_bytes: Option<usize>,
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
    /// A credential marshal *obtains* from an OAuth2 token endpoint, rather than one it is
    /// given. Composes with any `inject.type` — `bearer` in practice.
    Oauth2(Box<Oauth2Spec>),
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Oauth2Spec {
    /// The full URL, path included — unlike a judge `base_url`, the path is the point.
    token_endpoint: String,
    client_id: String,
    #[serde(default)]
    grant: GrantSpec,
    #[serde(default)]
    client_auth: ClientAuthSpec,
    /// Where the client secret comes from. Itself a source, so it can be an env var, a file,
    /// or a JSON field in one — the same choices every other secret has.
    #[serde(default)]
    client_secret: Option<SecretSourceSpec>,
    /// Required by `grant: refresh_token`, and meaningless for every other grant: the
    /// interactive grants keep their refresh token in marshal's own store instead.
    #[serde(default)]
    refresh_token: Option<SecretSourceSpec>,
    #[serde(default)]
    scope: Vec<String>,
    #[serde(default)]
    audience: Option<String>,
    /// Anything a provider wants that is not in the RFC — `resource`, a tenant id, a vendor
    /// flag. Sent verbatim on every token request.
    #[serde(default)]
    extra_params: std::collections::BTreeMap<String, String>,
    /// Subtracted from the provider's stated lifetime so a token cannot expire in flight.
    /// Defaults to 60s.
    #[serde(default, with = "humantime_serde")]
    expiry_skew: Option<std::time::Duration>,
    /// How long any single call to the provider may take. Defaults to 10s. Minting happens on
    /// the request path, so an unbounded call would hang a proxied request indefinitely.
    #[serde(default, with = "humantime_serde")]
    timeout: Option<std::time::Duration>,
    /// Where `marshal secrets oauth login` sends the browser. `authorization_code` only.
    #[serde(default)]
    authorization_endpoint: Option<String>,
    /// Where the provider sends the browser back. Must be loopback — marshal binds it itself.
    /// `authorization_code` only.
    #[serde(default)]
    redirect_uri: Option<String>,
    /// RFC 8628 device authorization endpoint. `device_code` only.
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
    /// The signing key for `grant: jwt_bearer` and `client_auth: private_key_jwt`. Itself a
    /// source, so a Google service-account JSON file works via
    /// `{ type: file, path: ..., json_key: private_key }` with no special case.
    #[serde(default)]
    private_key: Option<SecretSourceSpec>,
    /// `RS256` (default) or `ES256`.
    #[serde(default)]
    algorithm: Option<String>,
    /// The assertion's `kid` header, for a provider publishing more than one key.
    #[serde(default)]
    key_id: Option<String>,
    /// The assertion's `iss`. `jwt_bearer` only; defaults to `client_id`.
    #[serde(default)]
    issuer: Option<String>,
    /// The assertion's `sub`. `jwt_bearer` only; defaults to `issuer`. Set it to an
    /// impersonated user for Google's domain-wide delegation.
    #[serde(default)]
    subject: Option<String>,
    /// The assertion's `aud`. Defaults to `token_endpoint`, which is what the RFC says and
    /// what almost every provider wants.
    #[serde(default)]
    assertion_audience: Option<String>,
    /// How long an assertion is valid. Defaults to 5m — it is used once, immediately.
    #[serde(default, with = "humantime_serde")]
    assertion_lifetime: Option<std::time::Duration>,
    /// Whether marshal takes over an authorization flow the *agent* starts. `off` by default:
    /// this rewrites requests the agent made and answers requests it sent, which is a much
    /// larger claim on its behaviour than injecting a header.
    #[serde(default)]
    capture: CaptureSpec,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum CaptureSpec {
    #[default]
    Off,
    /// Substitute marshal's PKCE challenge, intercept the redirect, complete the exchange,
    /// and answer the agent's token request locally. See ADR-0032.
    InBand,
}

#[derive(Debug, Default, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum GrantSpec {
    /// Machine-to-machine. No user, no enrolment: the client credential is the identity.
    #[default]
    ClientCredentials,
    /// A long-lived refresh token something outside marshal manages.
    RefreshToken,
    /// Enrolled once by a human at a browser, via `marshal secrets oauth login`.
    AuthorizationCode,
    /// Enrolled once on a headless host, via `marshal secrets oauth login`.
    DeviceCode,
    /// A signed assertion *is* the grant (RFC 7523 §2.1) — Google service accounts,
    /// Salesforce, Snowflake. Needs `private_key`; nothing to enrol and nothing to refresh.
    JwtBearer,
}

impl GrantSpec {
    fn label(self) -> &'static str {
        match self {
            Self::ClientCredentials => "client_credentials",
            Self::RefreshToken => "refresh_token",
            Self::AuthorizationCode => "authorization_code",
            Self::DeviceCode => "device_code",
            Self::JwtBearer => "jwt_bearer",
        }
    }
}

#[derive(Debug, Default, Clone, Copy, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ClientAuthSpec {
    /// `Authorization: Basic base64(client_id:client_secret)` — what RFC 6749 says every
    /// server must support, so the default.
    #[default]
    ClientSecretBasic,
    /// The same credential in the form body. Some providers accept only this.
    ClientSecretPost,
    /// A public client, with no client secret at all.
    None,
    /// A signed assertion instead of a shared secret (RFC 7523 §2.2). Needs `private_key`.
    PrivateKeyJwt,
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

    /// Deps with no state directory and no guard: enough to build any source, and the
    /// oauth2-specific paths that need more say so themselves.
    fn test_deps() -> SecretDeps {
        SecretDeps {
            store: Arc::new(marshal_secrets::TokenStore::new(None)),
            tls: marshal_http::default_tls_config(),
            guard: None,
            redactor: marshal_core::Redactor::default(),
        }
    }

    /// Two profiles, each with its own secret swap for the same host. This is the exact
    /// shape that used to break: `build_runtime` resolved only the fallback profile's
    /// `request_transforms.secrets`, so a non-fallback profile's swap was either silently
    /// never built, or — worse, if both profiles targeted the same host — the fallback
    /// profile's real credential could be injected into an identity that resolved into the
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
  set_headers:
    Accept: application/json
  secrets:
    - name: SECRET_A
      source: {{ type: file, path: "{secret_a}" }}
      inject: {{ type: bearer }}
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
      inject: {{ type: bearer }}
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

        let (runtime, _, injectors) = build_runtime(
            &config,
            Some("profile-a".to_string()),
            &marshal_core::Redactor::default(),
        )
        .expect("config builds");

        // The mechanical bug: request_transforms used to be a flat Vec built from one
        // profile, so it either lacked profile-b's swap entirely, or (worse, when hosts
        // overlapped, as they do here) applied profile-a's real secret to profile-b's
        // identities. Both profiles must now have their own, independent entry.
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
        // appear in a log line regardless of which identity produced it.
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

    #[tokio::test]
    async fn configured_request_header_setters_are_wired_into_the_runtime() {
        let dir = std::env::temp_dir()
            .join(format!("marshal-build-runtime-header-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = write_two_profile_config(&dir);
        let (runtime, _, _) = build_runtime(
            &config,
            Some("profile-a".to_string()),
            &marshal_core::Redactor::default(),
        )
        .expect("config builds");
        let mut request = marshal_core::RequestContext {
            identity: marshal_core::Identity::new("test"),
            profile: Arc::from("profile-a"),
            ingress: marshal_core::IngressMode::Explicit,
            phase: marshal_core::Phase::Request,
            client_addr: "127.0.0.1:1234".parse().unwrap(),
            authority: marshal_core::Authority { host: "api.example.com".into(), port: 443 },
            method: "GET".parse().unwrap(),
            uri: "/".parse().unwrap(),
            headers: Default::default(),
            body: marshal_core::BodyHandle::Empty,
            evidence: marshal_core::Evidence::new(),
        };

        for transform in &runtime.request_transforms["profile-a"] {
            transform.apply(&mut request).await.unwrap();
        }

        assert_eq!(request.headers["accept"], "application/json");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn profile(yaml: &str) -> marshal_config::model::Profile {
        serde_yaml_ng::from_str(yaml).expect("test profile parses")
    }

    #[test]
    fn a_secret_spec_needs_inject() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: X
      source: { type: env, var: X }
      rules: [{ host: "example.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("inject"), "{err}");
    }

    #[test]
    fn an_oauth2_client_credentials_source_builds() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_secret: { type: env, var: SERVICE_CLIENT_SECRET }
        scope: ["read:things"]
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        let injector =
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).unwrap();
        assert!(!injector.is_empty());
    }

    #[test]
    fn an_oauth2_refresh_grant_needs_a_refresh_token_source() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        grant: refresh_token
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_secret: { type: env, var: S }
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("refresh_token"), "{err}");
    }

    #[test]
    fn an_oauth2_source_with_a_secret_bearing_client_auth_needs_a_client_secret() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("client_secret"), "{err}");
    }

    #[test]
    fn a_public_oauth2_client_needs_no_client_secret() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_auth: none
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        assert!(
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).is_ok()
        );
    }

    #[test]
    fn an_interactive_grant_without_a_state_dir_says_what_is_missing() {
        // The refresh token an enrolment produces cannot live anywhere without one, and
        // finding that out at the first request instead of at startup would be much worse.
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        grant: authorization_code
        token_endpoint: https://auth.example.com/oauth2/token
        authorization_endpoint: https://auth.example.com/oauth2/authorize
        redirect_uri: http://127.0.0.1:7777/callback
        client_id: marshal
        client_auth: none
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("state_dir"), "{err}");
    }

    #[test]
    fn an_authorization_code_grant_missing_its_endpoints_names_the_missing_key() {
        for (extra, expected) in [
            ("", "authorization_endpoint"),
            (
                "        authorization_endpoint: https://auth.example.com/authorize\n",
                "redirect_uri",
            ),
        ] {
            let p = profile(&format!(
                r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        grant: authorization_code
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_auth: none
{extra}      inject: {{ type: bearer }}
      rules: [{{ host: "api.example.com" }}]
"#
            ));
            let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
                .unwrap_err();
            assert!(err.to_string().contains(expected), "expected {expected}, got: {err}");
        }
    }

    #[test]
    fn a_device_code_grant_needs_its_device_authorization_endpoint() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        grant: device_code
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_auth: none
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("device_authorization_endpoint"), "{err}");
    }

    #[test]
    fn a_jwt_bearer_source_builds_from_a_service_account_key_file() {
        // The Google shape: the key is a field inside a JSON credentials file, which the
        // existing `file` source already reads.
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: GCP
      source:
        type: oauth2
        grant: jwt_bearer
        token_endpoint: https://oauth2.googleapis.com/token
        client_id: svc@project.iam.gserviceaccount.com
        client_auth: none
        private_key: { type: file, path: /etc/bot-marshal/sa.json, json_key: private_key }
        scope: ["https://www.googleapis.com/auth/cloud-platform"]
      inject: { type: bearer }
      rules: [{ host: "*.googleapis.com" }]
"#,
        );
        let injector =
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).unwrap();
        assert!(!injector.is_empty());
    }

    #[test]
    fn jwt_bearer_without_a_private_key_says_which_key_is_missing() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: GCP
      source:
        type: oauth2
        grant: jwt_bearer
        token_endpoint: https://oauth2.googleapis.com/token
        client_id: svc@project.iam.gserviceaccount.com
        client_auth: none
      inject: { type: bearer }
      rules: [{ host: "*.googleapis.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("private_key"), "{err}");
    }

    #[test]
    fn private_key_jwt_client_auth_composes_with_client_credentials() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_auth: private_key_jwt
        private_key: { type: file, path: /etc/bot-marshal/client.pem }
        algorithm: ES256
        key_id: "2026-09"
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        assert!(
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).is_ok()
        );
    }

    #[test]
    fn an_unsupported_jwt_algorithm_is_named_in_the_error() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        token_endpoint: https://auth.example.com/oauth2/token
        client_id: marshal
        client_auth: private_key_jwt
        private_key: { type: env, var: KEY }
        algorithm: HS256
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("HS256"), "{err}");
    }

    #[test]
    fn capture_in_band_yaml_actually_produces_a_broker() {
        // The integration tests build brokers by hand, so nothing else checks that the config
        // key reaches the runtime. Without this, `capture: in_band` could silently become a
        // no-op and every capture test would still pass.
        let yaml = |capture: &str| {
            format!(
                r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        grant: authorization_code
        token_endpoint: https://auth.example.com/oauth2/token
        authorization_endpoint: https://auth.example.com/oauth2/authorize
        client_id: marshal
        client_auth: none
{capture}      inject: {{ type: bearer }}
      rules: [{{ host: "api.example.com" }}]
"#
            )
        };
        let deps = SecretDeps {
            store: Arc::new(marshal_secrets::TokenStore::new(Some(std::env::temp_dir()))),
            tls: marshal_http::default_tls_config(),
            guard: None,
            redactor: marshal_core::Redactor::default(),
        };
        let cfg = marshal_config::model::Config::default();

        let (_, brokers) =
            build_secrets(&profile(&yaml("        capture: in_band\n")), &cfg, &deps).unwrap();
        assert_eq!(brokers.len(), 1, "`capture: in_band` should register one broker");

        // And the default really is off, rather than everything quietly getting a broker.
        // Without capture the grant needs a redirect_uri, since enrolment binds it.
        let off = yaml("        redirect_uri: http://127.0.0.1:7777/cb\n");
        let (_, none) = build_secrets(&profile(&off), &cfg, &deps).unwrap();
        assert!(none.is_empty(), "capture defaults to off");
    }

    #[test]
    fn an_oauth2_swap_never_injects_into_its_own_endpoints() {
        // The circularity guard, checked at the level the config actually configures.
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: SERVICE
      source:
        type: oauth2
        token_endpoint: https://api.example.com/oauth2/token
        client_id: marshal
        client_auth: none
      inject: { type: bearer }
      rules: [{ host: "api.example.com" }]
"#,
        );
        let (injector, _) =
            build_secrets(&p, &marshal_config::model::Config::default(), &test_deps()).unwrap();
        // The swap's own token endpoint shares the API's host, which is the case that bites.
        assert!(
            format!("{injector:?}").contains("api.example.com"),
            "the token endpoint should be excluded from injection: {injector:?}"
        );
    }

    #[test]
    fn an_unknown_source_type_is_refused_rather_than_ignored() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: X
      source: { type: vault, path: secret/x }
      inject: { type: bearer }
      rules: [{ host: "example.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("vault"), "{err}");
    }

    #[test]
    fn a_basic_inject_swap_builds() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: X
      source: { type: env, var: X }
      inject: { type: basic, username: "x-access-token" }
      rules: [{ host: "example.com" }]
"#,
        );
        let injector =
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).unwrap();
        assert!(!injector.is_empty());
    }

    #[test]
    fn a_bearer_inject_swap_builds() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: X
      source: { type: env, var: X }
      inject: { type: bearer }
      rules: [{ host: "example.com" }]
"#,
        );
        let injector =
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).unwrap();
        assert!(!injector.is_empty());
    }

    #[test]
    fn a_header_inject_swap_builds() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: X
      source: { type: env, var: X }
      inject: { type: header, name: "X-Api-Key" }
      rules: [{ host: "example.com" }]
"#,
        );
        let injector =
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).unwrap();
        assert!(!injector.is_empty());
    }

    #[test]
    fn a_header_inject_swap_rejects_an_invalid_header_name() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: X
      source: { type: env, var: X }
      inject: { type: header, name: "not a valid header" }
      rules: [{ host: "example.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("invalid header name"), "{err}");
    }

    #[test]
    fn a_query_inject_swap_builds() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: X
      source: { type: env, var: X }
      inject: { type: query, name: "api_key" }
      rules: [{ host: "example.com" }]
"#,
        );
        let injector =
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).unwrap();
        assert!(!injector.is_empty());
    }

    #[test]
    fn a_sigv4_inject_swap_builds_with_its_own_two_sources() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: AWS_S3
      inject:
        type: sigv4
        access_key_id: { type: env, var: AWS_ACCESS_KEY_ID }
        secret_access_key: { type: env, var: AWS_SECRET_ACCESS_KEY }
        region: us-east-1
        service: s3
      rules: [{ host: "*.s3.amazonaws.com" }]
"#,
        );
        let injector =
            build_injector(&p, &marshal_config::model::Config::default(), &test_deps()).unwrap();
        assert!(!injector.is_empty());
    }

    #[test]
    fn a_sigv4_inject_swap_rejects_a_top_level_source() {
        let p = profile(
            r#"
default_action: deny
request_transforms:
  secrets:
    - name: AWS_S3
      source: { type: env, var: AWS_SECRET_ACCESS_KEY }
      inject:
        type: sigv4
        access_key_id: { type: env, var: AWS_ACCESS_KEY_ID }
        secret_access_key: { type: env, var: AWS_SECRET_ACCESS_KEY }
        region: us-east-1
        service: s3
      rules: [{ host: "*.s3.amazonaws.com" }]
"#,
        );
        let err = build_injector(&p, &marshal_config::model::Config::default(), &test_deps())
            .unwrap_err();
        assert!(err.to_string().contains("no effect"), "{err}");
    }
}
