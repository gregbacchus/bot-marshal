//! `marshal` — the bot-marshal command line.

use std::path::PathBuf;
use std::process::ExitCode;

use std::sync::Arc;

use clap::{Parser, Subcommand};
use marshal_audit::{JsonSink, MultiSink, TracingSink};
use marshal_config::{Severity, validate};
use marshal_core::{AuditSink, DenyingDecider};
use marshal_policy::build_chain;
use marshal_proxy::{Server, ServerConfig, UpstreamGuard};

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

    /// Run the proxy.
    Serve {
        /// Profile to enforce. Session-based profile selection arrives in M4; until then one
        /// profile applies to every connection.
        #[arg(long, default_value = "base")]
        profile: String,

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
        Command::Serve { profile, listen, audit_log } => {
            let rt = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    eprintln!("error: cannot start the async runtime: {e}");
                    return ExitCode::FAILURE;
                }
            };
            match rt.block_on(serve(&cli.config, &profile, listen, audit_log)) {
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
    profile: &str,
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

    let chain = build_chain(&cfg, profile, Arc::new(DenyingDecider))?;
    let guard = UpstreamGuard::new(&cfg.upstream.deny_cidrs, cfg.upstream.allow_private)?;

    let json: Arc<dyn AuditSink> = match &audit_log {
        Some(path) => {
            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
                .map_err(|e| anyhow::anyhow!("opening audit log {}: {e}", path.display()))?;
            Arc::new(JsonSink::new(file))
        }
        None => JsonSink::stdout(),
    };
    let audit: Arc<dyn AuditSink> = Arc::new(MultiSink::new(vec![json, Arc::new(TracingSink)]));

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

    let listen = listen
        .or_else(|| cfg.listeners.explicit.as_ref().map(|e| e.listen.clone()))
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned());

    let server = Server::new(
        ServerConfig { listen, profile: Arc::from(profile), tls, passthrough },
        Arc::new(chain),
        Arc::new(guard),
        audit,
    );

    tokio::select! {
        r = server.run(|_| {}) => r.map_err(Into::into),
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
            Ok(())
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
        eprintln!("\n{} error(s), {warnings} warning(s)", errors);
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
