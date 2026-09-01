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

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(&cli.log);

    match cli.command {
        Command::Config(ConfigCommand::Check) => config_check(&cli.config),
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

    let listen = listen
        .or_else(|| cfg.listeners.explicit.as_ref().map(|e| e.listen.clone()))
        .unwrap_or_else(|| "127.0.0.1:8080".to_owned());

    let server = Server::new(
        ServerConfig { listen, profile: Arc::from(profile) },
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
