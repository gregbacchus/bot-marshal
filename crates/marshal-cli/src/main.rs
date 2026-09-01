//! `marshal` — the bot-marshal command line.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use marshal_config::{Severity, validate};

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
