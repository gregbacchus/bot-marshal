//! `marshal run`: launching an agent so the proxy can identify it.
//!
//! The mechanisms in `marshal-proxy::sessions` are useless if using one means assembling a
//! cgroup scope or a network namespace by hand. This turns that into a single command.
//!
//! Isolation modes, strongest first:
//!
//! * `cgroup` — a transient systemd scope per agent. The cgroup path is kernel-supplied and,
//!   crucially, **inherited by every child**: a coding agent's egress is mostly from spawned
//!   `git`, `npm` and `curl`, not the agent process. Strong against a prompt-injected agent;
//!   not against one deliberately impersonating another profile, since a process can move
//!   itself between delegated cgroups.
//! * `none` — environment variables only. Zero setup, and honestly labelled: identity comes
//!   from a credential the agent holds, so an agent that can read another one can choose
//!   another profile.
//!
//! A `netns` mode is deliberately absent rather than half-implemented. It is the only option
//! that *enforces* rather than identifies — the agent has no route to the internet except the
//! proxy — but doing it unprivileged needs a forwarder inside the namespace to reach the
//! proxy, which is real work rather than a flag. Offering a `netns` that silently degraded to
//! something weaker would be worse than not offering it.

use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Transient systemd scope; identity by cgroup, inherited by children.
    Cgroup,
    /// Environment variables only; identity by proxy credential.
    None,
}

impl std::str::FromStr for Isolation {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "cgroup" => Ok(Isolation::Cgroup),
            "none" => Ok(Isolation::None),
            "netns" => {
                Err("netns isolation is not implemented. It is the only mode that prevents \
                 bypass rather than merely identifying traffic, and doing it unprivileged \
                 needs a forwarder inside the namespace — shipping a `netns` flag that \
                 quietly did something weaker would be worse than not having one. Use \
                 `--isolation cgroup`, or run the agent in a container with its own address \
                 and a `source_ip` resolver."
                    .to_string())
            }
            other => Err(format!("unknown isolation mode `{other}`; expected cgroup or none")),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("no command given")]
    NoCommand,

    #[error("systemd-run is not available, which `--isolation cgroup` needs: {0}")]
    NoSystemdRun(#[source] std::io::Error),

    #[error("launching {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },
}

/// How the agent should be told to reach the proxy.
#[derive(Debug, Clone)]
pub struct ProxyEndpoint {
    /// e.g. `http://127.0.0.1:8080`.
    pub url: String,
    /// Path to the CA certificate, so the agent's tools accept intercepted connections.
    pub ca_cert: Option<PathBuf>,
    /// Credential embedded in the proxy URL, for `none` isolation.
    pub credential: Option<(String, String)>,
}

/// Build the scope name the `launched` resolver reads identity back out of.
///
/// The naming convention *is* the registration: no control socket, and nothing to get out of
/// sync if the proxy restarts.
pub fn scope_name(profile: &str, id: u32) -> String {
    format!("marshal-{profile}-{id}.scope")
}

/// Environment an agent needs to route through the proxy and trust its CA.
///
/// Every runtime is listed because they consult different trust stores: an agent shelling out
/// to git, npm, pip and curl uses four, and setting only one leaves three failing in ways
/// that look unrelated to the proxy.
pub fn proxy_env(endpoint: &ProxyEndpoint) -> Vec<(String, String)> {
    let url = match &endpoint.credential {
        Some((user, pass)) => {
            let (scheme, rest) = endpoint.url.split_once("://").unwrap_or(("http", &endpoint.url));
            format!("{scheme}://{user}:{pass}@{rest}")
        }
        None => endpoint.url.clone(),
    };

    let mut env = vec![
        ("HTTP_PROXY".to_string(), url.clone()),
        ("HTTPS_PROXY".to_string(), url.clone()),
        ("http_proxy".to_string(), url.clone()),
        ("https_proxy".to_string(), url.clone()),
        ("ALL_PROXY".to_string(), url),
        // Loopback is excluded from proxying by default, or an agent talking to its own
        // local services would be routed through the boundary for no reason.
        ("NO_PROXY".to_string(), "localhost,127.0.0.1,::1".to_string()),
    ];

    if let Some(ca) = &endpoint.ca_cert {
        let ca = ca.display().to_string();
        for var in [
            "SSL_CERT_FILE",
            "REQUESTS_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
            "GIT_SSL_CAINFO",
            "CARGO_HTTP_CAINFO",
            "CURL_CA_BUNDLE",
        ] {
            env.push((var.to_string(), ca.clone()));
        }
    }
    env
}

/// Build the command that launches `argv` under the requested isolation.
///
/// Returned rather than executed so the caller can print it, and so this is testable without
/// spawning anything.
pub fn build_command(
    isolation: Isolation,
    profile: &str,
    id: u32,
    endpoint: &ProxyEndpoint,
    argv: &[String],
) -> Result<Command, LaunchError> {
    let (program, args) = argv.split_first().ok_or(LaunchError::NoCommand)?;
    let env = proxy_env(endpoint);

    let mut cmd = match isolation {
        Isolation::None => {
            let mut c = Command::new(program);
            c.args(args);
            c
        }
        Isolation::Cgroup => {
            let mut c = Command::new("systemd-run");
            c.arg("--user")
                .arg("--scope")
                .arg("--quiet")
                // Collect the scope when the process exits, so a long-running proxy does not
                // accumulate one dead unit per agent invocation.
                .arg("--collect")
                .arg(format!("--unit={}", scope_name(profile, id)));
            // systemd-run does not inherit the caller's environment into the scope.
            for (k, v) in &env {
                c.arg(format!("--setenv={k}={v}"));
            }
            c.arg("--").arg(program).args(args);
            c
        }
    };

    for (k, v) in env {
        cmd.env(k, v);
    }
    Ok(cmd)
}

/// Whether `systemd-run --user` is usable here.
pub fn systemd_available() -> bool {
    Command::new("systemd-run")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> ProxyEndpoint {
        ProxyEndpoint {
            url: "http://127.0.0.1:8080".into(),
            ca_cert: Some(PathBuf::from("/tmp/ca.crt")),
            credential: None,
        }
    }

    #[test]
    fn scope_names_round_trip_through_the_resolver() {
        let name = scope_name("coding-agent", 4821);
        assert_eq!(name, "marshal-coding-agent-4821.scope");
        // The launcher and the resolver must agree, or identity silently stops working.
        let (profile, session) =
            marshal_proxy::sessions::launched::parse_scope(&format!("0::/user.slice/{name}"))
                .unwrap();
        assert_eq!(profile, "coding-agent");
        assert_eq!(session, "coding-agent-4821");
    }

    #[test]
    fn env_covers_the_runtimes_that_ignore_the_os_trust_store() {
        let env: std::collections::HashMap<_, _> = proxy_env(&endpoint()).into_iter().collect();
        assert_eq!(env["HTTPS_PROXY"], "http://127.0.0.1:8080");
        // Lower-case variants matter: curl and many tools only read those.
        assert_eq!(env["https_proxy"], "http://127.0.0.1:8080");
        for var in ["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO"] {
            assert_eq!(env[var], "/tmp/ca.crt", "missing {var}");
        }
        assert!(env["NO_PROXY"].contains("127.0.0.1"));
    }

    #[test]
    fn credentials_are_embedded_in_the_proxy_url() {
        let mut e = endpoint();
        e.credential = Some(("agent-a".into(), "hunter2".into()));
        let env: std::collections::HashMap<_, _> = proxy_env(&e).into_iter().collect();
        assert_eq!(env["HTTPS_PROXY"], "http://agent-a:hunter2@127.0.0.1:8080");
    }

    #[test]
    fn cgroup_mode_names_the_scope_and_forwards_the_environment() {
        let cmd = build_command(
            Isolation::Cgroup,
            "coding-agent",
            7,
            &endpoint(),
            &["claude".to_string(), "--help".to_string()],
        )
        .unwrap();

        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        assert!(args.contains(&"--unit=marshal-coding-agent-7.scope".to_string()), "{args:?}");
        // systemd-run does not inherit the caller's environment, so it must be passed through.
        assert!(args.iter().any(|a| a.starts_with("--setenv=HTTPS_PROXY=")), "{args:?}");
        assert!(args.contains(&"claude".to_string()));
        assert!(args.contains(&"--help".to_string()));
    }

    #[test]
    fn netns_is_refused_with_an_explanation_rather_than_degraded() {
        let err = "netns".parse::<Isolation>().unwrap_err();
        assert!(err.contains("not implemented"), "{err}");
        assert!(err.contains("cgroup"), "the error must name a working alternative: {err}");
    }

    #[test]
    fn an_empty_command_is_an_error() {
        assert!(matches!(
            build_command(Isolation::None, "p", 1, &endpoint(), &[]),
            Err(LaunchError::NoCommand)
        ));
    }
}
