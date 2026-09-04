//! `marshal run`: launching an agent so the proxy can identify it.
//!
//! The mechanisms in `marshal-proxy::identity` are useless if using one means assembling a
//! cgroup scope or a network namespace by hand. This turns that into a single command.
//!
//! Isolation modes, strongest first:
//!
//! * `netns` — a network namespace with no route out except the proxy, wrapped in a cgroup
//!   scope for identity. The only mode that **enforces** rather than identifies: every other
//!   mode labels traffic that could still route around the proxy. See [`sandbox`].
//! * `cgroup` — a transient systemd scope per agent. The cgroup path is kernel-supplied and,
//!   crucially, **inherited by every child**: a coding agent's egress is mostly from spawned
//!   `git`, `npm` and `curl`, not the agent process. Strong against a prompt-injected agent;
//!   not against one deliberately impersonating another profile, since a process can move
//!   itself between delegated cgroups.
//! * `none` — environment variables only. Zero setup, and honestly labelled: identity comes
//!   from a credential the agent holds, so an agent that can read another one can choose
//!   another profile.

use std::path::PathBuf;
use std::process::Command;

pub mod sandbox;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Network namespace with no route out except the proxy's Unix socket, inside a cgroup
    /// scope for identity. Enforces rather than identifies.
    Netns,
    /// Transient systemd scope; identity by cgroup, inherited by children.
    Cgroup,
    /// Environment variables only; identity by proxy credential.
    None,
}

impl std::str::FromStr for Isolation {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "netns" => Ok(Isolation::Netns),
            "cgroup" => Ok(Isolation::Cgroup),
            "none" => Ok(Isolation::None),
            other => {
                Err(format!("unknown isolation mode `{other}`; expected netns, cgroup or none"))
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LaunchError {
    #[error("no command given")]
    NoCommand,

    #[error("systemd-run is not available, which `--isolation cgroup` needs: {0}")]
    NoSystemdRun(#[source] std::io::Error),

    #[error("cannot determine the path to this executable, which netns isolation re-invokes: {0}")]
    NoSelfExe(#[source] std::io::Error),

    #[error("{0}")]
    Sandbox(String),

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
/// sync if the proxy restarts. `profile: None` (no `--profile`) omits the profile segment
/// entirely, producing a shape (`marshal-<id>.scope`) `parse_scope` does not recognise — the
/// same "no opinion" outcome as a cgroup naming nothing marshal-related at all, so the
/// connection falls through to the ordinary unattributed path and gets the embedded `profile:`
/// exactly as unattributed traffic already does. No sentinel, no reserved name.
pub fn scope_name(profile: Option<&str>, id: u32) -> String {
    match profile {
        Some(profile) => format!("marshal-{profile}-{id}.scope"),
        None => format!("marshal-{id}.scope"),
    }
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
    profile: Option<&str>,
    id: u32,
    endpoint: &ProxyEndpoint,
    argv: &[String],
) -> Result<Command, LaunchError> {
    build_command_with(isolation, profile, id, endpoint, argv, None, &[])
}

/// As [`build_command`], with the Unix socket that netns isolation forwards to and any extra
/// paths (`extra_binds`) the caller wants bound read-write inside the namespace — outside the
/// workspace and the fixed system paths, ignored by every isolation mode but `netns`.
pub fn build_command_with(
    isolation: Isolation,
    profile: Option<&str>,
    id: u32,
    endpoint: &ProxyEndpoint,
    argv: &[String],
    unix_socket: Option<&std::path::Path>,
    extra_binds: &[PathBuf],
) -> Result<Command, LaunchError> {
    let (program, args) = argv.split_first().ok_or(LaunchError::NoCommand)?;
    let env = proxy_env(endpoint);

    if isolation == Isolation::Netns {
        return build_netns_command(profile, id, endpoint, argv, unix_socket, extra_binds);
    }

    let mut cmd = match isolation {
        Isolation::Netns => unreachable!("handled above"),
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

/// Read-only system directories bound into the namespace verbatim, via `--ro-bind-try` so a
/// merged-`/usr` system (where several of these are a symlink into `/usr`, or simply do not
/// exist as their own directory) does not turn a missing one into a hard launch failure —
/// binding `/usr` alone already covers what a missing one would have added.
const READONLY_SYSTEM_DIRS: &[&str] = &["/usr", "/etc", "/bin", "/sbin", "/lib", "/lib64"];

/// `systemd-run --user --scope --unit=… -- bwrap --unshare-net -- marshal sandbox -- <agent>`
///
/// The scope supplies identity (the `launched` resolver reads the profile back out of the
/// cgroup name); `bwrap` supplies the empty network namespace; `marshal sandbox` supplies the
/// only way out of it.
///
/// Only the network is unshared, but the filesystem is no longer `--dev-bind / /` — binding
/// the whole host root put every other Unix socket reachable from this user in scope too
/// (Docker's, Podman's, anything else listening under `/run` or `/var/run`), which let an
/// agent reach host-level control planes the network namespace was supposed to remove it
/// from entirely. What is bound instead, and nothing else:
///
/// * the workspace (the directory `marshal run` was invoked from), read-write — the agent
///   needs to do its actual work;
/// * `READONLY_SYSTEM_DIRS`, read-only — the standard binaries and libraries any agent needs
///   to run at all;
/// * the CA certificate, read-only, bound as a single file — never its containing directory,
///   which on the default config layout also holds the CA *private key*, and that must never
///   be readable from inside the sandbox;
/// * the marshal Unix socket, read-write, as a single file — the only route out;
/// * `extra_binds`, read-write — the documented, explicit opt-in for anything else a
///   particular agent genuinely needs (a package manager cache outside the workspace, for
///   instance), rather than reopening the whole filesystem to get it.
///
/// `/proc` is bwrap's own mount, so `/proc/net` reflects the namespace the agent is actually
/// in rather than the host's. `/dev` and `/tmp` are bwrap's own synthetic, empty ones —
/// `/dev` because devices are not filesystem access this proxy has any opinion on, `/tmp`
/// because the host's real one may hold other processes' sockets exactly like `/run` does.
fn build_netns_command(
    profile: Option<&str>,
    id: u32,
    endpoint: &ProxyEndpoint,
    argv: &[String],
    unix_socket: Option<&std::path::Path>,
    extra_binds: &[PathBuf],
) -> Result<Command, LaunchError> {
    let socket = unix_socket.ok_or_else(|| {
        LaunchError::Sandbox(
            "netns isolation reaches the proxy through a Unix socket, so \
             `listeners.explicit.unix_socket` must be set in the config"
                .into(),
        )
    })?;
    sandbox::check_socket_path(socket).map_err(LaunchError::Sandbox)?;

    let self_exe = std::env::current_exe().map_err(LaunchError::NoSelfExe)?;
    let workspace = std::env::current_dir().map_err(|e| {
        LaunchError::Sandbox(format!("determining the current directory to bind: {e}"))
    })?;

    let mut cmd = Command::new("systemd-run");
    cmd.arg("--user")
        .arg("--scope")
        .arg("--quiet")
        .arg("--collect")
        .arg(format!("--unit={}", scope_name(profile, id)))
        .arg("--")
        .arg("bwrap")
        .arg("--dev")
        .arg("/dev")
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--proc")
        .arg("/proc")
        .arg("--bind")
        .arg(&workspace)
        .arg(&workspace);

    for dir in READONLY_SYSTEM_DIRS {
        cmd.arg("--ro-bind-try").arg(dir).arg(dir);
    }

    // `marshal sandbox` re-execs this same binary *inside* the namespace, so it must be
    // reachable there too. A system install under `/usr` is already covered by the loop
    // above; this exists for the equally normal case of running a locally built binary from
    // an arbitrary path, which is not.
    cmd.arg("--ro-bind-try").arg(&self_exe).arg(&self_exe);

    if let Some(ca) = &endpoint.ca_cert {
        cmd.arg("--ro-bind").arg(ca).arg(ca);
    }

    for extra in extra_binds {
        cmd.arg("--bind").arg(extra).arg(extra);
    }

    cmd.arg("--bind")
        .arg(socket)
        .arg(socket)
        .arg("--unshare-net")
        .arg("--")
        .arg(self_exe)
        .arg("sandbox")
        .arg("--socket")
        .arg(socket)
        .arg("--listen")
        // Inside its own namespace, so this cannot collide with anything on the host.
        .arg(SANDBOX_LISTEN);

    if let Some(ca) = &endpoint.ca_cert {
        cmd.arg("--ca").arg(ca);
    }

    cmd.arg("--").args(argv);
    Ok(cmd)
}

/// Where the in-namespace forwarder listens. Fixed rather than configurable because the
/// namespace is empty: nothing else can be using it.
pub const SANDBOX_LISTEN: &str = "127.0.0.1:8080";

/// Whether `bwrap` is available, which netns isolation needs.
pub fn bwrap_available() -> bool {
    Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Whether `bwrap` can actually create a network namespace here.
///
/// Distinct from `bwrap_available`: unprivileged user namespaces can be disabled by policy,
/// and finding that out at launch time gives a far better message than the agent silently
/// having no network.
pub fn netns_available() -> bool {
    // `/usr`, `/lib` and `/lib64` are bound read-only purely so there is a `true` binary and
    // a dynamic linker to exec at all — this is a capability probe for `--unshare-net`, not a
    // rehearsal of the real launch's bind list, so it deliberately stays minimal rather than
    // tracking `READONLY_SYSTEM_DIRS`. `-try` tolerates whichever of `/lib`/`/lib64` this
    // system does not have as a real directory.
    Command::new("bwrap")
        .args([
            "--dev",
            "/dev",
            "--unshare-net",
            "--ro-bind-try",
            "/usr",
            "/usr",
            "--ro-bind-try",
            "/lib",
            "/lib",
            "--ro-bind-try",
            "/lib64",
            "/lib64",
            "--",
            "/usr/bin/true",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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
        let name = scope_name(Some("coding-agent"), 4821);
        assert_eq!(name, "marshal-coding-agent-4821.scope");
        // The launcher and the resolver must agree, or identity silently stops working.
        let (profile, identity) =
            marshal_proxy::identity::launched::parse_scope(&format!("0::/user.slice/{name}"))
                .unwrap();
        assert_eq!(profile, "coding-agent");
        assert_eq!(identity, "coding-agent-4821");
    }

    #[test]
    fn no_profile_names_a_scope_the_resolver_does_not_recognise() {
        // `marshal run` with no `--profile` must not register any identity — the connection
        // is meant to fall through to the same unattributed/default path `marshal serve`
        // already uses, not conjure up a magic name that means "default".
        let name = scope_name(None, 4821);
        assert_eq!(name, "marshal-4821.scope");
        assert!(
            marshal_proxy::identity::launched::parse_scope(&format!("0::/user.slice/{name}"))
                .is_none()
        );
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
            Some("coding-agent"),
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
    fn netns_builds_a_scoped_sandbox_that_reaches_the_unix_socket() {
        let sock = std::path::PathBuf::from(format!("/tmp/mnb-{}.sock", std::process::id()));
        std::fs::write(&sock, b"").unwrap();

        let cmd = build_command_with(
            Isolation::Netns,
            Some("coding-agent"),
            7,
            &endpoint(),
            &["claude".to_string()],
            Some(&sock),
            &[],
        )
        .unwrap();

        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();

        // The scope gives identity, bwrap gives the empty namespace, and the sandbox
        // subcommand gives the only way out of it. All three must be present.
        assert!(args.contains(&"--unit=marshal-coding-agent-7.scope".to_string()), "{args:?}");
        assert!(args.contains(&"--unshare-net".to_string()), "{args:?}");
        assert!(args.contains(&"sandbox".to_string()), "{args:?}");
        assert!(args.contains(&sock.to_string_lossy().into_owned()), "{args:?}");
        assert!(args.contains(&"claude".to_string()), "{args:?}");

        // /proc must be remounted, or /proc/net inside shows the host's network.
        assert!(args.contains(&"--proc".to_string()), "{args:?}");

        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn netns_no_longer_binds_the_whole_host_root() {
        // The finding this fixes: `--dev-bind / /` put every Unix socket reachable from this
        // user in scope — Docker's, Podman's, anything else under `/run` — which let an agent
        // reach host-level control planes the namespace was supposed to remove it from.
        let sock = std::path::PathBuf::from(format!("/tmp/mnb-noroot-{}.sock", std::process::id()));
        std::fs::write(&sock, b"").unwrap();

        let cmd = build_command_with(
            Isolation::Netns,
            Some("p"),
            1,
            &endpoint(),
            &["true".to_string()],
            Some(&sock),
            &[],
        )
        .unwrap();

        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();

        assert!(!args.contains(&"--dev-bind".to_string()), "{args:?}");
        assert!(!args.contains(&"/run".to_string()), "{args:?}");
        assert!(!args.contains(&"/var/run".to_string()), "{args:?}");
        // The real host /tmp is not bound either — bwrap's own private, empty one is used
        // instead, via `--tmpfs`, so another process's socket living there is unreachable too.
        assert!(args.contains(&"--tmpfs".to_string()), "{args:?}");
        assert!(!args.windows(2).any(|w| w[0] == "--bind" && w[1] == "/tmp"), "{args:?}");

        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn netns_binds_the_workspace_and_the_ca_cert_as_a_single_file() {
        let sock = std::path::PathBuf::from(format!("/tmp/mnb-ws-{}.sock", std::process::id()));
        std::fs::write(&sock, b"").unwrap();

        let cmd = build_command_with(
            Isolation::Netns,
            Some("p"),
            1,
            &endpoint(),
            &["true".to_string()],
            Some(&sock),
            &[],
        )
        .unwrap();

        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        let cwd = std::env::current_dir().unwrap().to_string_lossy().into_owned();

        assert!(
            args.windows(3).any(|w| w[0] == "--bind" && w[1] == cwd && w[2] == cwd),
            "workspace must be bound read-write: {args:?}"
        );
        // The CA cert is bound by exact file path, read-only — never its parent directory,
        // which on the default config layout also holds the CA private key.
        let ca = endpoint().ca_cert.unwrap().to_string_lossy().into_owned();
        assert!(
            args.windows(3).any(|w| w[0] == "--ro-bind" && w[1] == ca && w[2] == ca),
            "CA cert must be bound read-only by file path: {args:?}"
        );
        assert!(!args.contains(&"/etc/bot-marshal".to_string()), "{args:?}");

        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn netns_includes_extra_binds_read_write() {
        let sock = std::path::PathBuf::from(format!("/tmp/mnb-extra-{}.sock", std::process::id()));
        std::fs::write(&sock, b"").unwrap();
        let extra = std::path::PathBuf::from("/opt/cache");

        let cmd = build_command_with(
            Isolation::Netns,
            Some("p"),
            1,
            &endpoint(),
            &["true".to_string()],
            Some(&sock),
            std::slice::from_ref(&extra),
        )
        .unwrap();

        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        let extra = extra.to_string_lossy().into_owned();
        assert!(
            args.windows(3).any(|w| w[0] == "--bind" && w[1] == extra && w[2] == extra),
            "{args:?}"
        );

        let _ = std::fs::remove_file(&sock);
    }

    #[test]
    fn netns_without_a_unix_socket_is_refused_with_the_reason() {
        let err = build_command_with(
            Isolation::Netns,
            Some("p"),
            1,
            &endpoint(),
            &["true".to_string()],
            None,
            &[],
        )
        .unwrap_err();
        assert!(err.to_string().contains("unix_socket"), "{err}");
    }

    #[test]
    fn netns_parses_as_an_isolation_mode() {
        assert_eq!("netns".parse::<Isolation>().unwrap(), Isolation::Netns);
        assert!("bogus".parse::<Isolation>().is_err());
    }

    #[test]
    fn an_empty_command_is_an_error() {
        assert!(matches!(
            build_command(Isolation::None, Some("p"), 1, &endpoint(), &[]),
            Err(LaunchError::NoCommand)
        ));
    }
}
