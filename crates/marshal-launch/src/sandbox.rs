//! The half of `--isolation netns` that runs *inside* the network namespace.
//!
//! # Why a forwarder is needed at all
//!
//! An unprivileged network namespace has loopback and nothing else. Giving it real
//! connectivity normally means a veth pair (needs `CAP_NET_ADMIN` in the host namespace) or a
//! userspace stack like slirp4netns (an extra dependency). Neither is necessary here, because
//! the agent does not need *network* access to the proxy — it needs *an* access path, and a
//! Unix socket is a filesystem object rather than a network one, so it crosses the namespace
//! boundary untouched.
//!
//! So: the proxy listens on a Unix socket on the host; this process, inside the namespace,
//! listens on loopback and relays each connection to that socket. The agent points its
//! `HTTP_PROXY` at loopback and never knows the difference.
//!
//! # What this buys over cgroup isolation
//!
//! Enforcement rather than identification. Every other mode identifies traffic that could
//! still route around the proxy; here there is no route to route around it with. Two
//! consequences worth stating plainly:
//!
//! * DNS is gone too. The agent cannot resolve anything, so a hostname is only ever
//!   resolved by the proxy after policy has run — which closes DNS-based exfiltration, a
//!   channel destination filtering never sees.
//! * A tool that ignores proxy environment variables gets no network at all. Under cgroup
//!   isolation the same tool would silently bypass the proxy. Failing closed is the point,
//!   but it does mean netns mode surfaces badly-behaved tooling as a hard failure.
//!
//! Only the network is isolated. The filesystem is passed through, because the agent needs
//! its workspace and this is an egress firewall rather than a sandbox.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Longest `sun_path` the kernel accepts, including the terminating NUL.
pub const UNIX_PATH_MAX: usize = 108;

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("binding the in-namespace listener on {listen}: {source}")]
    Bind {
        listen: SocketAddr,
        #[source]
        source: std::io::Error,
    },

    #[error("launching {program}: {source}")]
    Spawn {
        program: String,
        #[source]
        source: std::io::Error,
    },

    #[error("no command given")]
    NoCommand,
}

#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// The proxy's Unix socket, as seen from inside the namespace.
    pub socket: PathBuf,
    /// Where the forwarder listens. Inside its own namespace, so it cannot collide with
    /// anything on the host however common the port.
    pub listen: SocketAddr,
    /// CA certificate path for the agent's trust environment.
    pub ca_cert: Option<PathBuf>,
    pub command: Vec<String>,
}

/// Run the forwarder and the agent, returning the agent's exit code.
pub async fn run(config: SandboxConfig) -> Result<i32, SandboxError> {
    let (program, args) = config.command.split_first().ok_or(SandboxError::NoCommand)?;

    // Bind before spawning the agent. A tool that starts fast and immediately makes a request
    // would otherwise race the listener and see a connection refused it cannot retry past.
    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .map_err(|source| SandboxError::Bind { listen: config.listen, source })?;
    let bound = listener.local_addr().unwrap_or(config.listen);

    let socket = config.socket.clone();
    tokio::spawn(async move {
        loop {
            let Ok((inbound, _)) = listener.accept().await else { continue };
            let socket = socket.clone();
            tokio::spawn(async move {
                if let Err(e) = forward(inbound, &socket).await {
                    tracing::debug!(error = %e, "forwarded connection ended");
                }
            });
        }
    });

    let endpoint = crate::ProxyEndpoint {
        url: format!("http://{bound}"),
        ca_cert: config.ca_cert.clone(),
        credential: None,
    };

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    for (k, v) in crate::proxy_env(&endpoint) {
        cmd.env(k, v);
    }

    let mut child =
        cmd.spawn().map_err(|source| SandboxError::Spawn { program: program.clone(), source })?;

    let status = child
        .wait()
        .await
        .map_err(|source| SandboxError::Spawn { program: program.clone(), source })?;

    // 128 + signal is the shell convention for a signalled child, and keeps `marshal run`
    // transparent to whatever launched it.
    Ok(status.code().unwrap_or(128 + 15))
}

async fn forward(
    mut inbound: tokio::net::TcpStream,
    socket: &std::path::Path,
) -> std::io::Result<()> {
    let mut outbound = tokio::net::UnixStream::connect(socket).await?;
    tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

/// Check a socket path is usable before a sandbox is built around it.
///
/// `AF_UNIX` truncates silently at 108 bytes, which would otherwise surface as a connection
/// failure inside the namespace with no obvious cause.
pub fn check_socket_path(path: &std::path::Path) -> Result<(), String> {
    let len = path.as_os_str().len();
    if len >= UNIX_PATH_MAX {
        return Err(format!(
            "the unix socket path is {len} bytes, but AF_UNIX allows at most {} — choose a \
             shorter `listeners.explicit.unix_socket`, for example under /run/user/<uid>",
            UNIX_PATH_MAX - 1
        ));
    }
    if !path.exists() {
        return Err(format!(
            "{} does not exist. netns isolation reaches the proxy through this socket, so the \
             proxy must be running with `listeners.explicit.unix_socket` configured.",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn overlong_socket_paths_are_rejected_with_a_hint() {
        let long = PathBuf::from(format!("/tmp/{}", "x".repeat(120)));
        let err = check_socket_path(&long).unwrap_err();
        assert!(err.contains("108") || err.contains("107"), "{err}");
        assert!(err.contains("/run/user"), "the error should suggest a fix: {err}");
    }

    #[test]
    fn a_missing_socket_explains_what_is_needed() {
        let err =
            check_socket_path(std::path::Path::new("/tmp/definitely-not-here.sock")).unwrap_err();
        assert!(err.contains("unix_socket"), "{err}");
    }

    #[tokio::test]
    async fn the_forwarder_bridges_tcp_to_the_unix_socket() {
        // Short path: AF_UNIX would truncate a long one.
        let sock = PathBuf::from(format!("/tmp/mfw-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);

        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 64];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let mut echo = b"via-unix:".to_vec();
                    echo.extend_from_slice(&buf[..n]);
                    let _ = s.write_all(&echo).await;
                });
            }
        });

        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let s2 = sock.clone();
        tokio::spawn(async move {
            let (inbound, _) = tcp.accept().await.unwrap();
            let _ = forward(inbound, &s2).await;
        });

        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        c.write_all(b"hello").await.unwrap();
        let mut out = Vec::new();
        c.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"via-unix:hello");

        let _ = std::fs::remove_file(&sock);
    }

    #[tokio::test]
    async fn the_listener_is_bound_before_the_agent_starts() {
        // A fast-starting tool would otherwise race the forwarder and see a refusal it has
        // no way to retry past. The agent here connects immediately and must succeed.
        let sock = PathBuf::from(format!("/tmp/mfw2-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let _ = s.write_all(b"OK").await;
            }
        });

        let port = {
            let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            probe.local_addr().unwrap().port()
        };

        let code = run(SandboxConfig {
            socket: sock.clone(),
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            ca_cert: None,
            // A probe that connects the instant it starts, which is the race this is
            // guarding against. `python3` rather than a shell redirect, since /dev/tcp is a
            // bash-ism and `sh` may be dash.
            command: vec![
                "python3".into(),
                "-c".into(),
                format!(
                    "import socket,sys; s=socket.create_connection(('127.0.0.1',{port}),2); \
                     sys.exit(0 if s.recv(2)==b'OK' else 1)"
                ),
            ],
        })
        .await
        .unwrap();

        assert_eq!(code, 0, "the agent could not reach the forwarder");
        let _ = std::fs::remove_file(&sock);
    }
}
