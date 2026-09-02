//! The property that justifies `--isolation netns` existing at all: an agent inside it
//! **cannot** route around the proxy.
//!
//! Every other isolation mode identifies traffic; only this one prevents bypass. The test is
//! written as a pair — the same probe run with and without the namespace — because "the
//! connection failed" proves nothing on its own. It has to fail *only* when isolated.

use std::io::Write;
use std::process::Command;

/// bwrap and a usable user namespace are environment, not code. Skip rather than fail where
/// they are absent, but say so, so a silent skip is never mistaken for a pass.
fn netns_usable() -> bool {
    let ok = Command::new("bwrap")
        .args(["--dev-bind", "/", "/", "--unshare-net", "--", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: bwrap cannot create a network namespace here");
    }
    ok
}

/// A Unix-socket server that answers `PROXY-OK`, standing in for the proxy's listener.
fn spawn_unix_responder(path: &std::path::Path) -> std::thread::JoinHandle<()> {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path).expect("bind unix socket");
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"PROXY-OK");
        }
    })
}

/// A plain TCP server on host loopback, standing in for anything the agent might try to
/// reach directly.
fn spawn_tcp_responder() -> (std::net::SocketAddr, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind tcp");
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        while let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"DIRECT-OK");
        }
    });
    (addr, handle)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A probe that reports which of the two destinations it could reach.
fn probe(forwarder_port: u16, direct: std::net::SocketAddr) -> Vec<String> {
    vec![
        "python3".into(),
        "-c".into(),
        format!(
            "import socket\n\
             def try_connect(host, port):\n\
             \x20   try:\n\
             \x20       s = socket.create_connection((host, port), 3)\n\
             \x20       return s.recv(16).decode()\n\
             \x20   except Exception as e:\n\
             \x20       return 'FAIL'\n\
             print('forwarder=' + try_connect('127.0.0.1', {forwarder_port}))\n\
             print('direct=' + try_connect('{}', {}))\n",
            direct.ip(),
            direct.port()
        ),
    ]
}

/// Run `marshal sandbox`, optionally wrapped in a network namespace.
fn run_sandbox(
    isolated: bool,
    socket: &std::path::Path,
    forwarder_port: u16,
    direct: std::net::SocketAddr,
) -> String {
    let exe = env!("CARGO_BIN_EXE_marshal");
    let mut cmd = if isolated {
        let mut c = Command::new("bwrap");
        c.args(["--dev-bind", "/", "/", "--proc", "/proc", "--unshare-net", "--", exe]);
        c
    } else {
        Command::new(exe)
    };

    cmd.arg("sandbox")
        .arg("--socket")
        .arg(socket)
        .arg("--listen")
        .arg(format!("127.0.0.1:{forwarder_port}"))
        .arg("--")
        .args(probe(forwarder_port, direct));

    let out = cmd.output().expect("sandbox runs");
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn a_namespaced_agent_reaches_the_proxy_and_nothing_else() {
    if !netns_usable() {
        return;
    }

    // Short path: AF_UNIX truncates at 108 bytes, and a temp dir under a long prefix would
    // silently exceed it.
    let socket = std::path::PathBuf::from(format!("/tmp/mns-{}.sock", std::process::id()));
    let _unix = spawn_unix_responder(&socket);
    let (direct, _tcp) = spawn_tcp_responder();
    let port = free_port();

    // Control: without the namespace, both destinations are reachable. This is what proves
    // the isolated run below is measuring isolation rather than a closed port.
    let open = run_sandbox(false, &socket, port, direct);
    assert!(open.contains("forwarder=PROXY-OK"), "control could not reach the proxy: {open}");
    assert!(open.contains("direct=DIRECT-OK"), "control could not reach directly: {open}");

    // Isolated: the proxy is still reachable, because a Unix socket is a filesystem object
    // and crosses the namespace boundary. Nothing else is.
    let sealed = run_sandbox(true, &socket, free_port(), direct);
    assert!(
        sealed.contains("forwarder=PROXY-OK"),
        "the namespaced agent could not reach the proxy: {sealed}"
    );
    assert!(
        sealed.contains("direct=FAIL"),
        "the namespaced agent routed around the proxy, which is the one thing netns must \
         prevent: {sealed}"
    );

    let _ = std::fs::remove_file(&socket);
}

#[test]
fn a_namespaced_agent_cannot_resolve_dns() {
    // A consequence worth asserting rather than assuming: with no network, the agent cannot
    // resolve names either, so a hostname is only ever resolved by the proxy *after* policy
    // has run. That closes DNS-based exfiltration, which destination filtering never sees.
    if !netns_usable() {
        return;
    }

    let out = Command::new("bwrap")
        .args([
            "--dev-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--unshare-net",
            "--",
            "python3",
            "-c",
            "import socket\n\
             try:\n\
             \x20   socket.gethostbyname('example.com'); print('RESOLVED')\n\
             except Exception:\n\
             \x20   print('NO-DNS')\n",
        ])
        .output()
        .expect("bwrap runs");

    assert!(
        String::from_utf8_lossy(&out.stdout).contains("NO-DNS"),
        "the namespace still had DNS: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}
