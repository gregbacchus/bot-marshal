//! `SO_ORIGINAL_DST` against a real kernel redirect.
//!
//! Every other test of the transparent-interception path exercises `original_dst`'s parsing
//! and its "not redirected" fallback, but none of them prove the actual mechanism — a real
//! `nftables` NAT redirect handled by the kernel's connection tracker — because that normally
//! needs root.
//!
//! It doesn't, in practice. An unprivileged user namespace paired with its own network
//! namespace (`unshare --net --map-root-user`) grants full `CAP_NET_ADMIN` *inside* that
//! namespace with no privilege escalation at all — the same mechanism `marshal run
//! --isolation netns` already depends on. A loopback-only network inside that namespace is
//! sufficient: conntrack and NAT work identically regardless of whether the namespace has any
//! real connectivity, so a redirect rule targeting loopback proves the same code path a
//! deployed `deploy/nftables.conf` relies on.
//!
//! The test re-execs its own binary inside that namespace to run the actual probe, because
//! the socket accepting the redirected connection has to exist *inside* the namespace the
//! rule was loaded into — there is no way to set up the namespace from outside and then reach
//! into it for a single accept call.

use std::process::Command;

/// Whether this environment can create a namespace with net-admin capability. Skipped rather
/// than failed when it cannot, but loudly, so a skip is never mistaken for a pass.
fn netns_usable() -> bool {
    let ok = Command::new("unshare")
        .args(["--net", "--map-root-user", "--", "true"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: cannot create an unprivileged network namespace here");
    }
    ok
}

fn nft_usable() -> bool {
    let ok = Command::new("unshare")
        .args(["--net", "--map-root-user", "--", "nft", "--version"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("SKIP: nft is not available inside the namespace");
    }
    ok
}

#[test]
fn original_dst_recovers_the_real_destination_under_a_live_redirect() {
    if !netns_usable() || !nft_usable() {
        return;
    }

    let this_test_binary = std::env::current_exe().expect("current test binary path");

    // The victim port is where the client connects; the kernel redirects that to the proxy
    // port before any userspace socket on the victim port ever sees it. `capture` (not
    // `redirect`) as the chain name — `redirect` is an nft keyword, and using it as an
    // identifier is exactly the mistake deploy/nftables.conf itself made and this repo's own
    // `nft --check` test catches.
    let script = r#"
set -e
ip link set lo up
nft add table ip test
nft add chain ip test capture '{ type nat hook output priority dstnat ; }'
nft add rule ip test capture tcp dport 29999 redirect to :29998
exec "$0" --exact inner_probe_run_directly_only_from_the_namespaced_reexec --ignored --nocapture --test-threads=1
"#;

    // `bash -c script $0` — the binary path becomes `$0` inside the script, which is what
    // `exec "$0" ...` at the end of the script re-execs.
    let output = Command::new("unshare")
        .args(["--net", "--map-root-user", "--", "bash", "-c", script])
        .arg(&this_test_binary)
        .output()
        .expect("unshare runs");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the namespaced probe failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("RECOVERED 127.0.0.1:29999"),
        "the probe did not report recovering the victim address:\n{stdout}\n{stderr}"
    );
}

/// The half that runs *inside* the namespace, after the redirect rule is already loaded.
/// `#[ignore]`d so an ordinary `cargo test` never runs it directly — outside the namespace it
/// would just hit the "not redirected" fallback, which is already covered elsewhere and is
/// not what this file exists to prove.
#[tokio::test]
#[ignore = "only meaningful when re-invoked inside a namespace with the redirect rule loaded"]
async fn inner_probe_run_directly_only_from_the_namespaced_reexec() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:29998")
        .await
        .expect("bind the proxy-side listener");

    let client = tokio::spawn(async {
        // The victim port: never bound by anything. The connection never reaches userspace
        // there — the kernel redirects it before accept() on that port could ever fire.
        tokio::net::TcpStream::connect("127.0.0.1:29999")
            .await
            .expect("connect to the (redirected) victim port")
    });

    let (accepted, _peer) =
        tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .expect("accept within 5s")
            .expect("accept succeeds");

    let dst = marshal_proxy::transparent::original_dst(&accepted)
        .expect("SO_ORIGINAL_DST reports the real destination");

    // Printed rather than only asserted: the outer test reads this from captured stdout,
    // since the pass/fail signal alone does not distinguish "recovered the wrong address"
    // from every other way this could fail.
    println!("RECOVERED {dst}");
    assert_eq!(dst.port(), 29999, "recovered the proxy's own port, not the victim's");
    assert_eq!(dst.ip().to_string(), "127.0.0.1");

    client.await.unwrap();
}
