//! The shipped deployment artifacts must actually be valid.
//!
//! Both of these caught real breakage while being written: the nftables ruleset used
//! `redirect` as a chain name, which is a reserved word, and would have failed the first time
//! anyone loaded it.

use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

#[test]
fn the_nftables_ruleset_is_syntactically_valid() {
    let path = repo_root().join("deploy/nftables.conf");
    assert!(path.exists(), "{} is missing", path.display());

    let Ok(out) = Command::new("nft").arg("--check").arg("-f").arg(&path).output() else {
        eprintln!("SKIP: nft is not installed");
        return;
    };

    let stderr = String::from_utf8_lossy(&out.stderr);
    // Unprivileged `nft --check` still parses the file but cannot talk to netlink. That
    // failure is expected here; a syntax error is not.
    assert!(!stderr.contains("syntax error"), "deploy/nftables.conf has a syntax error:\n{stderr}");
    assert!(!stderr.contains("Error: unknown"), "{stderr}");
}

#[test]
fn the_shipped_configs_validate() {
    // A broken example config is worse than none: it is the first thing anyone copies.
    for relative in ["config/marshal.yaml", "examples/docker/marshal.yaml"] {
        let path = repo_root().join(relative);
        let out = Command::new(env!("CARGO_BIN_EXE_marshal"))
            .arg("--config")
            .arg(&path)
            .args(["config", "check"])
            .output()
            .expect("marshal runs");

        assert!(
            out.status.success(),
            "{relative} failed validation:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
