//! The shipped deployment artifacts must actually be valid.
//!
//! Caught real breakage while being written: an example config that fails to parse is worse
//! than none, since it's the first thing anyone copies.

use std::process::Command;

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
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
