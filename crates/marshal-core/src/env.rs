//! Environment variable lookup, with an overlay the binary installs from `env_file:`.
//!
//! Every place that reads a variable *named by the config* — an `env` secret source, a judge's
//! `api_key_env`, the management API key — goes through [`var`] rather than
//! `std::env::var`, so all of them can be fed from a file next to the config instead of
//! from whatever exported the variable.
//!
//! Two properties are deliberate, and both are why this is an overlay rather than a call to
//! `std::env::set_var`:
//!
//! * **The real environment wins.** An operator who ran `SERVICE_TOKEN=… marshal serve`, or
//!   who wrote `Environment=` in a unit file, has said something more specific than a file
//!   checked out beside the config. Silently overriding that would make a rotated token
//!   impossible to apply without editing the file.
//! * **Nothing a child process can inherit changes.** The whole point of boundary injection is
//!   that the agent never holds the credential (ADR-0011); `marshal run` spawns agents from
//!   this process, so putting the file's values into this process's *actual* environment would
//!   hand every one of them straight to the agent. An overlay is invisible to `fork`/`exec`,
//!   so that cannot happen by omission.
//!
//! It also avoids `std::env::set_var`, which is unsound once any thread exists.

use std::collections::BTreeMap;
use std::sync::OnceLock;

static OVERLAY: OnceLock<BTreeMap<String, String>> = OnceLock::new();

/// Install the overlay. Called once, at startup, before anything resolves a variable.
///
/// Returns `false` if an overlay was already installed, in which case `vars` is discarded —
/// there is exactly one env file per process and it is read before any work begins, so a
/// second call means a bug rather than a situation to merge.
pub fn install_overlay(vars: impl IntoIterator<Item = (String, String)>) -> bool {
    OVERLAY.set(vars.into_iter().collect()).is_ok()
}

/// The value of `name`: the process environment first, then the overlay.
pub fn var(name: &str) -> Option<String> {
    match std::env::var(name) {
        Ok(v) => Some(v),
        // A variable set to something that is not UTF-8 is treated as set-but-unusable rather
        // than falling through to the overlay: the operator's environment still wins, and
        // "your token has a stray byte in it" is a better thing to be told than a silent
        // substitution of a different value.
        Err(std::env::VarError::NotUnicode(_)) => None,
        Err(std::env::VarError::NotPresent) => OVERLAY.get().and_then(|o| o.get(name)).cloned(),
    }
}

/// Whether `name` has a value from either source.
pub fn is_set(name: &str) -> bool {
    var(name).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_overlay_fills_gaps_and_never_shadows_the_real_environment() {
        // `install_overlay` is process-global and one-shot, so this is the single test that
        // may install it; the rest of the behaviour is asserted through it.
        assert!(install_overlay([
            ("MARSHAL_TEST_OVERLAY_ONLY".to_owned(), "from-file".to_owned()),
            ("PATH".to_owned(), "should-never-win".to_owned()),
        ]));

        assert_eq!(var("MARSHAL_TEST_OVERLAY_ONLY").as_deref(), Some("from-file"));
        assert!(is_set("MARSHAL_TEST_OVERLAY_ONLY"));
        assert_eq!(var("MARSHAL_TEST_DEFINITELY_UNSET"), None);
        assert!(!is_set("MARSHAL_TEST_DEFINITELY_UNSET"));

        // PATH is set in every environment this runs in, so the overlay must lose.
        assert_ne!(var("PATH").as_deref(), Some("should-never-win"));

        // Second install is refused rather than merged.
        assert!(!install_overlay([("X".to_owned(), "y".to_owned())]));
    }
}
