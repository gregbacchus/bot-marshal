//! Where minted credentials live.
//!
//! Two tiers, because two things with very different lifetimes are being kept.
//!
//! An **access token** is short-lived and re-mintable, so it lives in memory only. Losing it
//! costs one round trip to the token endpoint.
//!
//! A **refresh token** is the credential itself. For the interactive grants it is the *only*
//! copy — it was obtained once, at enrolment, by a human at a browser, and cannot be re-derived
//! from anything in the config. It therefore goes to disk, and it goes there *before* the
//! access token it arrived with is handed to anyone: a provider that rotates refresh tokens
//! invalidates the old one the moment it issues the new one, so a crash between "used the
//! response" and "persisted the response" leaves the operator with nothing but a re-enrolment.
//!
//! The store is process-global and keyed by swap name, deliberately. A config reload rebuilds
//! every injector and throws the old ones away ([ADR-0020](../../../../docs/adr/0020-reload-builds-everything-before-swapping.md));
//! if the token cache lived on the injector, reloading would silently re-mint every credential
//! in the process. Reload is a config operation, not a credential operation.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use marshal_core::{Error, Result, SecretValue, percent_encode};

use super::token::CachedToken;

/// What survives a restart: the long-lived half of a grant.
#[derive(Debug, Clone)]
pub struct StoredGrant {
    pub refresh_token: SecretValue,
    /// Unix seconds. Diagnostic only — nothing branches on it, but `marshal secrets oauth
    /// status` showing "enrolled 40 days ago" is the difference between an operator knowing a
    /// refresh token is about to age out and finding out when it stops working.
    pub obtained_at: i64,
    pub scope: Option<String>,
}

impl StoredGrant {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "refresh_token": self.refresh_token.expose(),
            "obtained_at": self.obtained_at,
            "scope": self.scope,
        })
    }

    fn from_json(doc: &serde_json::Value, path: &Path) -> Result<Self> {
        let refresh_token = doc
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                Error::Config(format!("{}: no `refresh_token` field", path.display()))
            })?;
        Ok(Self {
            refresh_token: SecretValue::new(refresh_token),
            obtained_at: doc.get("obtained_at").and_then(|v| v.as_i64()).unwrap_or(0),
            scope: doc.get("scope").and_then(|v| v.as_str()).map(str::to_owned),
        })
    }
}

#[derive(Debug, Default)]
pub struct TokenStore {
    /// `None` means nothing is persisted: every credential lives only as long as the process,
    /// and the interactive grants cannot be used at all.
    dir: Option<PathBuf>,
    access: Mutex<HashMap<String, CachedToken>>,
    /// Write-through cache of what is on disk, so the common path does not stat a file per
    /// request.
    grants: Mutex<HashMap<String, StoredGrant>>,
}

/// The single store for the life of the process. See the module docs on why this outlives a
/// config reload.
static GLOBAL: OnceLock<std::sync::Arc<TokenStore>> = OnceLock::new();

impl TokenStore {
    /// Install the process-wide store, or return the one already installed.
    ///
    /// First caller wins: a reload calls this again with the same `state_dir` and gets the
    /// existing store back, tokens intact. A reload that *changes* `state_dir` does not take
    /// effect until restart, which is stated in the docs rather than silently worked around —
    /// silently moving live credentials to a new directory mid-process is worse.
    pub fn global(state_dir: Option<PathBuf>) -> std::sync::Arc<Self> {
        std::sync::Arc::clone(GLOBAL.get_or_init(|| std::sync::Arc::new(Self::new(state_dir))))
    }

    pub fn new(state_dir: Option<PathBuf>) -> Self {
        Self { dir: state_dir.map(|d| d.join("oauth")), ..Default::default() }
    }

    pub fn persists(&self) -> bool {
        self.dir.is_some()
    }

    pub fn cached_access(&self, swap: &str) -> Option<CachedToken> {
        let cache = self.access.lock().expect("token cache lock");
        cache.get(swap).filter(|t| t.is_live()).cloned()
    }

    pub fn put_access(&self, swap: &str, token: CachedToken) {
        // A token with no stated expiry is never live, so caching it would only grow the map
        // with entries nothing can ever read.
        if !token.is_live() {
            return;
        }
        self.access.lock().expect("token cache lock").insert(swap.to_owned(), token);
    }

    /// Drop the cached access token, forcing the next resolve to mint. Used by
    /// `marshal secrets oauth refresh` and after a provider rejects a token as invalid.
    pub fn forget_access(&self, swap: &str) {
        self.access.lock().expect("token cache lock").remove(swap);
    }

    /// The stored grant for `swap`, reading from disk on the first ask.
    pub fn grant(&self, swap: &str) -> Result<Option<StoredGrant>> {
        if let Some(g) = self.grants.lock().expect("grant cache lock").get(swap) {
            return Ok(Some(g.clone()));
        }
        let Some(path) = self.path_for(swap) else { return Ok(None) };
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(Error::Config(format!("{}: {e}", path.display()))),
        };
        let doc: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
        let grant = StoredGrant::from_json(&doc, &path)?;
        self.grants.lock().expect("grant cache lock").insert(swap.to_owned(), grant.clone());
        Ok(Some(grant))
    }

    /// Persist a grant, replacing whatever was there.
    ///
    /// Written to a temporary file and renamed, so a crash mid-write leaves the previous
    /// grant intact rather than a truncated file — which for a rotating refresh token would
    /// mean the credential is simply gone.
    pub fn put_grant(&self, swap: &str, grant: StoredGrant) -> Result<()> {
        let Some(path) = self.path_for(swap) else {
            return Err(Error::Config(format!(
                "cannot persist the `{swap}` grant: no `state_dir` is configured, so marshal \
                 has nowhere to keep a refresh token across restarts"
            )));
        };
        let dir = self.dir.as_ref().expect("path_for returned Some");
        create_private_dir(dir)?;

        let tmp = path.with_extension("json.tmp");
        write_private(&tmp, &serde_json::to_vec_pretty(&grant.to_json()).expect("serialises"))?;
        std::fs::rename(&tmp, &path)
            .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;

        self.grants.lock().expect("grant cache lock").insert(swap.to_owned(), grant);
        Ok(())
    }

    /// Forget a grant entirely, on disk and in memory. `marshal secrets oauth logout`.
    pub fn remove_grant(&self, swap: &str) -> Result<bool> {
        self.forget_access(swap);
        self.grants.lock().expect("grant cache lock").remove(swap);
        let Some(path) = self.path_for(swap) else { return Ok(false) };
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::Config(format!("{}: {e}", path.display()))),
        }
    }

    fn path_for(&self, swap: &str) -> Option<PathBuf> {
        // A swap name is operator-chosen and lands in a filename. Percent-encoding is enough
        // to make it safe (`/` and `..` both encode) and leaves ordinary names — which are
        // alphanumerics, `-` and `_` — completely readable on disk.
        self.dir.as_ref().map(|d| d.join(format!("{}.json", percent_encode(swap.as_bytes()))))
    }
}

/// Create a directory 0700, and refuse one that anybody else can read.
///
/// Refusing rather than fixing: silently tightening permissions on a directory the operator
/// set up would hide a real misconfiguration, and a refresh token that has already been
/// readable by another local user should be re-enrolled, not quietly locked down after the
/// fact.
fn create_private_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| Error::Config(format!("creating {}: {e}", dir.display())))?;
        return Ok(());
    }

    let mode = std::fs::metadata(dir)
        .map_err(|e| Error::Config(format!("{}: {e}", dir.display())))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Config(format!(
            "{} is mode {mode:o}, which lets other local users read stored credentials; \
             it must be 0700",
            dir.display()
        )));
    }
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    f.write_all(bytes).map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    // The point of the temp-and-rename is that the file on disk is complete; without the
    // sync, a power loss can leave the rename durable and the contents not.
    f.sync_all().map_err(|e| Error::Config(format!("{}: {e}", path.display())))?;
    Ok(())
}

/// Unix seconds now, for stamping a freshly obtained grant.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tempdir() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "marshal-oauth-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn grant(rt: &str) -> StoredGrant {
        StoredGrant {
            refresh_token: SecretValue::new(rt),
            obtained_at: now_unix(),
            scope: Some("read".into()),
        }
    }

    #[test]
    fn a_grant_round_trips_through_disk() {
        let dir = tempdir();
        let store = TokenStore::new(Some(dir.clone()));
        store.put_grant("SERVICE", grant("rt-1")).unwrap();

        // A second store over the same directory is what a restart looks like.
        let restarted = TokenStore::new(Some(dir));
        let got = restarted.grant("SERVICE").unwrap().unwrap();
        assert_eq!(got.refresh_token.expose(), "rt-1");
        assert_eq!(got.scope.as_deref(), Some("read"));
    }

    #[test]
    fn rotation_replaces_the_stored_refresh_token() {
        let dir = tempdir();
        let store = TokenStore::new(Some(dir.clone()));
        store.put_grant("SERVICE", grant("rt-old")).unwrap();
        store.put_grant("SERVICE", grant("rt-new")).unwrap();
        assert_eq!(
            TokenStore::new(Some(dir)).grant("SERVICE").unwrap().unwrap().refresh_token.expose(),
            "rt-new"
        );
    }

    #[test]
    fn the_grant_file_is_not_readable_by_anyone_else() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        let store = TokenStore::new(Some(dir.clone()));
        store.put_grant("SERVICE", grant("rt-1")).unwrap();

        let file = dir.join("oauth").join("SERVICE.json");
        assert_eq!(std::fs::metadata(&file).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(
            std::fs::metadata(dir.join("oauth")).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn a_world_readable_state_dir_is_refused_rather_than_quietly_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir();
        std::fs::create_dir_all(dir.join("oauth")).unwrap();
        std::fs::set_permissions(dir.join("oauth"), std::fs::Permissions::from_mode(0o755))
            .unwrap();

        let store = TokenStore::new(Some(dir));
        let err = store.put_grant("SERVICE", grant("rt-1")).unwrap_err();
        assert!(format!("{err}").contains("0700"), "{err}");
    }

    #[test]
    fn a_swap_name_cannot_escape_the_state_directory() {
        let dir = tempdir();
        let store = TokenStore::new(Some(dir.clone()));
        store.put_grant("../../escape", grant("rt-1")).unwrap();
        assert!(!dir.parent().unwrap().join("escape.json").exists());
        assert!(store.grant("../../escape").unwrap().is_some());
    }

    #[test]
    fn no_state_dir_means_a_grant_cannot_be_persisted_and_says_so() {
        let store = TokenStore::new(None);
        assert!(!store.persists());
        assert!(store.grant("SERVICE").unwrap().is_none());
        let err = store.put_grant("SERVICE", grant("rt-1")).unwrap_err();
        assert!(format!("{err}").contains("state_dir"), "{err}");
    }

    #[test]
    fn logout_removes_the_grant_and_the_cached_access_token() {
        let dir = tempdir();
        let store = TokenStore::new(Some(dir));
        store.put_grant("SERVICE", grant("rt-1")).unwrap();
        store.put_access(
            "SERVICE",
            CachedToken::new(
                SecretValue::new("at-1"),
                Some(Duration::from_secs(3600)),
                Duration::ZERO,
            ),
        );
        assert!(store.remove_grant("SERVICE").unwrap());
        assert!(store.grant("SERVICE").unwrap().is_none());
        assert!(store.cached_access("SERVICE").is_none());
        // Removing again is not an error — `logout` is idempotent.
        assert!(!store.remove_grant("SERVICE").unwrap());
    }

    #[test]
    fn an_expired_access_token_is_not_handed_out() {
        let store = TokenStore::new(None);
        store.put_access(
            "SERVICE",
            CachedToken::new(
                SecretValue::new("at"),
                Some(Duration::from_secs(10)),
                Duration::from_secs(60),
            ),
        );
        assert!(store.cached_access("SERVICE").is_none());
    }
}
