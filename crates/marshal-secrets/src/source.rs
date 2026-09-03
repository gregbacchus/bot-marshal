//! Where real secrets come from.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use marshal_core::{Error, Result, SecretSource, SecretValue};

/// Reads a secret from an environment variable.
///
/// Read once at resolve time rather than cached at startup, so a process that has its
/// environment updated in place picks it up — and so the proxy holds no copy it does not need.
///
/// Via [`marshal_core::env::var`], so `env_file:` can supply a variable the process
/// environment does not have. The real environment still wins where both have one.
#[derive(Debug)]
pub struct EnvSource {
    var: String,
}

impl EnvSource {
    pub fn new(var: impl Into<String>) -> Self {
        Self { var: var.into() }
    }
}

#[async_trait::async_trait]
impl SecretSource for EnvSource {
    fn name(&self) -> &str {
        &self.var
    }

    async fn resolve(&self) -> Result<SecretValue> {
        marshal_core::env::var(&self.var)
            .map(SecretValue::new)
            .ok_or_else(|| Error::Config(format!("environment variable `{}` is not set", self.var)))
    }
}

/// Reads a secret from a file, cached for a TTL so rotation does not need a restart.
#[derive(Debug)]
pub struct FileSource {
    path: PathBuf,
    ttl: Duration,
    /// When set, the file is parsed as JSON and this key extracted.
    json_key: Option<String>,
    cached: Mutex<Option<(Instant, SecretValue)>>,
}

impl FileSource {
    pub fn new(path: impl Into<PathBuf>, ttl: Duration, json_key: Option<String>) -> Self {
        Self { path: path.into(), ttl, json_key, cached: Mutex::new(None) }
    }

    fn read(&self) -> Result<SecretValue> {
        let text = std::fs::read_to_string(&self.path)?;
        match &self.json_key {
            None => Ok(SecretValue::new(text.trim())),
            Some(key) => {
                let doc: serde_json::Value = serde_json::from_str(&text)
                    .map_err(|e| Error::Config(format!("{}: {e}", self.path.display())))?;
                doc.get(key).and_then(|v| v.as_str()).map(SecretValue::new).ok_or_else(|| {
                    Error::Config(format!("{} has no string field `{key}`", self.path.display()))
                })
            }
        }
    }
}

#[async_trait::async_trait]
impl SecretSource for FileSource {
    fn name(&self) -> &str {
        // Deliberately the path, not the contents.
        self.path.to_str().unwrap_or("<file>")
    }

    async fn resolve(&self) -> Result<SecretValue> {
        {
            let cached = self.cached.lock().expect("secret cache lock");
            if let Some((at, value)) = cached.as_ref()
                && at.elapsed() < self.ttl
            {
                return Ok(value.clone());
            }
        }

        let fresh = self.read()?;
        let mut cached = self.cached.lock().expect("secret cache lock");
        *cached = Some((Instant::now(), fresh.clone()));
        Ok(fresh)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn env_source_reads_the_process_environment() {
        // Reads whatever the runner exported; `PATH` is the one variable that is reliably
        // present. Setting a variable here would need `unsafe`, which the workspace denies,
        // and would race with other tests in the same process.
        let s = EnvSource::new("PATH");
        assert!(!s.resolve().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn env_source_falls_back_to_the_env_file_overlay() {
        // The link that makes `env_file:` work at all: nothing here knows the value came from
        // a file rather than from an export. The overlay is process-global and one-shot, so
        // this is the only test in this binary that installs one, and it uses a name no other
        // test asserts on.
        marshal_core::env::install_overlay([(
            "MARSHAL_TEST_FROM_ENV_FILE".to_owned(),
            "value-from-file".to_owned(),
        )]);
        let s = EnvSource::new("MARSHAL_TEST_FROM_ENV_FILE");
        assert_eq!(s.resolve().await.unwrap().expose(), "value-from-file");
    }

    #[tokio::test]
    async fn a_missing_variable_is_reported_clearly_and_without_a_value() {
        let missing = EnvSource::new("MARSHAL_TEST_ABSENT_VAR");
        let err = missing.resolve().await.unwrap_err().to_string();
        // Names the variable so the operator can fix it, and carries no value.
        assert!(err.contains("MARSHAL_TEST_ABSENT_VAR"), "{err}");
    }

    #[tokio::test]
    async fn file_source_trims_and_caches() {
        let dir = std::env::temp_dir().join(format!("marshal-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "  sk-file-1\n").unwrap();

        let s = FileSource::new(&path, Duration::from_secs(60), None);
        assert_eq!(s.resolve().await.unwrap().expose(), "sk-file-1");

        // Within the TTL the old value is served, which is the point of the cache.
        std::fs::write(&path, "sk-file-2").unwrap();
        assert_eq!(s.resolve().await.unwrap().expose(), "sk-file-1");

        // A zero TTL re-reads, which is how rotation is picked up.
        let fresh = FileSource::new(&path, Duration::ZERO, None);
        assert_eq!(fresh.resolve().await.unwrap().expose(), "sk-file-2");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn file_source_extracts_a_json_field() {
        let dir = std::env::temp_dir().join(format!("marshal-secret-j-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("creds.json");
        std::fs::write(&path, r#"{"api_key": "sk-json-9", "other": 1}"#).unwrap();

        let s = FileSource::new(&path, Duration::ZERO, Some("api_key".into()));
        assert_eq!(s.resolve().await.unwrap().expose(), "sk-json-9");

        let missing = FileSource::new(&path, Duration::ZERO, Some("nope".into()));
        assert!(missing.resolve().await.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
