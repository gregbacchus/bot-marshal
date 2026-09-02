//! Loading: a base file plus, by convention, one profile per file under `profiles/` and one
//! bundle per file under `bundles/`, both resolved relative to the base file.
//!
//! This is deliberately a fixed convention rather than an arbitrary `include:` glob of full
//! config documents: a file under `profiles/` can only ever be a profile — its schema has no
//! `tls`/`listeners`/anything else to accidentally clobber — and the filename *is* the key, so
//! two profiles cannot silently collide the way two arbitrary included files defining the same
//! `profiles.<name>` key once could. The base file may still define `profiles:`/`bundles:`
//! inline for a config small enough not to need the split; a name that appears both inline and
//! as a file is a load error, not a silent override.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

use crate::layer::HostSet;
use crate::model::{Config, Profile};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("parsing {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error(
        "profile `{name}` is defined both in {path} and inline in the base config — name it \
         in only one place"
    )]
    DuplicateProfile { name: String, path: PathBuf },

    #[error(
        "bundle `{name}` is defined both in {path} and inline in the base config — name it in \
         only one place"
    )]
    DuplicateBundle { name: String, path: PathBuf },
}

/// Load a config file, plus every profile under a sibling `profiles/` directory and every
/// bundle under a sibling `bundles/` directory.
pub fn load(path: impl AsRef<Path>) -> Result<Config, LoadError> {
    let path = path.as_ref();
    let mut cfg: Config = read_one(path)?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));

    for (name, path, profile) in load_dir::<Profile>(&dir.join("profiles"))? {
        if cfg.profiles.insert(name.clone(), profile).is_some() {
            return Err(LoadError::DuplicateProfile { name, path });
        }
    }
    for (name, path, bundle) in load_dir::<HostSet>(&dir.join("bundles"))? {
        if cfg.bundles.insert(name.clone(), bundle).is_some() {
            return Err(LoadError::DuplicateBundle { name, path });
        }
    }
    Ok(cfg)
}

fn read_one<T: DeserializeOwned>(path: &Path) -> Result<T, LoadError> {
    let text = std::fs::read_to_string(path)
        .map_err(|source| LoadError::Io { path: path.to_path_buf(), source })?;
    serde_yaml_ng::from_str(&text)
        .map_err(|source| LoadError::Parse { path: path.to_path_buf(), source })
}

/// Every `.yaml`/`.yml` file directly under `dir`, each parsed as `T` and keyed by its file
/// stem. Sorted so a duplicate-detection error is deterministic. A missing directory yields no
/// entries rather than an error — the split is opt-in.
fn load_dir<T: DeserializeOwned>(dir: &Path) -> Result<Vec<(String, PathBuf, T)>, LoadError> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };

    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && matches!(p.extension().and_then(|e| e.to_str()), Some("yaml") | Some("yml"))
        })
        .collect();
    files.sort();

    files
        .into_iter()
        .map(|path| {
            // Not a full path lookup, so a name containing a path separator (impossible in a
            // real file stem) can't be crafted to name something other than a plain key.
            let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or_default().to_owned();
            let value: T = read_one(&path)?;
            Ok((name, path, value))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory unique to this test, cleaned up on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("marshal-config-load-{label}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, rel: &str, contents: &str) {
            let path = self.0.join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn one_profile_per_file_is_keyed_by_filename() {
        let dir = TempDir::new("profiles-ok");
        dir.write("config.yaml", "tls: {}\n");
        dir.write("profiles/coding-agent.yaml", "default_action: deny\n");
        dir.write("profiles/base.yaml", "default_action: allow\n");

        let cfg = load(dir.0.join("config.yaml")).unwrap();
        assert_eq!(cfg.profiles.len(), 2);
        assert!(matches!(
            cfg.profiles["coding-agent"].default_action,
            marshal_core::Decision::Deny
        ));
        assert!(matches!(cfg.profiles["base"].default_action, marshal_core::Decision::Allow));
    }

    #[test]
    fn one_bundle_per_file_is_keyed_by_filename() {
        let dir = TempDir::new("bundles-ok");
        dir.write("config.yaml", "tls: {}\n");
        dir.write("bundles/github.yaml", "domains: [\"github.com\"]\n");

        let cfg = load(dir.0.join("config.yaml")).unwrap();
        assert_eq!(cfg.bundles["github"].domains, vec!["github.com".to_string()]);
    }

    #[test]
    fn a_profile_file_cannot_smuggle_in_an_unrelated_section() {
        // The whole point of the convention over an arbitrary include: a file under
        // profiles/ has no `tls`/`listeners` field to accidentally set — deserialising it
        // as `Profile` directly rejects anything that isn't a profile field.
        let dir = TempDir::new("profiles-cannot-smuggle");
        dir.write("config.yaml", "tls: {}\n");
        dir.write("profiles/base.yaml", "tls: { ca_cert: \"/evil\" }\n");

        let err = load(dir.0.join("config.yaml")).unwrap_err();
        assert!(matches!(err, LoadError::Parse { .. }), "{err}");
    }

    #[test]
    fn a_name_defined_both_inline_and_as_a_file_is_a_load_error() {
        let dir = TempDir::new("profiles-duplicate");
        dir.write("config.yaml", "tls: {}\nprofiles:\n  base:\n    default_action: allow\n");
        dir.write("profiles/base.yaml", "default_action: deny\n");

        let err = load(dir.0.join("config.yaml")).unwrap_err();
        assert!(matches!(err, LoadError::DuplicateProfile { name, .. } if name == "base"));
    }

    #[test]
    fn a_missing_profiles_directory_is_not_an_error() {
        let dir = TempDir::new("profiles-missing-dir");
        dir.write("config.yaml", "tls: {}\n");

        let cfg = load(dir.0.join("config.yaml")).unwrap();
        assert!(cfg.profiles.is_empty());
    }
}
