//! Layered loading: a base file plus `include` globs.

use std::path::{Path, PathBuf};

use crate::model::Config;

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

    #[error("invalid include glob {glob:?}: {source}")]
    Glob {
        glob: String,
        #[source]
        source: globset::Error,
    },
}

/// Load a config file and everything its `include` globs match.
///
/// Includes are merged **before** the base document's own entries, so a base file always wins
/// over a bundle it imported. Includes do not recurse: a bundle listing its own `include` is
/// ignored, which keeps the merge order comprehensible.
pub fn load(path: impl AsRef<Path>) -> Result<Config, LoadError> {
    let path = path.as_ref();
    let base: Config = read_one(path)?;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut merged = Config::default();

    for glob in &base.include {
        for included in expand(dir, glob)? {
            let cfg = read_one(&included)?;
            merge(&mut merged, cfg);
        }
    }

    merge(&mut merged, base);
    Ok(merged)
}

fn read_one(path: &Path) -> Result<Config, LoadError> {
    let text = std::fs::read_to_string(path)
        .map_err(|source| LoadError::Io { path: path.to_path_buf(), source })?;
    serde_yaml_ng::from_str(&text)
        .map_err(|source| LoadError::Parse { path: path.to_path_buf(), source })
}

/// Expand one glob against `dir`. Returns matches in sorted order so a merge is deterministic
/// regardless of directory iteration order.
fn expand(dir: &Path, glob: &str) -> Result<Vec<PathBuf>, LoadError> {
    let matcher = globset::Glob::new(glob)
        .map_err(|source| LoadError::Glob { glob: glob.to_string(), source })?
        .compile_matcher();

    let search_root = match Path::new(glob).parent() {
        Some(p) if !p.as_os_str().is_empty() => dir.join(p),
        _ => dir.to_path_buf(),
    };

    let Ok(entries) = std::fs::read_dir(&search_root) else {
        return Ok(Vec::new());
    };

    let mut out: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .filter(|p| p.strip_prefix(dir).map(|rel| matcher.is_match(rel)).unwrap_or(false))
        .collect();
    out.sort();
    Ok(out)
}

/// Later documents win. Profiles and bundles merge by key rather than replacing wholesale.
fn merge(into: &mut Config, from: Config) {
    let Config { include, listeners, tls, upstream, profiles, sessions, bundles } = from;

    if !include.is_empty() {
        into.include = include;
    }
    if listeners.explicit.is_some() {
        into.listeners.explicit = listeners.explicit;
    }
    if listeners.transparent.is_some() {
        into.listeners.transparent = listeners.transparent;
    }
    if listeners.dns.is_some() {
        into.listeners.dns = listeners.dns;
    }
    if listeners.management.is_some() {
        into.listeners.management = listeners.management;
    }
    if tls.ca_cert.is_some() || tls.ca_key.is_some() || !tls.passthrough.is_empty() {
        into.tls = tls;
    }
    if !upstream.deny_cidrs.is_empty() {
        into.upstream = upstream;
    }
    into.profiles.extend(profiles);
    into.bundles.extend(bundles);
    if !sessions.resolvers.is_empty() || sessions.unidentified.is_some() {
        into.sessions = sessions;
    }
}
