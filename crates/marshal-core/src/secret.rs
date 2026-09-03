//! Secret sources and values.

use crate::error::Result;

/// A resolved secret.
///
/// `Debug` and `Display` are deliberately not derived: the only way to reach the bytes is
/// [`SecretValue::expose`], which makes every use site greppable.
#[derive(Clone)]
pub struct SecretValue(String);

impl SecretValue {
    pub fn new(value: impl Into<String>) -> Self {
        SecretValue(value.into())
    }

    /// Yield the real value. Call sites are audited; never log the result.
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretValue(<redacted, {} bytes>)", self.0.len())
    }
}

/// Where a secret comes from. Implementations cache with a TTL so rotation does not require
/// a restart.
#[async_trait::async_trait]
pub trait SecretSource: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;

    /// Produce the secret, doing whatever that takes.
    async fn resolve(&self) -> Result<SecretValue>;

    /// The value this source can supply **without going and getting one**, for seeding the
    /// redactor at startup.
    ///
    /// The distinction only matters for a source where resolving has a cost or a side effect.
    /// Reading an environment variable or a file is free and idempotent, so the default is
    /// simply to resolve — and a failure here is worth reporting, because a missing variable
    /// at startup is a configuration error the operator wants to hear about immediately.
    ///
    /// A source that *obtains* a credential rather than reading one — OAuth2 — must override
    /// this to return only what it already holds. Resolving such a source at startup would
    /// mint a credential nobody asked for, tie process start to a third party's availability,
    /// and, against a provider that rotates refresh tokens, consume a rotation just by
    /// booting.
    ///
    /// `Ok(None)` means "nothing yet, and that is not an error".
    async fn preload(&self) -> Result<Option<SecretValue>> {
        self.resolve().await.map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_debug_never_leaks() {
        let s = SecretValue::new("sk-live-abcdef");
        let rendered = format!("{s:?}");
        assert!(!rendered.contains("sk-live"));
        assert!(rendered.contains("14 bytes"));
    }
}
