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
    async fn resolve(&self) -> Result<SecretValue>;
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
