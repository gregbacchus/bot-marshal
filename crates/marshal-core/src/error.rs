//! Error type shared across the workspace.

/// Errors raised while evaluating policy or moving traffic.
///
/// A layer returning `Err` is *not* a verdict: the chain applies that layer's configured
/// [`FailureMode`](crate::policy::FailureMode) instead, so an error can never accidentally
/// become an allow.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("policy layer {layer} failed: {source}")]
    Layer {
        layer: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("layer {layer} timed out after {elapsed_ms}ms")]
    LayerTimeout { layer: String, elapsed_ms: u64 },

    #[error("upstream connection refused by guard: {0}")]
    UpstreamGuard(String),

    #[error("body exceeded the configured cap of {cap} bytes")]
    BodyTooLarge { cap: usize },

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
