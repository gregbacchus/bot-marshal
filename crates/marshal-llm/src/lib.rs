//! LLM dialect routing: OpenAI/Anthropic chat translation and native System One decisions.
//!
//! No I/O. The proxy opens the mapped origin; this crate rewrites JSON, headers, and SSE.

mod router;
mod sse;
mod translate;

pub use router::LlmRouter;
pub use translate::{Dialect, TranslateError, translate_request, translate_response};

pub use marshal_config::{LlmDialect, LlmRouterConfig};
