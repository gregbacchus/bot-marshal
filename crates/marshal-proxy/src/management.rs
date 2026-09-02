//! The management API.
//!
//! Small on purpose. It exists to answer three operational questions — is the proxy alive,
//! what is it doing, and can it pick up a config change without dropping connections — and
//! nothing else. Every endpoint it does not have is one that cannot be abused.
//!
//! It binds loopback by default and requires a bearer token, because reload is a
//! policy-changing operation: anyone who can call it can replace the ruleset.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::runtime::{Runtime, RuntimeHandle};
use crate::stats::SessionStats;

/// Builds a fresh runtime from the current configuration on disk.
///
/// Returning a `Result` rather than mutating is the whole point: the caller only swaps on
/// success, so a broken config leaves the running proxy untouched.
pub type RuntimeBuilder = Arc<dyn Fn() -> Result<Runtime, String> + Send + Sync + 'static>;

#[derive(Clone)]
struct ManagementState {
    runtime: Arc<RuntimeHandle>,
    stats: Arc<SessionStats>,
    build: RuntimeBuilder,
    token: Option<Arc<str>>,
}

#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    #[error("binding the management listener on {listen}: {source}")]
    Bind {
        listen: String,
        #[source]
        source: std::io::Error,
    },
}

/// Serve the management API until the process ends.
pub async fn serve(
    listen: &str,
    runtime: Arc<RuntimeHandle>,
    stats: Arc<SessionStats>,
    build: RuntimeBuilder,
    token: Option<String>,
) -> Result<(), ManagementError> {
    if token.is_none() {
        // Reload replaces the policy. An unauthenticated one is a way to disable the proxy.
        tracing::warn!(
            "the management API has no API key: anyone who can reach {listen} can replace \
             the running policy. Set `management.api_key_env`."
        );
    }

    let state =
        ManagementState { runtime, stats, build, token: token.map(|t| Arc::from(t.as_str())) };

    let app = Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/v1/sessions", get(sessions))
        .route("/v1/reload", post(reload))
        .route("/v1/metrics", get(metrics))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .map_err(|source| ManagementError::Bind { listen: listen.to_string(), source })?;

    tracing::info!(listen = %listener.local_addr().map_err(|source| ManagementError::Bind {
        listen: listen.to_string(),
        source,
    })?, "management api listening");

    axum::serve(listener, app)
        .await
        .map_err(|source| ManagementError::Bind { listen: listen.to_string(), source })
}

/// Constant-time bearer check, so a token cannot be recovered by timing.
fn authorised(state: &ManagementState, headers: &axum::http::HeaderMap) -> bool {
    let Some(expected) = &state.token else {
        return true;
    };
    let Some(offered) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return false;
    };
    if offered.len() != expected.len() {
        return false;
    }
    offered.bytes().zip(expected.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn unauthorised() -> axum::response::Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({ "error": "unauthorized" }))).into_response()
}

async fn healthz(State(state): State<ManagementState>) -> impl IntoResponse {
    // Deliberately unauthenticated: a health check that needs a credential is one that will
    // be configured wrong, and this reveals nothing an attacker could not learn by connecting.
    let runtime = state.runtime.load();
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "generation": state.runtime.generation(),
        "profiles": runtime.chains.keys().map(|k| &**k).collect::<Vec<_>>(),
        "intercepting": runtime.tls.is_some(),
        // Surfaced here because a proxy left in warn mode looks healthy in every other way.
        "warn_only_profiles": runtime.warn_only_profiles(),
    }))
}

async fn sessions(
    State(state): State<ManagementState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !authorised(&state, &headers) {
        return unauthorised();
    }
    let rows: Vec<_> = state
        .stats
        .by_session()
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "session": row.key,
                "allowed": row.allowed,
                "denied": row.denied,
                "would_deny": row.would_deny,
            })
        })
        .collect();
    Json(serde_json::json!({ "sessions": rows })).into_response()
}

/// Prometheus scrape endpoint.
///
/// Unauthenticated like `healthz`: a scrape target that needs a credential is one that gets
/// configured wrong, and these are counts rather than content.
async fn metrics(State(state): State<ManagementState>) -> impl IntoResponse {
    ([(axum::http::header::CONTENT_TYPE, "text/plain; version=0.0.4")], state.stats.prometheus())
}

async fn reload(
    State(state): State<ManagementState>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    if !authorised(&state, &headers) {
        return unauthorised();
    }

    match (state.build)() {
        Ok(runtime) => {
            let profiles: Vec<String> = runtime.chains.keys().map(|k| k.to_string()).collect();
            let warn_only: Vec<String> =
                runtime.warn_only_profiles().into_iter().map(String::from).collect();
            state.runtime.store(runtime);

            tracing::info!(
                generation = state.runtime.generation(),
                ?profiles,
                "configuration reloaded"
            );
            Json(serde_json::json!({
                "status": "reloaded",
                "generation": state.runtime.generation(),
                "profiles": profiles,
                "warn_only_profiles": warn_only,
            }))
            .into_response()
        }
        Err(message) => {
            // The running pipeline is untouched. Saying so explicitly matters: an operator
            // reading a failed reload needs to know whether they are now unprotected.
            tracing::error!(%message, "reload failed; keeping the running configuration");
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "status": "rejected",
                    "error": message,
                    "generation": state.runtime.generation(),
                    "note": "the previously loaded configuration is still in effect",
                })),
            )
                .into_response()
        }
    }
}
