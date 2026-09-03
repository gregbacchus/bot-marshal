//! One request, one response, no connection reuse.
//!
//! This is the whole client marshal uses for calls it makes as *itself* — an LLM judge, an
//! OAuth2 token endpoint. Those are rare relative to proxied traffic, so pooling is an
//! optimisation deferred rather than complexity carried from the start.
//!
//! Two layers on purpose. [`send`] returns whatever came back, status and all, because an
//! OAuth2 error is a structured JSON body on a `400` and throwing it away loses the
//! `error_description` an operator needs. [`post_json`] adds the status check on top, for
//! callers where a non-2xx really is just a failure.

use std::sync::Arc;

use bytes::Bytes;
use http::StatusCode;
use http_body_util::{BodyExt, Full};
use hyper::Request;

use crate::endpoint::Endpoint;
use crate::error::HttpError;
use crate::guard::UpstreamGuard;

/// A few hundred bytes of JSON is the expected shape of every response this client reads; an
/// endpoint sending megabytes has nothing legitimate to say. Capped independently of any
/// timeout — a slow trickle under this size still completes within a timeout, and this exists
/// for the orthogonal case of a response that never stops sending.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

pub type ClientBody = http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>;

fn body_from(bytes: Vec<u8>) -> ClientBody {
    Full::new(Bytes::from(bytes)).map_err(|e: std::convert::Infallible| match e {}).boxed()
}

/// Connect, send one request, read one capped response. The status is returned rather than
/// checked, so the caller decides what a non-2xx means.
pub async fn send(
    endpoint: &Endpoint,
    tls_config: &Arc<rustls::ClientConfig>,
    guard: Option<&UpstreamGuard>,
    req: Request<ClientBody>,
) -> Result<(StatusCode, Bytes), HttpError> {
    let conn = endpoint.connect(tls_config, guard).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(conn)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender.send_request(req).await?;
    let status = resp.status();

    let mut body = bytes::BytesMut::new();
    let mut incoming = resp.into_body();
    while let Some(frame) = incoming.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            if body.len() + data.len() > MAX_RESPONSE_BYTES {
                return Err(HttpError::ResponseTooLarge { limit: MAX_RESPONSE_BYTES });
            }
            body.extend_from_slice(data);
        }
    }
    Ok((status, body.freeze()))
}

/// [`send`], plus "a non-2xx is an error" and "the body is JSON".
pub async fn post_json(
    endpoint: &Endpoint,
    tls_config: &Arc<rustls::ClientConfig>,
    guard: Option<&UpstreamGuard>,
    req: Request<ClientBody>,
) -> Result<serde_json::Value, HttpError> {
    let (status, body) = send(endpoint, tls_config, guard, req).await?;
    if !status.is_success() {
        return Err(HttpError::Status {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }
    serde_json::from_slice(&body).map_err(HttpError::MalformedJson)
}

/// POST a form-encoded body and parse the reply as JSON, **keeping the status**.
///
/// This is the OAuth2 token endpoint's shape exactly: the request is
/// `application/x-www-form-urlencoded` ([RFC 6749 §4.1.3](https://www.rfc-editor.org/rfc/rfc6749)),
/// and the reply is JSON whether it succeeded or failed — a failure carries `error` and
/// `error_description` on a 400, which is the most useful thing an operator can be told.
pub async fn post_form(
    endpoint: &Endpoint,
    tls_config: &Arc<rustls::ClientConfig>,
    guard: Option<&UpstreamGuard>,
    path: &str,
    extra_headers: &[(&str, &str)],
    form: &str,
) -> Result<(StatusCode, serde_json::Value), HttpError> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(endpoint.uri(path))
        .header("host", &endpoint.host)
        .header("content-type", "application/x-www-form-urlencoded")
        .header("accept", "application/json");
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    let req = builder
        .body(body_from(form.as_bytes().to_vec()))
        .map_err(|e| HttpError::InvalidUrl(e.to_string()))?;

    let (status, body) = send(endpoint, tls_config, guard, req).await?;
    // An empty or non-JSON body on an error status is a real possibility (a gateway in front
    // of the auth server, say). Surface it as the status error rather than as a parse
    // failure, because the status is the fact that matters.
    let json = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) if status.is_success() => return Err(HttpError::MalformedJson(e)),
        Err(_) => {
            return Err(HttpError::Status {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
    };
    Ok((status, json))
}

/// Build a JSON POST against this endpoint.
pub fn json_post_request(
    endpoint: &Endpoint,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: serde_json::Value,
) -> Request<ClientBody> {
    let bytes = serde_json::to_vec(&body).expect("a serde_json::Value serialises");
    let mut builder = Request::builder()
        .method("POST")
        .uri(endpoint.uri(path))
        .header("host", &endpoint.host)
        .header("content-type", "application/json");
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    builder.body(body_from(bytes)).expect("well-formed request")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    /// A one-shot server that drains the request and replies with exactly `response`.
    async fn one_shot(response: String) -> Endpoint {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
            let _ = stream.write_all(response.as_bytes()).await;
        });
        Endpoint { https: false, host: "127.0.0.1".into(), port }
    }

    fn http_response(status: &str, body: &str) -> String {
        format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n\r\n{body}", body.len())
    }

    #[tokio::test]
    async fn a_response_over_the_size_cap_is_refused_rather_than_buffered_without_bound() {
        let oversized = "x".repeat(MAX_RESPONSE_BYTES + 1024);
        let endpoint = one_shot(http_response("200 OK", &oversized)).await;
        let req = json_post_request(&endpoint, "/", &[], serde_json::json!({}));
        let result = post_json(&endpoint, &crate::tls::default_tls_config(), None, req).await;
        assert!(
            matches!(result, Err(HttpError::ResponseTooLarge { .. })),
            "expected ResponseTooLarge, got {result:?}"
        );
    }

    #[tokio::test]
    async fn post_form_keeps_the_body_of_an_error_status() {
        // The whole reason post_form exists: RFC 6749 §5.2 puts the useful detail in a JSON
        // body on a 400, and a client that only reports "400" throws away the diagnosis.
        let endpoint = one_shot(http_response(
            "400 Bad Request",
            r#"{"error":"invalid_client","error_description":"unknown client"}"#,
        ))
        .await;
        let (status, json) = post_form(
            &endpoint,
            &crate::tls::default_tls_config(),
            None,
            "/token",
            &[],
            "grant_type=client_credentials",
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(json["error"], "invalid_client");
        assert_eq!(json["error_description"], "unknown client");
    }

    #[tokio::test]
    async fn post_form_reports_a_non_json_error_body_as_a_status_error() {
        let endpoint = one_shot(http_response("502 Bad Gateway", "<html>nope</html>")).await;
        let err = post_form(
            &endpoint,
            &crate::tls::default_tls_config(),
            None,
            "/token",
            &[],
            "grant_type=client_credentials",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, HttpError::Status { status: 502, .. }), "{err}");
    }

    #[tokio::test]
    async fn the_guard_refuses_a_blocked_destination_before_connecting() {
        // marshal's own outbound calls are subject to ADR-0010 when a guard is supplied: the
        // token endpoint comes from config, so a config that points it at link-local is an
        // SSRF, not a feature.
        let guard = UpstreamGuard::new(["169.254.0.0/16"], false).unwrap();
        let endpoint = Endpoint { https: false, host: "169.254.169.254".into(), port: 80 };
        let err =
            post_form(&endpoint, &crate::tls::default_tls_config(), Some(&guard), "/", &[], "")
                .await
                .unwrap_err();
        assert!(matches!(err, HttpError::Blocked(_)), "{err}");
    }
}
