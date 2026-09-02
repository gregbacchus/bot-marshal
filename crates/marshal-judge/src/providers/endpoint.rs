//! Where a provider's API actually lives.
//!
//! Every provider defaults to the real vendor API, but a self-hosted or compatible server —
//! Azure OpenAI, a local vLLM/Ollama instance, OpenRouter, an internal gateway — is a very
//! normal thing to want instead, and the config-time-only cost of supporting it is small: the
//! default host and TLS-or-not decision come from a parsed URL rather than a compile-time
//! constant.
//!
//! Deliberately not the `url` crate: the shape needed here is `scheme://host[:port]`, nothing
//! else — no path, no query, no userinfo — and that is a dozen lines to parse by hand rather
//! than a dependency to pull in for it.

use std::sync::Arc;

use bytes::Bytes;
use hyper::Request;
use tokio::io::{AsyncRead, AsyncWrite};

use super::ProviderError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    pub https: bool,
    pub host: String,
    pub port: u16,
}

impl Endpoint {
    /// Parse `scheme://host[:port]`. `https` unless the scheme says otherwise, so a bare
    /// mistake (forgetting the scheme) fails safe rather than silently connecting in plain
    /// text — the one exception being `http://`, which has to be spelled out to be chosen.
    pub fn parse(url: &str) -> Result<Self, ProviderError> {
        let (scheme, rest) =
            url.split_once("://").ok_or_else(|| ProviderError::InvalidBaseUrl(url.to_owned()))?;
        let https = match scheme {
            "https" => true,
            "http" => false,
            other => {
                return Err(ProviderError::InvalidBaseUrl(format!(
                    "{url}: unsupported scheme `{other}`, expected http or https"
                )));
            }
        };

        // Nothing past the authority is meaningful here: the path is provider-specific and
        // appended separately, and a base URL carrying one is very likely a copy-paste
        // mistake worth catching rather than silently ignoring.
        if rest.contains('/') {
            return Err(ProviderError::InvalidBaseUrl(format!(
                "{url}: base_url must be `scheme://host[:port]` with no path"
            )));
        }

        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                let port = p
                    .parse()
                    .map_err(|_| ProviderError::InvalidBaseUrl(format!("{url}: bad port")))?;
                (h.to_owned(), port)
            }
            _ if !rest.is_empty() => (rest.to_owned(), if https { 443 } else { 80 }),
            _ => return Err(ProviderError::InvalidBaseUrl(url.to_owned())),
        };

        Ok(Self { https, host, port })
    }

    pub fn https(host: impl Into<String>) -> Self {
        Self { https: true, host: host.into(), port: 443 }
    }

    pub fn uri(&self, path: &str) -> String {
        format!(
            "{}://{}:{}{}",
            if self.https { "https" } else { "http" },
            self.host,
            self.port,
            path
        )
    }
}

/// Unifies a plain and a TLS-wrapped connection behind one type, so the rest of the client
/// does not need to know which one it got. `Box<dyn AsyncConn>` gets `AsyncRead`/`AsyncWrite`
/// for free from tokio's blanket impls over boxed trait objects.
pub(crate) trait AsyncConn: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncConn for T {}

impl Endpoint {
    pub(crate) async fn connect(
        &self,
        tls_config: &Arc<rustls::ClientConfig>,
    ) -> Result<Box<dyn AsyncConn>, ProviderError> {
        let addr = tokio::net::lookup_host((self.host.as_str(), self.port))
            .await
            .map_err(ProviderError::Resolve)?
            .next()
            .ok_or_else(|| {
                ProviderError::Resolve(std::io::Error::other(format!(
                    "no address for {}",
                    self.host
                )))
            })?;
        let tcp = tokio::net::TcpStream::connect(addr).await.map_err(ProviderError::Connect)?;

        if !self.https {
            return Ok(Box::new(tcp));
        }

        let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| ProviderError::InvalidBaseUrl(format!("bad hostname: {}", self.host)))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::clone(tls_config))
            .connect(server_name, tcp)
            .await
            .map_err(ProviderError::Tls)?;
        Ok(Box::new(tls))
    }
}

/// Connect, send one JSON request, parse one JSON response. Every provider so far is a
/// single POST-and-parse over HTTP(S), so this is the whole client: resolve, connect,
/// optionally TLS, send, check status, parse. Connection reuse is an optimisation deferred
/// rather than complexity carried from the start — the judge is called rarely relative to
/// ordinary proxy traffic.
pub(crate) async fn post_json(
    endpoint: &Endpoint,
    tls_config: &Arc<rustls::ClientConfig>,
    req: Request<http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>>,
) -> Result<serde_json::Value, ProviderError> {
    use http_body_util::BodyExt;

    let conn = endpoint.connect(tls_config).await?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(conn)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let resp = sender.send_request(req).await?;
    let status = resp.status();
    let body = resp.into_body().collect().await?.to_bytes();

    if !status.is_success() {
        return Err(ProviderError::Status {
            status: status.as_u16(),
            body: String::from_utf8_lossy(&body).into_owned(),
        });
    }

    serde_json::from_slice(&body).map_err(ProviderError::MalformedVerdict)
}

/// Build a JSON POST request against this endpoint.
pub(crate) fn json_post_request(
    endpoint: &Endpoint,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: serde_json::Value,
) -> Request<http_body_util::combinators::BoxBody<Bytes, std::convert::Infallible>> {
    use http_body_util::{BodyExt, Full};

    let bytes = serde_json::to_vec(&body).expect("judge request body serialises");
    let mut builder = Request::builder()
        .method("POST")
        .uri(endpoint.uri(path))
        .header("host", &endpoint.host)
        .header("content-type", "application/json");
    for (name, value) in extra_headers {
        builder = builder.header(*name, *value);
    }
    builder
        .body(
            Full::new(Bytes::from(bytes)).map_err(|e: std::convert::Infallible| match e {}).boxed(),
        )
        .expect("well-formed request")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_bare_https_host() {
        let e = Endpoint::parse("https://api.anthropic.com").unwrap();
        assert_eq!(e, Endpoint { https: true, host: "api.anthropic.com".into(), port: 443 });
    }

    #[test]
    fn parses_http_with_an_explicit_port_for_a_local_server() {
        // The common shape for a self-hosted OpenAI-compatible server, e.g. Ollama.
        let e = Endpoint::parse("http://localhost:11434").unwrap();
        assert_eq!(e, Endpoint { https: false, host: "localhost".into(), port: 11434 });
    }

    #[test]
    fn defaults_the_port_from_the_scheme() {
        assert_eq!(Endpoint::parse("http://example.internal").unwrap().port, 80);
        assert_eq!(Endpoint::parse("https://example.internal").unwrap().port, 443);
    }

    #[test]
    fn a_missing_scheme_is_rejected_rather_than_assumed() {
        // Silently assuming https (or worse, http) for a bare host would be a surprising
        // default in either direction; better to say so.
        assert!(Endpoint::parse("api.anthropic.com").is_err());
    }

    #[test]
    fn an_unsupported_scheme_is_rejected() {
        assert!(Endpoint::parse("ftp://example.com").is_err());
    }

    #[test]
    fn a_path_on_the_base_url_is_rejected_rather_than_silently_ignored() {
        // The path is provider-specific and appended separately; a base_url carrying one is
        // very likely a copy-paste mistake, and silently dropping it would hide that.
        assert!(Endpoint::parse("https://api.anthropic.com/v1/messages").is_err());
    }

    #[test]
    fn uri_builds_the_full_request_url() {
        let e = Endpoint::parse("https://api.openai.com").unwrap();
        assert_eq!(e.uri("/v1/chat/completions"), "https://api.openai.com:443/v1/chat/completions");
    }
}
