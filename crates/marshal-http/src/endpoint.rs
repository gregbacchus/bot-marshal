//! Where a call marshal makes for itself actually goes.
//!
//! Deliberately not the `url` crate: the shape needed here is `scheme://host[:port]`, nothing
//! else — no path, no query, no userinfo — and that is a dozen lines to parse by hand rather
//! than a dependency to pull in for it.

use std::sync::Arc;

use marshal_core::Authority;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::HttpError;
use crate::guard::UpstreamGuard;

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
    pub fn parse(url: &str) -> Result<Self, HttpError> {
        let (scheme, rest) =
            url.split_once("://").ok_or_else(|| HttpError::InvalidUrl(url.to_owned()))?;
        let https = match scheme {
            "https" => true,
            "http" => false,
            other => {
                return Err(HttpError::InvalidUrl(format!(
                    "{url}: unsupported scheme `{other}`, expected http or https"
                )));
            }
        };

        // Nothing past the authority is meaningful here: the path is caller-specific and
        // appended separately, and a base URL carrying one is very likely a copy-paste
        // mistake worth catching rather than silently ignoring.
        if rest.contains('/') {
            return Err(HttpError::InvalidUrl(format!(
                "{url}: expected `scheme://host[:port]` with no path"
            )));
        }

        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
                let port =
                    p.parse().map_err(|_| HttpError::InvalidUrl(format!("{url}: bad port")))?;
                (h.to_owned(), port)
            }
            _ if !rest.is_empty() => (rest.to_owned(), if https { 443 } else { 80 }),
            _ => return Err(HttpError::InvalidUrl(url.to_owned())),
        };

        Ok(Self { https, host, port })
    }

    /// Split a full `scheme://host[:port]/path` URL into the endpoint and the path to request.
    ///
    /// [`Endpoint::parse`] rejects a path because a *base* URL carrying one is a mistake. A
    /// token endpoint is the opposite case: the path is the whole point, and an operator
    /// writes it as one URL rather than as a host and a path in two config keys.
    pub fn parse_with_path(url: &str) -> Result<(Self, String), HttpError> {
        let (scheme, rest) =
            url.split_once("://").ok_or_else(|| HttpError::InvalidUrl(url.to_owned()))?;
        let (authority, path) = match rest.find('/') {
            Some(at) => (&rest[..at], rest[at..].to_owned()),
            None => (rest, "/".to_owned()),
        };
        Ok((Self::parse(&format!("{scheme}://{authority}"))?, path))
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

    pub fn authority(&self) -> Authority {
        Authority { host: self.host.clone(), port: self.port }
    }
}

/// Unifies a plain and a TLS-wrapped connection behind one type, so the rest of the client
/// does not need to know which one it got. `Box<dyn AsyncConn>` gets `AsyncRead`/`AsyncWrite`
/// for free from tokio's blanket impls over boxed trait objects.
pub trait AsyncConn: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncConn for T {}

impl Endpoint {
    /// Connect, optionally through the upstream guard.
    ///
    /// The guard is optional rather than mandatory because marshal's own outbound
    /// destinations are not all the same kind of thing. An OAuth2 token endpoint comes from
    /// config and points at a third party, so it belongs behind the guard. A judge `base_url`
    /// pointing at `http://localhost:11434` is a *supported* configuration (see the module
    /// docs on self-hosted providers), and the guard's default `allow_private=false` would
    /// refuse it. Passing `None` is therefore a real choice, not an omission — but it is a
    /// choice each call site has to make explicitly.
    pub async fn connect(
        &self,
        tls_config: &Arc<rustls::ClientConfig>,
        guard: Option<&UpstreamGuard>,
    ) -> Result<Box<dyn AsyncConn>, HttpError> {
        let tcp = match guard {
            Some(guard) => guard.connect(&self.authority()).await?,
            None => {
                let addr = tokio::net::lookup_host((self.host.as_str(), self.port))
                    .await
                    .map_err(HttpError::Resolve)?
                    .next()
                    .ok_or_else(|| {
                        HttpError::Resolve(std::io::Error::other(format!(
                            "no address for {}",
                            self.host
                        )))
                    })?;
                tokio::net::TcpStream::connect(addr).await.map_err(HttpError::Connect)?
            }
        };

        if !self.https {
            return Ok(Box::new(tcp));
        }

        let server_name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| HttpError::InvalidUrl(format!("bad hostname: {}", self.host)))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::clone(tls_config))
            .connect(server_name, tcp)
            .await
            .map_err(HttpError::Tls)?;
        Ok(Box::new(tls))
    }
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
        // The path is caller-specific and appended separately; a base_url carrying one is
        // very likely a copy-paste mistake, and silently dropping it would hide that.
        assert!(Endpoint::parse("https://api.anthropic.com/v1/messages").is_err());
    }

    #[test]
    fn uri_builds_the_full_request_url() {
        let e = Endpoint::parse("https://api.openai.com").unwrap();
        assert_eq!(e.uri("/v1/chat/completions"), "https://api.openai.com:443/v1/chat/completions");
    }

    #[test]
    fn parse_with_path_splits_a_token_endpoint_url() {
        let (e, path) = Endpoint::parse_with_path("https://auth.example.com/oauth2/token").unwrap();
        assert_eq!(e, Endpoint { https: true, host: "auth.example.com".into(), port: 443 });
        assert_eq!(path, "/oauth2/token");
    }

    #[test]
    fn parse_with_path_keeps_the_port_and_defaults_a_missing_path() {
        let (e, path) = Endpoint::parse_with_path("http://127.0.0.1:8081").unwrap();
        assert_eq!(e.port, 8081);
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_with_path_carries_the_query_string_through() {
        // Some providers put a tenant or version in the query of the token endpoint itself.
        let (_, path) =
            Endpoint::parse_with_path("https://auth.example.com/token?tenant=acme").unwrap();
        assert_eq!(path, "/token?tenant=acme");
    }
}
