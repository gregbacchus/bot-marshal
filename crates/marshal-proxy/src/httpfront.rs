//! HTTP proxy front-end: `CONNECT` tunnels and absolute-form requests.
//!
//! Deliberately a hand-rolled request-head reader rather than a full HTTP server. At M1 the
//! proxy does not interpret HTTP beyond the request line and `Host` — bodies are copied
//! verbatim — and using a real HTTP stack here would mean parsing, re-serialising, and
//! subtly changing traffic we have promised only to observe. That changes in M2 when TLS is
//! terminated and the pipeline genuinely needs structured requests.

use marshal_core::Authority;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Refuse a request head larger than this. Prevents a client from making us buffer without
/// bound before any policy has run.
const MAX_HEAD_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum HttpError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed request line")]
    MalformedRequestLine,
    #[error("request head exceeded {MAX_HEAD_BYTES} bytes")]
    HeadTooLarge,
    #[error("cannot determine the target host; absolute-form URI or Host header required")]
    NoHost,
    #[error("unsupported URI form: {0}")]
    UnsupportedUri(String),
}

/// A parsed proxy request.
#[derive(Debug)]
pub struct ProxyRequest {
    pub authority: Authority,
    pub method: String,
    /// Path and query, origin-form. Empty for `CONNECT`.
    pub path: String,
    /// The complete head as received, so an allowed plaintext request can be replayed
    /// upstream without us having re-serialised (and possibly altered) it.
    pub raw_head: Vec<u8>,
    pub is_connect: bool,
    /// `Proxy-Authorization`, when present. Selects a session.
    pub proxy_auth: Option<marshal_core::Credential>,
}

/// Read and parse the request head. `first_byte` is the byte already consumed by the sniffer.
pub async fn read_request<S>(
    stream: &mut BufReader<S>,
    first_byte: u8,
) -> Result<ProxyRequest, HttpError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut head = vec![first_byte];
    loop {
        let before = head.len();
        let n = stream.read_until(b'\n', &mut head).await?;
        if n == 0 {
            return Err(HttpError::MalformedRequestLine);
        }
        if head.len() > MAX_HEAD_BYTES {
            return Err(HttpError::HeadTooLarge);
        }
        // Blank line terminates the head.
        if head[before..].iter().all(|b| *b == b'\r' || *b == b'\n') && head.len() > before {
            break;
        }
    }

    let text = String::from_utf8_lossy(&head).into_owned();
    let mut lines = text.split("\r\n").filter(|l| !l.is_empty());
    let request_line = lines.next().ok_or(HttpError::MalformedRequestLine)?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().ok_or(HttpError::MalformedRequestLine)?.to_owned();
    let target = parts.next().ok_or(HttpError::MalformedRequestLine)?;

    let headers: Vec<(&str, &str)> =
        lines.filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim(), v.trim()))).collect();

    let host_header =
        headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")).map(|(_, v)| (*v).to_owned());

    let proxy_auth = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
        .and_then(|(_, v)| parse_basic(v));

    let is_connect = method.eq_ignore_ascii_case("CONNECT");

    let (authority, path) = if is_connect {
        // authority-form: host:port
        (parse_authority(target, 443)?, String::new())
    } else if let Some(rest) =
        target.strip_prefix("http://").or_else(|| target.strip_prefix("HTTP://"))
    {
        let (auth, path) = match rest.find('/') {
            Some(i) => (&rest[..i], rest[i..].to_owned()),
            None => (rest, "/".to_owned()),
        };
        (parse_authority(auth, 80)?, path)
    } else if target.starts_with("https://") {
        // A client that sends an absolute https:// URI to a proxy is not using CONNECT and
        // expects us to originate TLS. That is M2 territory; refuse clearly rather than
        // silently tunnelling plaintext.
        return Err(HttpError::UnsupportedUri(target.to_owned()));
    } else {
        // origin-form: only meaningful with a Host header, i.e. transparent interception.
        let host = host_header.clone().ok_or(HttpError::NoHost)?;
        (parse_authority(&host, 80)?, target.to_owned())
    };

    Ok(ProxyRequest { authority, method, path, raw_head: head, is_connect, proxy_auth })
}

/// Parse `Proxy-Authorization: Basic <base64(user:pass)>`.
///
/// Only Basic is supported. Digest buys nothing here: the credential is client-asserted
/// either way, and the connection to the proxy is local or already trusted.
fn parse_basic(value: &str) -> Option<marshal_core::Credential> {
    let encoded = value.strip_prefix("Basic ").or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64_decode(encoded.trim())?;
    let text = String::from_utf8(decoded).ok()?;
    let (user, password) = text.split_once(':')?;
    Some(marshal_core::Credential { user: user.to_owned(), password: password.to_owned() })
}

/// Minimal standard-alphabet base64 decoder. Pulling in a dependency for one header would be
/// more surface than the twenty lines it replaces.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in input.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn parse_authority(s: &str, default_port: u16) -> Result<Authority, HttpError> {
    let s = s.trim();
    // IPv6 literal: [::1]:443
    if let Some(rest) = s.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or(HttpError::MalformedRequestLine)?;
        let port = match tail.strip_prefix(':') {
            Some(p) => p.parse().map_err(|_| HttpError::MalformedRequestLine)?,
            None => default_port,
        };
        return Ok(Authority { host: host.to_ascii_lowercase(), port });
    }
    match s.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok(Authority {
            host: host.to_ascii_lowercase(),
            port: port.parse().map_err(|_| HttpError::MalformedRequestLine)?,
        }),
        _ if !s.is_empty() => Ok(Authority { host: s.to_ascii_lowercase(), port: default_port }),
        _ => Err(HttpError::NoHost),
    }
}

/// Send a refusal the agent can act on.
///
/// The body is JSON because the client is a program: a bare 403 makes agents retry-loop,
/// whereas a structured reason lets one report *why* it was blocked and what to change.
pub async fn write_denial<S>(
    stream: &mut S,
    reason: &marshal_core::Reason,
    session: &str,
    profile: &str,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let body = serde_json::json!({
        "error": "egress_denied",
        "proxy": "bot-marshal",
        "session": session,
        "profile": profile,
        "reason": reason,
    });
    let body = serde_json::to_vec_pretty(&body).unwrap_or_else(|_| b"{}".to_vec());

    let head = format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Proxy-Agent: bot-marshal\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}

pub async fn write_status<S>(stream: &mut S, status: &str, detail: &str) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let body = serde_json::json!({ "error": detail, "proxy": "bot-marshal" });
    let body = serde_json::to_vec(&body).unwrap_or_default();
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Proxy-Agent: bot-marshal\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    async fn parse(raw: &[u8]) -> Result<ProxyRequest, HttpError> {
        let (mut client, server) = tokio::io::duplex(8192);
        // The write is spawned rather than awaited: a head larger than the duplex buffer
        // would otherwise block here forever, before the reader that drains it exists.
        let raw = raw.to_vec();
        tokio::spawn(async move {
            let _ = client.write_all(&raw).await;
        });
        let mut r = BufReader::new(server);
        let first = {
            use tokio::io::AsyncReadExt;
            let mut b = [0u8; 1];
            r.read_exact(&mut b).await.unwrap();
            b[0]
        };
        read_request(&mut r, first).await
    }

    #[test]
    fn decodes_basic_credentials() {
        // "agent-a:hunter2"
        let cred = parse_basic("Basic YWdlbnQtYTpodW50ZXIy").unwrap();
        assert_eq!(cred.user, "agent-a");
        assert_eq!(cred.password, "hunter2");

        assert!(parse_basic("Bearer xyz").is_none());
        assert!(parse_basic("Basic !!!not-base64!!!").is_none());
        // No colon means no credential, rather than a user with an empty password.
        assert!(parse_basic("Basic bm9jb2xvbg==").is_none());
    }

    #[tokio::test]
    async fn parses_proxy_authorization_from_the_head() {
        let r = parse(
            b"CONNECT api.github.com:443 HTTP/1.1\r\n\
              Proxy-Authorization: Basic YWdlbnQtYTpodW50ZXIy\r\n\r\n",
        )
        .await
        .unwrap();
        let cred = r.proxy_auth.expect("credential parsed");
        assert_eq!(cred.user, "agent-a");
    }

    #[tokio::test]
    async fn parses_connect() {
        let r = parse(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
            .await
            .unwrap();
        assert!(r.is_connect);
        assert_eq!(r.authority.host, "api.github.com");
        assert_eq!(r.authority.port, 443);
    }

    #[tokio::test]
    async fn connect_without_a_port_defaults_to_443() {
        let r = parse(b"CONNECT api.github.com HTTP/1.1\r\n\r\n").await.unwrap();
        assert_eq!(r.authority.port, 443);
    }

    #[tokio::test]
    async fn parses_absolute_form() {
        let r = parse(b"GET http://example.com/a/b?c=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        assert!(!r.is_connect);
        assert_eq!(r.authority.host, "example.com");
        assert_eq!(r.authority.port, 80);
        assert_eq!(r.path, "/a/b?c=1");
    }

    #[tokio::test]
    async fn parses_origin_form_via_host_header() {
        let r = parse(b"GET /zen HTTP/1.1\r\nHost: api.github.com\r\n\r\n").await.unwrap();
        assert_eq!(r.authority.host, "api.github.com");
        assert_eq!(r.path, "/zen");
    }

    #[tokio::test]
    async fn parses_ipv6_authority() {
        let r = parse(b"CONNECT [2606:4700::1111]:443 HTTP/1.1\r\n\r\n").await.unwrap();
        assert_eq!(r.authority.host, "2606:4700::1111");
        assert_eq!(r.authority.port, 443);
    }

    #[tokio::test]
    async fn origin_form_without_host_is_refused() {
        assert!(matches!(parse(b"GET /zen HTTP/1.1\r\n\r\n").await, Err(HttpError::NoHost)));
    }

    #[tokio::test]
    async fn oversized_head_is_refused() {
        let mut raw = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..5000 {
            raw.extend(format!("X-Pad-{i}: {}\r\n", "a".repeat(64)).as_bytes());
        }
        raw.extend(b"\r\n");
        assert!(matches!(parse(&raw).await, Err(HttpError::HeadTooLarge)));
    }
}
