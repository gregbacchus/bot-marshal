//! Transparent interception: traffic the client never knew was proxied.
//!
//! Under an nftables/iptables `REDIRECT`, the kernel rewrites the packet's destination to the
//! proxy before the socket ever sees it, so `getpeername`-style information is useless — the
//! destination the client actually asked for is only recoverable from the connection tracking
//! table via `SO_ORIGINAL_DST`.
//!
//! Recovering an address is not enough, though. Policy is written in terms of hostnames, and
//! the address is what DNS happened to return; a proxy that could only see `140.82.121.4`
//! would be back to the coarse filtering the whole project exists to improve on. So the
//! hostname is recovered separately — from the TLS SNI, or the HTTP `Host` header — and the
//! two are cross-checked.

use std::net::SocketAddr;

/// Errors recovering the pre-redirect destination.
#[derive(Debug, thiserror::Error)]
pub enum OriginalDstError {
    #[error("SO_ORIGINAL_DST is unavailable: {0}")]
    Unavailable(#[source] std::io::Error),

    #[error("the connection was not redirected; its destination is the proxy itself")]
    NotRedirected,
}

/// Recover the destination a redirected connection was originally aimed at.
///
/// Linux-only, because `SO_ORIGINAL_DST` is a netfilter feature. Other platforms get a clear
/// error rather than a silently wrong address.
#[cfg(target_os = "linux")]
pub fn original_dst(stream: &tokio::net::TcpStream) -> Result<SocketAddr, OriginalDstError> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let local = stream.local_addr().map_err(OriginalDstError::Unavailable)?;

    // SAFETY: `getsockopt` writes at most `len` bytes into `storage`, which is sized for the
    // largest address family; `len` is initialised to that size and updated by the kernel.
    // `fd` is owned by `stream` and outlives the call. The option is read-only.
    #[allow(unsafe_code)]
    let (storage, len) = unsafe {
        let mut storage: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;

        // The option number is 80 for both families; only the level differs.
        let (level, name) = match local {
            SocketAddr::V4(_) => (libc::SOL_IP, SO_ORIGINAL_DST),
            SocketAddr::V6(_) => (libc::SOL_IPV6, IP6T_SO_ORIGINAL_DST),
        };

        let rc = libc::getsockopt(
            fd,
            level,
            name,
            (&raw mut storage).cast::<libc::c_void>(),
            &raw mut len,
        );
        if rc != 0 {
            return Err(OriginalDstError::Unavailable(std::io::Error::last_os_error()));
        }
        (storage, len)
    };

    let addr = sockaddr_to_socketaddr(&storage, len)
        .ok_or_else(|| OriginalDstError::Unavailable(std::io::Error::other("unknown family")))?;

    // Without a redirect rule the kernel reports the socket's own address, which would send
    // the proxy into a loop connecting to itself.
    if addr == local {
        return Err(OriginalDstError::NotRedirected);
    }
    Ok(addr)
}

#[cfg(not(target_os = "linux"))]
pub fn original_dst(_stream: &tokio::net::TcpStream) -> Result<SocketAddr, OriginalDstError> {
    Err(OriginalDstError::Unavailable(std::io::Error::other(
        "SO_ORIGINAL_DST is a Linux netfilter feature; transparent mode needs Linux",
    )))
}

#[cfg(target_os = "linux")]
const SO_ORIGINAL_DST: libc::c_int = 80;
#[cfg(target_os = "linux")]
const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn sockaddr_to_socketaddr(
    storage: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in>() {
                return None;
            }
            // SAFETY: the family field says this is a sockaddr_in, and the length check above
            // confirms the kernel wrote a whole one.
            let sin = unsafe { *(std::ptr::from_ref(storage).cast::<libc::sockaddr_in>()) };
            Some(SocketAddr::new(
                std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).into(),
                u16::from_be(sin.sin_port),
            ))
        }
        libc::AF_INET6 => {
            if (len as usize) < std::mem::size_of::<libc::sockaddr_in6>() {
                return None;
            }
            // SAFETY: as above, for the v6 layout.
            let sin6 = unsafe { *(std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>()) };
            Some(SocketAddr::new(
                std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr).into(),
                u16::from_be(sin6.sin6_port),
            ))
        }
        _ => None,
    }
}

/// What the proxy could work out about a transparently intercepted connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intercepted {
    /// Where the client was actually trying to go, from the connection tracking table.
    pub destination: SocketAddr,
    /// The name the client used, from TLS SNI or the HTTP `Host` header.
    pub hostname: Option<String>,
    /// Whether the opening bytes looked like TLS.
    pub tls: bool,
}

impl Intercepted {
    /// The authority policy is evaluated against.
    ///
    /// Prefers the hostname, because policy is written in terms of names and an address is
    /// only what DNS happened to return. Falls back to the address, which is correct for a
    /// client that genuinely connected to a bare IP.
    pub fn authority(&self) -> marshal_core::Authority {
        match &self.hostname {
            Some(host) => {
                marshal_core::Authority { host: host.clone(), port: self.destination.port() }
            }
            None => marshal_core::Authority {
                host: self.destination.ip().to_string(),
                port: self.destination.port(),
            },
        }
    }
}

/// Work out the hostname from a connection's opening bytes.
///
/// Reads rather than peeks; the caller must replay these bytes to the upstream, which is what
/// [`crate::rewind::Rewind`] exists for.
pub fn classify(destination: SocketAddr, opening: &[u8]) -> Intercepted {
    if opening.first() == Some(&0x16) {
        return Intercepted {
            destination,
            hostname: crate::sniff::sni_from_client_hello(opening),
            tls: true,
        };
    }
    Intercepted { destination, hostname: host_header(opening), tls: false }
}

/// Pull the `Host` header out of an HTTP request head.
fn host_header(opening: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(opening).ok()?;
    // Only the head; a body could contain anything that looks like a header.
    let head = text.split("\r\n\r\n").next()?;
    for line in head.split("\r\n").skip(1) {
        let (name, value) = line.split_once(':')?;
        if name.trim().eq_ignore_ascii_case("host") {
            let value = value.trim();
            // Strip any port: the real port comes from the destination, and trusting the
            // header's would let a client claim a port it never connected to.
            let host = match value.rsplit_once(':') {
                Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !h.is_empty() => h,
                _ => value,
            };
            return Some(host.trim_matches(['[', ']']).to_ascii_lowercase());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dst() -> SocketAddr {
        "140.82.121.4:443".parse().unwrap()
    }

    #[test]
    fn plaintext_uses_the_host_header() {
        let head = b"GET /zen HTTP/1.1\r\nHost: api.github.com\r\nAccept: */*\r\n\r\n";
        let got = classify(dst(), head);
        assert!(!got.tls);
        assert_eq!(got.hostname.as_deref(), Some("api.github.com"));
        assert_eq!(got.authority().host, "api.github.com");
        // The port comes from the connection, not the header.
        assert_eq!(got.authority().port, 443);
    }

    #[test]
    fn a_host_header_port_is_ignored_in_favour_of_the_real_destination() {
        // Trusting the header's port would let a client claim one it never connected to.
        let head = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let got = classify("93.184.216.34:80".parse().unwrap(), head);
        assert_eq!(got.hostname.as_deref(), Some("example.com"));
        assert_eq!(got.authority().port, 80);
    }

    #[test]
    fn host_headers_are_case_insensitive_and_lowercased() {
        let head = b"GET / HTTP/1.1\r\nHOST: API.GitHub.COM\r\n\r\n";
        assert_eq!(classify(dst(), head).hostname.as_deref(), Some("api.github.com"));
    }

    #[test]
    fn a_body_that_looks_like_a_header_is_not_read() {
        let head = b"POST / HTTP/1.1\r\nHost: real.example.com\r\n\r\nHost: evil.example.com\r\n";
        assert_eq!(classify(dst(), head).hostname.as_deref(), Some("real.example.com"));
    }

    #[test]
    fn without_a_hostname_the_address_is_the_authority() {
        // Correct for a client that genuinely connected to a bare IP, and the honest answer
        // when nothing better is available.
        let got = classify(dst(), b"\x00\x01\x02 not http");
        assert_eq!(got.hostname, None);
        assert_eq!(got.authority().host, "140.82.121.4");
        assert_eq!(got.authority().port, 443);
    }

    #[test]
    fn tls_is_recognised_and_its_sni_extracted() {
        let hello = crate::sniff::tests_support::client_hello("api.github.com");
        let got = classify(dst(), &hello);
        assert!(got.tls);
        assert_eq!(got.hostname.as_deref(), Some("api.github.com"));
    }

    #[test]
    fn a_truncated_client_hello_yields_no_hostname_rather_than_a_wrong_one() {
        let hello = crate::sniff::tests_support::client_hello("api.github.com");
        let got = classify(dst(), &hello[..hello.len() / 2]);
        assert!(got.tls, "it still looks like TLS");
        assert_eq!(got.hostname, None);
        // Falling back to the address is safe; inventing a hostname would not be.
        assert_eq!(got.authority().host, "140.82.121.4");
    }

    #[tokio::test]
    async fn a_connection_that_was_not_redirected_is_reported_as_such() {
        // Without a redirect rule the kernel reports the socket's own address, which would
        // otherwise send the proxy into a loop connecting to itself.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        match original_dst(&server) {
            Err(OriginalDstError::NotRedirected) => {}
            // Some kernels refuse the option outright when conntrack is not involved, which
            // is equally safe: either way the proxy declines rather than looping.
            Err(OriginalDstError::Unavailable(_)) => {}
            Ok(other) => panic!("reported a destination for an unredirected connection: {other}"),
        }
    }
}
