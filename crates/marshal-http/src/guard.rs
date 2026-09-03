//! The upstream guard: SSRF and DNS-rebinding protection.
//!
//! This is the most important correctness detail in the proxy. The rule it enforces:
//!
//! > Resolve the hostname ourselves, check **every** resulting address, then connect to a
//! > checked address — never re-resolve between the check and the connect.
//!
//! An implementation that checks a hostname and then hands the *name* to `TcpStream::connect`
//! has a second, unchecked resolution in it, and a hostile DNS server only has to answer
//! differently the second time. The guard therefore returns connected sockets, not addresses,
//! so there is no way for a caller to accidentally reintroduce the gap.

use std::net::{IpAddr, SocketAddr};

use ipnet::IpNet;
use marshal_core::Authority;
use tokio::net::TcpStream;

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("cannot resolve `{host}`: {source}")]
    Resolve {
        host: String,
        #[source]
        source: std::io::Error,
    },

    #[error("`{host}` did not resolve to any address")]
    NoAddresses { host: String },

    #[error("`{host}` resolves to {addr}, which is blocked by `{rule}`")]
    Blocked { host: String, addr: IpAddr, rule: String },

    #[error("connecting to {addr} for `{host}`: {source}")]
    Connect {
        host: String,
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct UpstreamGuard {
    deny: Vec<IpNet>,
    allow_private: bool,
}

impl UpstreamGuard {
    pub fn new(
        deny_cidrs: impl IntoIterator<Item = impl AsRef<str>>,
        allow_private: bool,
    ) -> Result<Self, ipnet::AddrParseError> {
        let deny = deny_cidrs
            .into_iter()
            .map(|c| c.as_ref().parse::<IpNet>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { deny, allow_private })
    }

    /// Why this address is refused, or `None` if it is acceptable.
    pub fn check(&self, addr: IpAddr) -> Option<String> {
        if let Some(net) = self.deny.iter().find(|n| n.contains(&addr)) {
            return Some(net.to_string());
        }
        if !self.allow_private && is_private(addr) {
            return Some("upstream.allow_private=false".to_owned());
        }
        None
    }

    /// Resolve, check every answer, then connect to one of the checked addresses.
    ///
    /// If *any* resolved address is blocked the whole attempt is refused, rather than quietly
    /// connecting to whichever answer happened to be acceptable. A name that resolves to both
    /// a public address and a metadata endpoint is a rebinding signal, not a menu.
    pub async fn connect(&self, authority: &Authority) -> Result<TcpStream, GuardError> {
        let host = authority.host.as_str();

        let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, authority.port)]
        } else {
            tokio::net::lookup_host((host, authority.port))
                .await
                .map_err(|source| GuardError::Resolve { host: host.to_owned(), source })?
                .collect()
        };

        if addrs.is_empty() {
            return Err(GuardError::NoAddresses { host: host.to_owned() });
        }

        for addr in &addrs {
            if let Some(rule) = self.check(addr.ip()) {
                return Err(GuardError::Blocked { host: host.to_owned(), addr: addr.ip(), rule });
            }
        }

        // Connect to the addresses we just checked, by value. No name crosses this boundary.
        let mut last = None;
        for addr in &addrs {
            match TcpStream::connect(addr).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(source) => {
                    last = Some(GuardError::Connect { host: host.to_owned(), addr: *addr, source });
                }
            }
        }
        Err(last.expect("addrs is non-empty"))
    }
}

/// Addresses that are not routable on the public internet, and so are never a legitimate
/// egress destination for an agent unless explicitly permitted.
fn is_private(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // 100.64.0.0/10, carrier-grade NAT — also used by container runtimes.
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link-local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // v4-mapped: judge by the embedded v4 address, or the guard is trivially
                // bypassed by writing ::ffff:169.254.169.254
                || v6.to_ipv4_mapped().map(|v4| is_private(IpAddr::V4(v4))).unwrap_or(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> UpstreamGuard {
        UpstreamGuard::new(["169.254.0.0/16", "127.0.0.0/8", "::1/128"], false).unwrap()
    }

    #[test]
    fn blocks_cloud_metadata_endpoint() {
        assert!(guard().check("169.254.169.254".parse().unwrap()).is_some());
    }

    #[test]
    fn blocks_loopback_and_rfc1918() {
        let g = guard();
        assert!(g.check("127.0.0.1".parse().unwrap()).is_some());
        assert!(g.check("10.1.2.3".parse().unwrap()).is_some());
        assert!(g.check("192.168.1.1".parse().unwrap()).is_some());
        assert!(g.check("172.16.0.1".parse().unwrap()).is_some());
    }

    #[test]
    fn blocks_v4_mapped_bypass() {
        // Writing the metadata address as an IPv6-mapped literal must not evade the check.
        let g = guard();
        assert!(g.check("::ffff:169.254.169.254".parse().unwrap()).is_some());
        assert!(g.check("::ffff:127.0.0.1".parse().unwrap()).is_some());
    }

    #[test]
    fn blocks_ipv6_unique_local_and_link_local() {
        let g = guard();
        assert!(g.check("fd00::1".parse().unwrap()).is_some());
        assert!(g.check("fe80::1".parse().unwrap()).is_some());
    }

    #[test]
    fn allows_public_addresses() {
        let g = guard();
        assert!(g.check("140.82.121.4".parse().unwrap()).is_none());
        assert!(g.check("2606:4700::1111".parse().unwrap()).is_none());
    }

    #[test]
    fn allow_private_opens_rfc1918_but_not_the_denylist() {
        let g = UpstreamGuard::new(["169.254.0.0/16"], true).unwrap();
        assert!(g.check("10.1.2.3".parse().unwrap()).is_none());
        // An explicit deny_cidr still wins over allow_private.
        assert!(g.check("169.254.169.254".parse().unwrap()).is_some());
    }

    #[tokio::test]
    async fn connect_to_a_blocked_literal_is_refused() {
        let g = guard();
        let err =
            g.connect(&Authority { host: "169.254.169.254".into(), port: 80 }).await.unwrap_err();
        assert!(matches!(err, GuardError::Blocked { .. }), "{err}");
    }
}
