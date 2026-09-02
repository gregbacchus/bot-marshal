//! Deriving the calling user from the connection itself.
//!
//! Uid obtained here is supplied by the kernel and cannot be asserted by the client, which
//! makes it safe to use for policy — unlike a proxy credential, which is only as strong as
//! the secret the agent holds. The limitation is provisioning, not mechanism: uid separates
//! agents only if they actually run as different users.
//!
//! Two sources, in decreasing order of strength:
//!
//! * `SO_PEERCRED` on a Unix-domain listener. The kernel stamps pid/uid/gid at connect time,
//!   so there is no lookup and no race.
//! * A tuple lookup for TCP. `/proc/net/tcp` carries a uid column, so `(ip, port) → uid` is
//!   one read rather than a scan of `/proc/*/fd`.
//!
//! This composes with transparent redirect. REDIRECT rewrites only the destination, so the
//! client's source address and port survive and the tuple still identifies its socket — but
//! only for `nat OUTPUT`. Traffic redirected in `PREROUTING` comes from another namespace,
//! where no local socket exists and `/proc/net/tcp` cannot see the peer's sockets anyway;
//! that case belongs to the source-IP resolver.

use std::net::SocketAddr;

use marshal_core::PeerCred;

/// Look up the peer's uid from `/proc/net/tcp` and `/proc/net/tcp6`.
///
/// `peer` is the remote address of an accepted connection, which is the client's *local*
/// address — so that is the column matched.
pub fn uid_for_tcp_peer(peer: SocketAddr) -> Option<u32> {
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Some(entry) = find_entry(&text, peer)
        {
            return Some(entry.0);
        }
    }
    None
}

/// Uid and socket inode for the peer, if found.
pub fn uid_and_inode_for_tcp_peer(peer: SocketAddr) -> Option<(u32, u64)> {
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(path)
            && let Some(entry) = find_entry(&text, peer)
        {
            return Some(entry);
        }
    }
    None
}

/// Parse a `/proc/net/tcp{,6}` table, returning `(uid, inode)` for the row whose local
/// address matches `peer`.
fn find_entry(table: &str, peer: SocketAddr) -> Option<(u32, u64)> {
    for line in table.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let _slot = fields.next()?;
        let local = fields.next()?;
        let _remote = fields.next()?;
        let _state = fields.next()?;
        let _queues = fields.next()?;
        let _timer = fields.next()?;
        let _retrans = fields.next()?;
        let uid = fields.next()?;
        let _timeout = fields.next()?;
        let inode = fields.next()?;

        let Some((addr, port)) = parse_hex_addr(local) else { continue };
        if port != peer.port() {
            continue;
        }
        // Compare on the address too: two sockets can share a port across interfaces.
        if !same_addr(addr, peer) {
            continue;
        }
        return Some((uid.parse().ok()?, inode.parse().ok()?));
    }
    None
}

/// `/proc/net/tcp` renders addresses as little-endian hex words; `tcp6` as four of them.
fn parse_hex_addr(field: &str) -> Option<(std::net::IpAddr, u16)> {
    let (addr, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;

    match addr.len() {
        8 => {
            let raw = u32::from_str_radix(addr, 16).ok()?;
            Some((std::net::Ipv4Addr::from(raw.to_be()).into(), port))
        }
        32 => {
            let mut octets = [0u8; 16];
            for (i, chunk) in addr.as_bytes().chunks(8).enumerate() {
                let word = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
                octets[i * 4..i * 4 + 4].copy_from_slice(&word.to_be().to_be_bytes());
            }
            Some((std::net::Ipv6Addr::from(octets).into(), port))
        }
        _ => None,
    }
}

/// Compare a table address with a socket address, treating v4-mapped forms as equal so a
/// dual-stack listener does not lose identity.
fn same_addr(table: std::net::IpAddr, peer: SocketAddr) -> bool {
    let normalise = |ip: std::net::IpAddr| match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(Into::into).unwrap_or(ip),
        other => other,
    };
    normalise(table) == normalise(peer.ip())
}

/// Resolve pid, cgroup and command line from a socket inode.
///
/// Racy for short-lived processes and costs a directory walk, so it is opt-in and used for
/// audit annotation rather than as a policy input — except for cgroup matching, which the
/// launcher relies on and which the operator enables deliberately.
pub fn enrich_from_inode(inode: u64) -> Option<(u32, Option<String>, Option<String>)> {
    let target = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()? {
        let Ok(entry) = entry else { continue };
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else { continue };

        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else { continue };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|l| l == std::path::Path::new(&target)) {
                let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
                    .ok()
                    .map(|c| c.trim().to_owned());
                let cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
                    .ok()
                    .map(|c| c.replace('\0', " ").trim().to_owned());
                return Some((pid, cgroup, cmdline));
            }
        }
    }
    None
}

/// Full credentials for a TCP peer.
pub fn peer_cred_for_tcp(peer: SocketAddr, enrich: bool) -> Option<PeerCred> {
    let (uid, inode) = uid_and_inode_for_tcp_peer(peer)?;
    let mut cred = PeerCred { uid: Some(uid), ..Default::default() };
    if enrich && let Some((pid, cgroup, cmdline)) = enrich_from_inode(inode) {
        cred.pid = Some(pid);
        cred.cgroup = cgroup;
        cred.cmdline = cmdline;
    }
    Some(cred)
}

/// `SO_PEERCRED` on a Unix-domain connection: authoritative, race-free, unspoofable.
pub fn peer_cred_for_unix(stream: &tokio::net::UnixStream, enrich: bool) -> Option<PeerCred> {
    let ucred = stream.peer_cred().ok()?;
    let mut cred = PeerCred {
        uid: Some(ucred.uid()),
        gid: Some(ucred.gid()),
        pid: ucred.pid().map(|p| p as u32),
        ..Default::default()
    };
    if enrich && let Some(pid) = cred.pid {
        cred.cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))
            .ok()
            .map(|c| c.trim().to_owned());
        cred.cmdline = std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
            .ok()
            .map(|c| c.replace('\0', " ").trim().to_owned());
    }
    Some(cred)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_rows() {
        // 0100007F = 127.0.0.1 little-endian, :0035 = port 53
        let (addr, port) = parse_hex_addr("0100007F:0035").unwrap();
        assert_eq!(addr.to_string(), "127.0.0.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn parses_ipv6_rows() {
        let (addr, _) = parse_hex_addr("00000000000000000000000001000000:0050").unwrap();
        assert_eq!(addr.to_string(), "::1");
    }

    #[test]
    fn rejects_malformed_rows_without_panicking() {
        assert!(parse_hex_addr("").is_none());
        assert!(parse_hex_addr("nonsense").is_none());
        assert!(parse_hex_addr("ZZZZZZZZ:0050").is_none());
        assert!(parse_hex_addr("0100007F").is_none());
    }

    #[test]
    fn v4_mapped_addresses_compare_equal() {
        let mapped: std::net::IpAddr = "::ffff:127.0.0.1".parse().unwrap();
        let peer: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        assert!(same_addr(mapped, peer));
    }

    /// The end-to-end check that the table format has not drifted: open a real socket and
    /// look up our own uid through the same path the proxy uses.
    #[tokio::test]
    async fn finds_the_uid_of_a_live_local_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (_server, peer) = listener.accept().await.unwrap();

        // The accepted connection's peer is the client's own socket.
        assert_eq!(peer, client.local_addr().unwrap());

        let uid = uid_for_tcp_peer(peer).expect("our own socket must be findable in /proc/net/tcp");
        // Compare against what the OS says we are, rather than hardcoding a value.
        let expected: u32 = std::fs::read_to_string("/proc/self/status")
            .unwrap()
            .lines()
            .find(|l| l.starts_with("Uid:"))
            .and_then(|l| l.split_whitespace().nth(1).and_then(|v| v.parse().ok()))
            .unwrap();
        assert_eq!(uid, expected);
    }

    #[tokio::test]
    async fn so_peercred_reports_our_own_credentials() {
        let dir = std::env::temp_dir().join(format!("marshal-uds-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s.sock");
        let _ = std::fs::remove_file(&path);

        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let _client = tokio::net::UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let cred = peer_cred_for_unix(&server, false).expect("SO_PEERCRED is available");
        assert!(cred.uid.is_some());
        assert!(cred.is_trusted_for_policy());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
