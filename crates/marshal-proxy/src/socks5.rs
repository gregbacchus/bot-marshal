//! SOCKS5 front-end (RFC 1928).
//!
//! Only `CONNECT` is supported. `BIND` and `UDP ASSOCIATE` are refused: both would open an
//! egress path the policy chain cannot see, which defeats the point of the proxy.

use marshal_core::Authority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("client offered no acceptable authentication method")]
    NoAcceptableAuth,
    #[error("unsupported SOCKS command {0:#04x}; only CONNECT is allowed")]
    UnsupportedCommand(u8),
    #[error("unsupported address type {0:#04x}")]
    UnsupportedAddressType(u8),
    #[error("malformed SOCKS5 message")]
    Malformed,
}

/// Reply codes we send back. Named rather than numeric at call sites so a refusal cannot be
/// mislabelled as a network failure.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum Reply {
    Succeeded = 0x00,
    GeneralFailure = 0x01,
    /// What a policy denial maps to: the client is told the rule forbids it, not that the
    /// network is broken.
    NotAllowed = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
}

/// What the handshake established.
#[derive(Debug)]
pub struct Socks5Request {
    pub authority: Authority,
    /// Present when the client authenticated with username/password (RFC 1929). Used to
    /// select an identity, so a single port can serve several agents.
    pub credential: Option<marshal_core::Credential>,
}

/// Complete the greeting and read the CONNECT request.
///
/// Both `NO AUTH` and username/password are offered. Username/password is preferred when the
/// client supports it, because a credential selects a profile — but it is not required, since
/// stronger identity (uid, source address) is available without the client's cooperation and
/// a credential the agent holds is the weakest of the three anyway.
pub async fn handshake<S>(stream: &mut S) -> Result<Socks5Request, Socks5Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Greeting: ver(1) nmethods(1) methods(nmethods). The version byte was already consumed
    // by the sniffer, so we start at nmethods.
    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let credential = if methods.contains(&0x02) {
        stream.write_all(&[0x05, 0x02]).await?;
        Some(read_userpass(stream).await?)
    } else if methods.contains(&0x00) {
        stream.write_all(&[0x05, 0x00]).await?;
        None
    } else {
        stream.write_all(&[0x05, 0xff]).await?;
        return Err(Socks5Error::NoAcceptableAuth);
    };

    // Request: ver(1) cmd(1) rsv(1) atyp(1) addr(..) port(2)
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(Socks5Error::Malformed);
    }
    if head[1] != 0x01 {
        reply(stream, Reply::CommandNotSupported).await?;
        return Err(Socks5Error::UnsupportedCommand(head[1]));
    }

    let host = match head[3] {
        0x01 => {
            let mut o = [0u8; 4];
            stream.read_exact(&mut o).await?;
            std::net::Ipv4Addr::from(o).to_string()
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            String::from_utf8(name).map_err(|_| Socks5Error::Malformed)?
        }
        0x04 => {
            let mut o = [0u8; 16];
            stream.read_exact(&mut o).await?;
            std::net::Ipv6Addr::from(o).to_string()
        }
        other => {
            reply(stream, Reply::AddressTypeNotSupported).await?;
            return Err(Socks5Error::UnsupportedAddressType(other));
        }
    };

    let port = stream.read_u16().await?;
    Ok(Socks5Request { authority: Authority { host, port }, credential })
}

/// RFC 1929 username/password sub-negotiation.
///
/// Always answered with success: the credential selects an identity, and an unknown one simply
/// fails to match any resolver and lands in the unidentified fallback. Rejecting here would
/// turn a profile-selection miss into an opaque transport error.
async fn read_userpass<S>(stream: &mut S) -> Result<marshal_core::Credential, Socks5Error>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let version = stream.read_u8().await?;
    if version != 0x01 {
        return Err(Socks5Error::Malformed);
    }
    let ulen = stream.read_u8().await? as usize;
    let mut user = vec![0u8; ulen];
    stream.read_exact(&mut user).await?;
    let plen = stream.read_u8().await? as usize;
    let mut pass = vec![0u8; plen];
    stream.read_exact(&mut pass).await?;

    stream.write_all(&[0x01, 0x00]).await?;

    Ok(marshal_core::Credential {
        user: String::from_utf8(user).map_err(|_| Socks5Error::Malformed)?,
        password: String::from_utf8(pass).map_err(|_| Socks5Error::Malformed)?,
    })
}

/// Send a reply. The bound address is reported as `0.0.0.0:0`: the real upstream address is
/// not the client's business, and echoing it would leak which of several resolved addresses
/// we chose.
pub async fn reply<S>(stream: &mut S, code: Reply) -> Result<(), Socks5Error>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream.write_all(&[0x05, code as u8, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    async fn drive(client_bytes: &[u8]) -> (Result<Socks5Request, Socks5Error>, Vec<u8>) {
        let (mut client, mut server) = duplex(4096);
        client.write_all(client_bytes).await.unwrap();
        let result = handshake(&mut server).await;
        drop(server);
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out).await;
        (result, out)
    }

    #[tokio::test]
    async fn parses_a_domain_connect() {
        // nmethods=1, NO_AUTH; then CONNECT example.com:443
        let mut req = vec![0x01, 0x00];
        req.extend([0x05, 0x01, 0x00, 0x03, 11]);
        req.extend(b"example.com");
        req.extend(443u16.to_be_bytes());

        let (auth, replied) = drive(&req).await;
        let auth = auth.unwrap();
        assert_eq!(auth.authority.host, "example.com");
        assert_eq!(auth.authority.port, 443);
        assert!(auth.credential.is_none());
        assert_eq!(&replied[..2], &[0x05, 0x00], "method selection must be NO_AUTH");
    }

    #[tokio::test]
    async fn parses_an_ipv4_connect() {
        let mut req = vec![0x01, 0x00];
        req.extend([0x05, 0x01, 0x00, 0x01, 140, 82, 121, 4]);
        req.extend(443u16.to_be_bytes());
        assert_eq!(drive(&req).await.0.unwrap().authority.host, "140.82.121.4");
    }

    #[tokio::test]
    async fn refuses_bind_and_udp_associate() {
        for cmd in [0x02u8, 0x03] {
            let mut req = vec![0x01, 0x00];
            req.extend([0x05, cmd, 0x00, 0x01, 1, 2, 3, 4]);
            req.extend(80u16.to_be_bytes());
            let (r, _) = drive(&req).await;
            assert!(matches!(r, Err(Socks5Error::UnsupportedCommand(_))), "cmd {cmd:#04x}");
        }
    }

    #[tokio::test]
    async fn refuses_when_no_supported_method_is_offered() {
        // Offers only GSSAPI (0x01).
        let (r, replied) = drive(&[0x01, 0x01]).await;
        assert!(matches!(r, Err(Socks5Error::NoAcceptableAuth)));
        assert_eq!(&replied[..2], &[0x05, 0xff]);
    }

    #[tokio::test]
    async fn username_password_selects_a_credential() {
        // methods: NO_AUTH and USER/PASS; the server must prefer the one that identifies.
        let mut req = vec![0x02, 0x00, 0x02];
        req.extend([0x01, 7]);
        req.extend(b"agent-a");
        req.push(7);
        req.extend(b"hunter2");
        req.extend([0x05, 0x01, 0x00, 0x03, 11]);
        req.extend(b"example.com");
        req.extend(443u16.to_be_bytes());

        let (r, replied) = drive(&req).await;
        let r = r.unwrap();
        assert_eq!(&replied[..2], &[0x05, 0x02], "user/pass must be selected when offered");
        let cred = r.credential.expect("credential parsed");
        assert_eq!(cred.user, "agent-a");
        assert_eq!(cred.password, "hunter2");
    }
}
