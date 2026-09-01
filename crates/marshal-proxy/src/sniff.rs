//! Protocol sniffing on the shared listener, and TLS SNI extraction.
//!
//! One port serves HTTP `CONNECT`, absolute-form HTTP, and SOCKS5, because making the user
//! run three ports to satisfy three clients is friction with no security benefit. The first
//! byte distinguishes them unambiguously: SOCKS version bytes (4, 5) are not valid leading
//! characters of an HTTP method.

/// What the client appears to be speaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Socks5,
    /// SOCKS4/4a. Recognised only so it can be refused with a clear message rather than
    /// looking like malformed HTTP.
    Socks4,
    Http,
}

pub fn detect(first_byte: u8) -> Protocol {
    match first_byte {
        0x05 => Protocol::Socks5,
        0x04 => Protocol::Socks4,
        _ => Protocol::Http,
    }
}

/// Extract the SNI hostname from a TLS ClientHello.
///
/// Used to cross-check the `CONNECT` authority: a client that tunnels to `allowed.example.com`
/// and then presents SNI for a different host is either broken or attacking, and either way
/// the tunnel must not be established. Returns `None` when the bytes are not a ClientHello or
/// carry no SNI extension — the caller decides what that means, since a missing SNI is
/// legitimate for a bare-IP connection.
///
/// This is a deliberately shallow parser: it walks the ClientHello's length-prefixed fields
/// far enough to find `server_name` and no further. It never allocates from attacker-supplied
/// lengths and every read is bounds-checked.
pub fn sni_from_client_hello(buf: &[u8]) -> Option<String> {
    let mut r = Reader::new(buf);

    // TLS record header: content_type(1) legacy_version(2) length(2)
    if r.u8()? != 0x16 {
        return None; // not a handshake record
    }
    r.skip(2)?;
    let record_len = r.u16()? as usize;
    let mut rec = Reader::new(r.take(record_len)?);

    // Handshake header: msg_type(1) length(3)
    if rec.u8()? != 0x01 {
        return None; // not a ClientHello
    }
    let hs_len = rec.u24()? as usize;
    let mut hs = Reader::new(rec.take(hs_len)?);

    hs.skip(2)?; // legacy_version
    hs.skip(32)?; // random

    let session_id_len = hs.u8()? as usize;
    hs.skip(session_id_len)?;

    let cipher_suites_len = hs.u16()? as usize;
    hs.skip(cipher_suites_len)?;

    let compression_len = hs.u8()? as usize;
    hs.skip(compression_len)?;

    let extensions_len = hs.u16()? as usize;
    let mut ext = Reader::new(hs.take(extensions_len)?);

    while ext.remaining() >= 4 {
        let ext_type = ext.u16()?;
        let ext_len = ext.u16()? as usize;
        let body = ext.take(ext_len)?;

        if ext_type != 0x0000 {
            continue; // not server_name
        }

        let mut sni = Reader::new(body);
        let list_len = sni.u16()? as usize;
        let mut list = Reader::new(sni.take(list_len)?);
        while list.remaining() >= 3 {
            let name_type = list.u8()?;
            let name_len = list.u16()? as usize;
            let name = list.take(name_len)?;
            if name_type == 0 {
                return std::str::from_utf8(name).ok().map(|s| s.to_ascii_lowercase());
            }
        }
        return None;
    }
    None
}

/// A bounds-checked cursor. Every accessor returns `None` rather than panicking, so a
/// truncated or hostile ClientHello can only make us give up.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.take(n).map(|_| ())
    }

    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Option<u32> {
        self.take(3).map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_protocols() {
        assert_eq!(detect(0x05), Protocol::Socks5);
        assert_eq!(detect(0x04), Protocol::Socks4);
        assert_eq!(detect(b'C'), Protocol::Http); // CONNECT
        assert_eq!(detect(b'G'), Protocol::Http); // GET
    }

    /// Build a minimal but well-formed ClientHello carrying one SNI name.
    fn client_hello(host: &str) -> Vec<u8> {
        let name = host.as_bytes();
        let mut sni_list = Vec::new();
        sni_list.push(0x00); // host_name
        sni_list.extend((name.len() as u16).to_be_bytes());
        sni_list.extend(name);

        let mut sni_ext = Vec::new();
        sni_ext.extend((sni_list.len() as u16).to_be_bytes());
        sni_ext.extend(&sni_list);

        let mut exts = Vec::new();
        exts.extend(0x0000u16.to_be_bytes()); // server_name
        exts.extend((sni_ext.len() as u16).to_be_bytes());
        exts.extend(&sni_ext);

        let mut body = Vec::new();
        body.extend([0x03, 0x03]); // legacy_version
        body.extend([0u8; 32]); // random
        body.push(0); // session_id len
        body.extend(2u16.to_be_bytes()); // cipher suites len
        body.extend([0x13, 0x01]);
        body.push(1); // compression len
        body.push(0);
        body.extend((exts.len() as u16).to_be_bytes());
        body.extend(&exts);

        let mut hs = Vec::new();
        hs.push(0x01); // ClientHello
        hs.extend(&(body.len() as u32).to_be_bytes()[1..]); // u24
        hs.extend(&body);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake
        rec.extend([0x03, 0x01]);
        rec.extend((hs.len() as u16).to_be_bytes());
        rec.extend(&hs);
        rec
    }

    #[test]
    fn extracts_sni() {
        let hello = client_hello("api.github.com");
        assert_eq!(sni_from_client_hello(&hello).as_deref(), Some("api.github.com"));
    }

    #[test]
    fn sni_is_lowercased() {
        let hello = client_hello("API.GitHub.COM");
        assert_eq!(sni_from_client_hello(&hello).as_deref(), Some("api.github.com"));
    }

    #[test]
    fn truncation_never_panics() {
        let hello = client_hello("api.github.com");
        // Every prefix must return cleanly rather than panicking or reading out of bounds.
        for n in 0..hello.len() {
            let _ = sni_from_client_hello(&hello[..n]);
        }
    }

    #[test]
    fn garbage_is_rejected() {
        assert_eq!(sni_from_client_hello(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(sni_from_client_hello(&[]), None);
        // A handshake record claiming an absurd length must not allocate or panic.
        assert_eq!(sni_from_client_hello(&[0x16, 0x03, 0x01, 0xff, 0xff, 0x01]), None);
    }
}
