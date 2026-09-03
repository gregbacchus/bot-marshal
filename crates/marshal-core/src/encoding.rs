//! Base64 and percent-encoding, by hand.
//!
//! Every one of these is a dozen lines and none of them is a place where a subtle bug hides
//! for long — the RFCs publish test vectors, and they are asserted below. Pulling a crate in
//! per encoding would be more supply-chain surface than the code it replaces, and this crate
//! is deliberately dependency-free (ADR-0002).

const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_SAFE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn encode_with(alphabet: &[u8; 64], input: &[u8], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(alphabet[(b0 >> 2) as usize] as char);
        out.push(alphabet[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(alphabet[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else if pad {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(alphabet[(b2 & 0x3f) as usize] as char);
        } else if pad {
            out.push('=');
        }
    }
    out
}

/// Standard-alphabet base64 with padding ([RFC 4648 §4](https://www.rfc-editor.org/rfc/rfc4648)).
/// What `Authorization: Basic` wants.
pub fn base64_encode(input: &[u8]) -> String {
    encode_with(STANDARD, input, true)
}

/// URL-safe base64 without padding ([RFC 4648 §5](https://www.rfc-editor.org/rfc/rfc4648)).
/// What JWTs and the PKCE `S256` challenge want — both specify unpadded `base64url`, and a
/// stray `=` makes a challenge that no provider will match.
pub fn base64url_encode(input: &[u8]) -> String {
    encode_with(URL_SAFE, input, false)
}

/// Percent-encode every byte outside the RFC 3986 unreserved set. Safe to use on either half
/// of a query parameter, because it encodes `=` and `&` along with everything else.
pub fn percent_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// Encode name/value pairs as `application/x-www-form-urlencoded`.
///
/// Percent-encoding, not the legacy `+`-for-space variant: both are accepted everywhere that
/// parses this content type, and `%20` avoids the class of bug where a value containing a
/// literal `+` survives one hop and is mangled at the next.
pub fn form_urlencode<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = String::new();
    for (name, value) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&percent_encode(name.as_bytes()));
        out.push('=');
        out.push_str(&percent_encode(value.as_bytes()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc4648_test_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64url_is_unpadded_and_uses_the_url_safe_alphabet() {
        // 0xfb 0xff encodes to `+/` under the standard alphabet and `-_` under url-safe.
        assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn percent_encoding_leaves_the_unreserved_set_alone_and_escapes_the_rest() {
        assert_eq!(percent_encode(b"aZ0-_.~"), "aZ0-_.~");
        assert_eq!(percent_encode(b"a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(percent_encode("é".as_bytes()), "%C3%A9");
    }

    #[test]
    fn form_urlencode_escapes_separators_in_both_halves() {
        // A client secret containing `&` must not be able to inject an extra form field.
        assert_eq!(
            form_urlencode([("grant_type", "client_credentials"), ("secret", "a&b=c")]),
            "grant_type=client_credentials&secret=a%26b%3Dc"
        );
        assert_eq!(form_urlencode([]), "");
    }
}
