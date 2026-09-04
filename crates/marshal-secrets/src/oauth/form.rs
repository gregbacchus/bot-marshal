//! Reading `application/x-www-form-urlencoded` and query strings.
//!
//! Shared by both capture mechanisms: [`super::broker`] reads a `Location` header's query,
//! [`super::bootstrap`] reads a token request's form body, and they must agree on what a
//! parameter means down to the decoding — a `code_verifier` that survives one parser and not
//! the other is the kind of difference that only shows up against one provider.

/// Parse a query string or form body into pairs, percent-decoding both halves.
pub(crate) fn parse_pairs(input: &str) -> Vec<(String, String)> {
    input
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

pub(crate) fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(
                    std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                    16,
                ) {
                    Ok(b) => {
                        out.push(b);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            // `+` for space is the form-encoded spelling. Query strings use it too in
            // practice, whatever the RFC says, so both parsers accept it.
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub(crate) fn find<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_both_halves_of_every_pair() {
        let pairs = parse_pairs(
            "grant_type=authorization_code&redirect_uri=http%3A%2F%2F127.0.0.1%3A9%2Fcb",
        );
        assert_eq!(find(&pairs, "grant_type"), Some("authorization_code"));
        assert_eq!(find(&pairs, "redirect_uri"), Some("http://127.0.0.1:9/cb"));
        assert_eq!(find(&pairs, "absent"), None);
    }

    #[test]
    fn plus_is_a_space_and_a_valueless_key_is_empty_not_missing() {
        let pairs = parse_pairs("scope=read+write&flag");
        assert_eq!(find(&pairs, "scope"), Some("read write"));
        assert_eq!(find(&pairs, "flag"), Some(""));
    }

    #[test]
    fn a_truncated_escape_is_left_alone_rather_than_dropped() {
        // Better to carry a literal `%` through than to silently lose a byte of a credential.
        assert_eq!(percent_decode("ab%"), "ab%");
        assert_eq!(percent_decode("a%zzb"), "a%zzb");
    }
}
