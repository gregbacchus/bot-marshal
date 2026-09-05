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

/// Parse a token request body as whatever its `Content-Type` says, into the same pairs shape
/// either way.
///
/// RFC 6749 says `application/x-www-form-urlencoded`, and that is what every source in this
/// crate sends when *marshal* drives the exchange. But bootstrap capture is reading somebody
/// else's client, and plenty of real ones — an axios-based CLI among them — send
/// `application/json` instead. Parsed the wrong way, a JSON body silently yields no
/// `grant_type` at all rather than an error, which looks identical to a request this genuinely
/// isn't interested in. Only the top-level scalar fields are flattened; a request body has no
/// legitimate reason to nest.
pub(crate) fn parse_body(content_type: Option<&str>, body: &[u8]) -> Vec<(String, String)> {
    let is_json = content_type.is_some_and(|ct| {
        ct.split(';').next().unwrap_or("").trim().eq_ignore_ascii_case("application/json")
    });
    if is_json {
        let Ok(serde_json::Value::Object(map)) = serde_json::from_slice(body) else {
            return Vec::new();
        };
        return map
            .into_iter()
            .filter_map(|(k, v)| {
                let v = match v {
                    serde_json::Value::String(s) => s,
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => return None,
                };
                Some((k, v))
            })
            .collect();
    }
    parse_pairs(&String::from_utf8_lossy(body))
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

    #[test]
    fn parses_a_json_body_by_content_type() {
        let body = br#"{"grant_type":"authorization_code","code":"abc","expires_in":5}"#;
        let pairs = parse_body(Some("application/json"), body);
        assert_eq!(find(&pairs, "grant_type"), Some("authorization_code"));
        assert_eq!(find(&pairs, "code"), Some("abc"));
        assert_eq!(find(&pairs, "expires_in"), Some("5"));
    }

    #[test]
    fn a_json_content_type_with_a_charset_parameter_still_parses_as_json() {
        let body = br#"{"grant_type":"authorization_code"}"#;
        let pairs = parse_body(Some("application/json; charset=utf-8"), body);
        assert_eq!(find(&pairs, "grant_type"), Some("authorization_code"));
    }

    #[test]
    fn falls_back_to_form_parsing_with_no_or_a_form_content_type() {
        let pairs =
            parse_body(Some("application/x-www-form-urlencoded"), b"grant_type=authorization_code");
        assert_eq!(find(&pairs, "grant_type"), Some("authorization_code"));

        let pairs = parse_body(None, b"grant_type=authorization_code");
        assert_eq!(find(&pairs, "grant_type"), Some("authorization_code"));
    }

    #[test]
    fn a_non_object_or_malformed_json_body_yields_no_pairs_rather_than_garbage() {
        assert_eq!(parse_body(Some("application/json"), b"[1,2,3]"), Vec::new());
        assert_eq!(parse_body(Some("application/json"), b"not json"), Vec::new());
    }
}
