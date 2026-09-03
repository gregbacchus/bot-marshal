//! Signed JWT assertions, for the two OAuth2 flows that prove identity with a key rather than
//! a shared secret.
//!
//! * **`jwt_bearer`** ([RFC 7523 §2.1](https://www.rfc-editor.org/rfc/rfc7523#section-2.1)) —
//!   the assertion *is* the grant. Google service accounts, and the usual way a workload
//!   authenticates to a cloud provider without a password anywhere.
//! * **`private_key_jwt`** ([RFC 7523 §2.2](https://www.rfc-editor.org/rfc/rfc7523#section-2.2))
//!   — the assertion replaces `client_secret` as *client authentication*, and composes with
//!   any grant.
//!
//! Signed with `ring`, which is already the cryptographic provider underneath rustls: nothing
//! new enters the dependency graph, and the primitives are ones this project already trusts
//! for TLS. A JWT library would add a parser this code does not need — marshal only ever
//! *produces* these assertions, never validates one.

use std::time::{SystemTime, UNIX_EPOCH};

use marshal_core::{Error, Result, SecretValue, base64url_encode};
use ring::rand::SystemRandom;
use ring::signature;

/// Which signature algorithm the provider expects.
///
/// Only the two that matter in practice. `HS256` is deliberately absent: it is a shared
/// secret, so it offers nothing over `client_secret_basic` while looking like asymmetric
/// cryptography, and `none` is not an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// RSASSA-PKCS1-v1_5 with SHA-256. What almost every provider wants.
    Rs256,
    /// ECDSA with P-256 and SHA-256.
    Es256,
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "RS256" => Ok(Self::Rs256),
            "ES256" => Ok(Self::Es256),
            other => Err(Error::Config(format!(
                "unsupported JWT algorithm `{other}` — expected RS256 or ES256"
            ))),
        }
    }
}

/// The claims of an assertion. Built by the caller, since the two flows want different ones.
#[derive(Debug, Default)]
pub struct Claims {
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    /// Google's service-account flow puts the requested scope in the assertion rather than in
    /// the form body.
    pub scope: Option<String>,
    /// A unique id. Required by `private_key_jwt` so a provider can reject a replayed
    /// assertion; harmless elsewhere.
    pub jti: Option<String>,
    pub lifetime_secs: u64,
    /// Anything a provider wants that is not in the RFC.
    pub extra: Vec<(String, serde_json::Value)>,
}

/// Sign a JWT.
///
/// `key_pem` is the PEM the operator configured. PKCS#8 and the older PKCS#1/SEC1 forms are
/// all accepted, because which one a provider hands out is not something an operator chooses
/// — Google issues PKCS#8, `openssl genrsa` produces PKCS#1, and telling someone to convert
/// their key before it will work is a poor use of their afternoon.
pub fn sign(
    key_pem: &SecretValue,
    algorithm: Algorithm,
    key_id: Option<&str>,
    claims: &Claims,
) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Config(format!("the system clock is before the epoch: {e}")))?
        .as_secs();

    let mut header = serde_json::json!({ "alg": algorithm.name(), "typ": "JWT" });
    if let Some(kid) = key_id {
        header["kid"] = serde_json::Value::String(kid.to_owned());
    }

    let mut payload = serde_json::json!({
        "iss": claims.issuer,
        "sub": claims.subject,
        "aud": claims.audience,
        "iat": now,
        "exp": now + claims.lifetime_secs,
    });
    if let Some(scope) = &claims.scope {
        payload["scope"] = serde_json::Value::String(scope.clone());
    }
    if let Some(jti) = &claims.jti {
        payload["jti"] = serde_json::Value::String(jti.clone());
    }
    for (k, v) in &claims.extra {
        payload[k] = v.clone();
    }

    let signing_input = format!(
        "{}.{}",
        base64url_encode(&serde_json::to_vec(&header).expect("serialises")),
        base64url_encode(&serde_json::to_vec(&payload).expect("serialises"))
    );

    let signature = raw_sign(key_pem, algorithm, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{}", base64url_encode(&signature)))
}

fn raw_sign(key_pem: &SecretValue, algorithm: Algorithm, message: &[u8]) -> Result<Vec<u8>> {
    let der = private_key_der(key_pem)?;
    let rng = SystemRandom::new();

    match algorithm {
        Algorithm::Rs256 => {
            let key = rsa_key(&der)?;
            let mut sig = vec![0u8; key.public().modulus_len()];
            key.sign(&signature::RSA_PKCS1_SHA256, &rng, message, &mut sig).map_err(|_| {
                Error::Config(
                    "signing the JWT assertion failed — the RSA key may be too small (2048 bits \
                     is the minimum)"
                        .to_owned(),
                )
            })?;
            Ok(sig)
        }
        Algorithm::Es256 => {
            let key = signature::EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                der.as_ref(),
                &rng,
            )
            .map_err(|_| {
                Error::Config(
                    "the private key is not a PKCS#8 P-256 key, which `algorithm: ES256` \
                     requires"
                        .to_owned(),
                )
            })?;
            Ok(key
                .sign(&rng, message)
                .map_err(|_| Error::Config("signing the JWT assertion failed".to_owned()))?
                .as_ref()
                .to_vec())
        }
    }
}

/// Accept either PKCS#8 or the bare PKCS#1 form for an RSA key.
fn rsa_key(der: &PrivateKeyBytes) -> Result<signature::RsaKeyPair> {
    let from_pkcs8 = signature::RsaKeyPair::from_pkcs8(der.as_ref());
    let result = match der.kind {
        KeyKind::Pkcs8 => from_pkcs8,
        KeyKind::Pkcs1 => signature::RsaKeyPair::from_der(der.as_ref()),
        // SEC1 is unambiguously an EC key, so this one can be certain about the cause.
        KeyKind::Sec1 => {
            return Err(Error::Config(
                "the private key is an EC key, but `algorithm: RS256` was configured — use \
                 `algorithm: ES256`"
                    .to_owned(),
            ));
        }
    };
    // A PKCS#8 wrapper does not say which algorithm is inside until ring looks, so the hint
    // has to be part of the general failure: "not a usable RSA key" alone leaves an operator
    // with an EC key nowhere to go.
    result.map_err(|e| {
        Error::Config(format!(
            "the private key is not a usable RSA key ({e}) — if it is an EC key, set \
             `algorithm: ES256`"
        ))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Pkcs8,
    Pkcs1,
    Sec1,
}

struct PrivateKeyBytes {
    bytes: Vec<u8>,
    kind: KeyKind,
}

impl AsRef<[u8]> for PrivateKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

fn private_key_der(pem: &SecretValue) -> Result<PrivateKeyBytes> {
    use rustls::pki_types::PrivateKeyDer;
    use rustls::pki_types::pem::{Error as PemError, PemObject};

    let key = PrivateKeyDer::from_pem_slice(pem.expose().as_bytes()).map_err(|e| match e {
        PemError::NoItemsFound => Error::Config(
            "no PRIVATE KEY block in the configured `private_key` source — it must be a PEM \
             file, not a base64 blob or a JSON document"
                .to_owned(),
        ),
        other => Error::Config(format!("reading the private key: {other}")),
    })?;
    Ok(match key {
        PrivateKeyDer::Pkcs8(k) => {
            PrivateKeyBytes { bytes: k.secret_pkcs8_der().to_vec(), kind: KeyKind::Pkcs8 }
        }
        PrivateKeyDer::Pkcs1(k) => {
            PrivateKeyBytes { bytes: k.secret_pkcs1_der().to_vec(), kind: KeyKind::Pkcs1 }
        }
        PrivateKeyDer::Sec1(k) => {
            PrivateKeyBytes { bytes: k.secret_sec1_der().to_vec(), kind: KeyKind::Sec1 }
        }
        _ => return Err(Error::Config("unrecognised private key format".to_owned())),
    })
}

/// The throwaway key the tests in this module and in `source` both sign with.
#[cfg(test)]
pub(crate) mod tests_support {
    pub(crate) const TEST_RSA_PKCS8: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCss0hasSARe/QL
sPFKXPNV3xzWqPw9crIVn17NtXimIyw2a2BeYs7AaIIjtGrGoNWlHt7FiNOO6MQ1
syRH8YeScgWxEJ8cbRZ4CZnC7Hk8WuT5M48YelhuEvfCLhsZ9eC9qZjESK/C/GYw
M8PFvW2LrXXvy0krxuf3ZYkrofBRnK7byIBsXFWdU8Vz2SQF7rS5/TTZu4SbbJ/F
Uy92LRlmY6g3/Kz0nrNcUVnW3CcTQE7RT1hC7X7aqeQAxIuWrLV7f+LAzRcdwGwH
AVfGlKX399ALbLZlsepOZjsPbqRN1rlq/FrQ/k3yp2CYObknVToxs3xvaz6xYuXP
0V/BMIjRAgMBAAECggEAJIxelB7nH/whBjZgojGwp6wrkLw7gY+b45qSOCufCF3q
NewcfW0gvzR+0iqU7EtOW38Ae0J9L0HQgGLUm0sgu1vZG4NegOgPOMEjYs6jy6Oa
0KhaML53p3fpKhWS07gm40yYkXWmiLfcsnfKBzeTDtvbWS+m4RZbsg4xbOP9FXAf
E+gCGFdaajoUd+cGOhvcleo8BTxEbbIlWHlW53WnJdu+PuLTTLAPB0dzABihchb9
fLaVzHK7xalLyrZOWaR/3d7mcLVz7IlhAkuA+PLlp5UR6r1A+UYywdd7+QFOvIPT
mkUAXVS0Cd6m7Rj+Xit7abjOdI2kBhca41y8CoayxwKBgQDuvtWneZAFInOlOABv
+RAqoYSpvn52VXDDi33dzKmExBMQ6SVjrG8EKDPWxzGzyBCQu0bjcS1PqdZgDYJX
6urLS3z2x6pgENIcbEE02PNUUGX7JpTK90DOZvwpKNrcqGWw4aWWtG/jaP4/35Vl
YG0tFeiMjsX2JGDZESRk4VIvRwKBgQC5LoJ1RSFC8u8jQH98PaIRdbH1HCM69da9
rRSFSHPocPqtbV5pgk2cEzlU9ksPUoZO2xY5wP2Pw4JD5HQjX6isct6n3wnNyAzW
2b8k3f+zaqCPmQZmz9TAr1grWEy0KtgI5QalzDoTaBBiY66qC6oWQoW1OKjj9gCs
0gbCpbaDJwKBgQDpACXUBLehyzXCER2cKh60/F1UrC0Pn+MldIWqaYsnn5Rb9K4g
0LCoBfRRsKW5J4/DMILGhjYKgV5O7+A9nW74aPvUfJiymLf2NVCOGw2fQ7fDnKuq
ShRdW/TM1qqCn3ZfYlkQ85gfAODhxXswLSNf1PnX858P0gES18AFFEH5EQKBgQCD
e9+LbpNIWv+q8w/R4l0hsoSxudHV+loIAU2xuRj7cMS8wQwpNCjw6cFqbxoqffj5
IpwsU7h2DGaA2EQSHcjA8Srg3P+0Chf7sU4D2lDFTq9EZm3iMC0qxxV+aUrFHiqY
Xi2TKWgPAXOouIh7Gp8hAQi4/MsGWVRvYQ0Fxe3KPwKBgQDdaM3N9Dcg9N6wi4Ho
GP3r4TWDdPYOHQi14ohewJod/xJVrB+50KKVqXNnF2OjcpXxhnRQYObqXZKcq/3j
cGJKSik3OjvLzVjqFzFMS+zGD3D0VMKSD3tFpx/vrK4pEzFCAJUQxPdrZDrMw/fC
IgYs3kYS02y5aHYasLfWHMSSEw==
-----END PRIVATE KEY-----";
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway 2048-bit RSA key, generated once for these tests and committed.
    ///
    /// Committed rather than generated at test time because rcgen cannot produce RSA keys with
    /// the backend this workspace uses, and shelling out to openssl from a test would make the
    /// suite depend on what happens to be installed. It authenticates nothing and exists
    /// nowhere else; treat any grep hit on it as a false positive.
    use super::tests_support::TEST_RSA_PKCS8;

    /// The same key in the older PKCS#1 form, which `openssl genrsa` still emits by default
    /// and which a provider may well have handed the operator.
    const TEST_RSA_PKCS1: &str = r"-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEArLNIWrEgEXv0C7DxSlzzVd8c1qj8PXKyFZ9ezbV4piMsNmtg
XmLOwGiCI7RqxqDVpR7exYjTjujENbMkR/GHknIFsRCfHG0WeAmZwux5PFrk+TOP
GHpYbhL3wi4bGfXgvamYxEivwvxmMDPDxb1ti61178tJK8bn92WJK6HwUZyu28iA
bFxVnVPFc9kkBe60uf002buEm2yfxVMvdi0ZZmOoN/ys9J6zXFFZ1twnE0BO0U9Y
Qu1+2qnkAMSLlqy1e3/iwM0XHcBsBwFXxpSl9/fQC2y2ZbHqTmY7D26kTda5avxa
0P5N8qdgmDm5J1U6MbN8b2s+sWLlz9FfwTCI0QIDAQABAoIBACSMXpQe5x/8IQY2
YKIxsKesK5C8O4GPm+Oakjgrnwhd6jXsHH1tIL80ftIqlOxLTlt/AHtCfS9B0IBi
1JtLILtb2RuDXoDoDzjBI2LOo8ujmtCoWjC+d6d36SoVktO4JuNMmJF1poi33LJ3
ygc3kw7b21kvpuEWW7IOMWzj/RVwHxPoAhhXWmo6FHfnBjob3JXqPAU8RG2yJVh5
Vud1pyXbvj7i00ywDwdHcwAYoXIW/Xy2lcxyu8WpS8q2Tlmkf93e5nC1c+yJYQJL
gPjy5aeVEeq9QPlGMsHXe/kBTryD05pFAF1UtAnepu0Y/l4re2m4znSNpAYXGuNc
vAqGsscCgYEA7r7Vp3mQBSJzpTgAb/kQKqGEqb5+dlVww4t93cyphMQTEOklY6xv
BCgz1scxs8gQkLtG43EtT6nWYA2CV+rqy0t89seqYBDSHGxBNNjzVFBl+yaUyvdA
zmb8KSja3KhlsOGllrRv42j+P9+VZWBtLRXojI7F9iRg2REkZOFSL0cCgYEAuS6C
dUUhQvLvI0B/fD2iEXWx9RwjOvXWva0UhUhz6HD6rW1eaYJNnBM5VPZLD1KGTtsW
OcD9j8OCQ+R0I1+orHLep98JzcgM1tm/JN3/s2qgj5kGZs/UwK9YK1hMtCrYCOUG
pcw6E2gQYmOuqguqFkKFtTio4/YArNIGwqW2gycCgYEA6QAl1AS3ocs1whEdnCoe
tPxdVKwtD5/jJXSFqmmLJ5+UW/SuINCwqAX0UbCluSePwzCCxoY2CoFeTu/gPZ1u
+Gj71HyYspi39jVQjhsNn0O3w5yrqkoUXVv0zNaqgp92X2JZEPOYHwDg4cV7MC0j
X9T51/OfD9IBEtfABRRB+RECgYEAg3vfi26TSFr/qvMP0eJdIbKEsbnR1fpaCAFN
sbkY+3DEvMEMKTQo8OnBam8aKn34+SKcLFO4dgxmgNhEEh3IwPEq4Nz/tAoX+7FO
A9pQxU6vRGZt4jAtKscVfmlKxR4qmF4tkyloDwFzqLiIexqfIQEIuPzLBllUb2EN
BcXtyj8CgYEA3WjNzfQ3IPTesIuB6Bj96+E1g3T2Dh0IteKIXsCaHf8SVawfudCi
lalzZxdjo3KV8YZ0UGDm6l2SnKv943BiSkopNzo7y81Y6hcxTEvsxg9w9FTCkg97
Racf76yuKRMxQgCVEMT3a2Q6zMP3wiIGLN5GEtNsuWh2GrC31hzEkhM=
-----END RSA PRIVATE KEY-----";

    fn rsa_pem() -> SecretValue {
        SecretValue::new(TEST_RSA_PKCS8)
    }

    fn ec_pem() -> SecretValue {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ec keygen");
        SecretValue::new(key.serialize_pem())
    }

    fn claims() -> Claims {
        Claims {
            issuer: "svc@project.iam.gserviceaccount.com".into(),
            subject: "svc@project.iam.gserviceaccount.com".into(),
            audience: "https://oauth2.googleapis.com/token".into(),
            scope: Some("https://www.googleapis.com/auth/cloud-platform".into()),
            jti: None,
            lifetime_secs: 3600,
            extra: vec![],
        }
    }

    /// A minimal base64url decoder, so the tests read a token the way a provider would rather
    /// than trusting the encoder they are testing.
    fn b64u_decode(part: &str) -> Vec<u8> {
        let mut bytes = Vec::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for c in part.chars() {
            let v = match c {
                'A'..='Z' => c as u32 - 'A' as u32,
                'a'..='z' => c as u32 - 'a' as u32 + 26,
                '0'..='9' => c as u32 - '0' as u32 + 52,
                '-' => 62,
                '_' => 63,
                _ => panic!("`{c}` is not in the base64url alphabet: {part}"),
            };
            acc = (acc << 6) | v;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                bytes.push((acc >> bits) as u8);
            }
        }
        bytes
    }

    fn decode(part: &str) -> serde_json::Value {
        serde_json::from_slice(&b64u_decode(part)).expect("the part is JSON")
    }

    #[test]
    fn an_rs256_assertion_has_the_header_and_claims_the_rfc_requires() {
        let jwt = sign(&rsa_pem(), Algorithm::Rs256, Some("key-1"), &claims()).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWS is three dot-separated parts: {jwt}");

        let header = decode(parts[0]);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], "key-1");

        let payload = decode(parts[1]);
        assert_eq!(payload["iss"], "svc@project.iam.gserviceaccount.com");
        assert_eq!(payload["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(payload["scope"], "https://www.googleapis.com/auth/cloud-platform");
        // RFC 7523 section 3: `exp` is required, and must be after `iat`.
        assert_eq!(payload["exp"].as_u64().unwrap() - payload["iat"].as_u64().unwrap(), 3600);
    }

    #[test]
    fn the_signature_verifies_against_the_public_key() {
        // The check that matters. A token that is well-shaped but not correctly signed is
        // rejected by every provider and by nothing in a shape assertion.
        let pem = rsa_pem();
        let jwt = sign(&pem, Algorithm::Rs256, None, &claims()).unwrap();
        let (signing_input, sig) = jwt.rsplit_once('.').unwrap();

        let der = private_key_der(&pem).unwrap();
        let key = rsa_key(&der).unwrap();
        let public = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            key.public().as_ref().to_vec(),
        );
        public
            .verify(signing_input.as_bytes(), &b64u_decode(sig))
            .expect("the assertion must verify against its own public key");
    }

    #[test]
    fn a_tampered_assertion_does_not_verify() {
        // Proves the verification above is actually checking something.
        let pem = rsa_pem();
        let jwt = sign(&pem, Algorithm::Rs256, None, &claims()).unwrap();
        let (signing_input, sig) = jwt.rsplit_once('.').unwrap();

        let der = private_key_der(&pem).unwrap();
        let key = rsa_key(&der).unwrap();
        let public = signature::UnparsedPublicKey::new(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            key.public().as_ref().to_vec(),
        );
        let tampered = format!("{signing_input}x");
        assert!(public.verify(tampered.as_bytes(), &b64u_decode(sig)).is_err());
    }

    #[test]
    fn the_older_pkcs1_key_form_works_too() {
        // `openssl genrsa` still emits this by default, so refusing it would send an operator
        // off to convert a key for no reason.
        let jwt =
            sign(&SecretValue::new(TEST_RSA_PKCS1), Algorithm::Rs256, None, &claims()).unwrap();
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn es256_signs_with_an_ec_key() {
        let jwt = sign(&ec_pem(), Algorithm::Es256, None, &claims()).unwrap();
        assert_eq!(decode(jwt.split('.').next().unwrap())["alg"], "ES256");
        assert_eq!(jwt.split('.').count(), 3);
    }

    #[test]
    fn an_ec_key_configured_as_rs256_says_which_algorithm_to_use() {
        // An easy mistake, and the underlying error ("invalid key") says nothing useful.
        let err = sign(&ec_pem(), Algorithm::Rs256, None, &claims()).unwrap_err();
        assert!(format!("{err}").contains("ES256"), "{err}");
    }

    #[test]
    fn an_rsa_key_configured_as_es256_is_refused() {
        let err = sign(&rsa_pem(), Algorithm::Es256, None, &claims()).unwrap_err();
        assert!(format!("{err}").contains("P-256"), "{err}");
    }

    #[test]
    fn something_that_is_not_a_pem_says_so_rather_than_failing_obscurely() {
        let err = sign(&SecretValue::new("not-a-pem-at-all"), Algorithm::Rs256, None, &claims())
            .unwrap_err();
        assert!(format!("{err}").contains("PEM"), "{err}");
    }

    #[test]
    fn jti_and_extra_claims_reach_the_payload() {
        let mut c = claims();
        c.jti = Some("unique-1".into());
        c.extra = vec![("target_audience".into(), serde_json::json!("https://api.example.com"))];
        let jwt = sign(&rsa_pem(), Algorithm::Rs256, None, &c).unwrap();
        let payload = decode(jwt.split('.').nth(1).unwrap());
        assert_eq!(payload["jti"], "unique-1");
        assert_eq!(payload["target_audience"], "https://api.example.com");
    }

    #[test]
    fn algorithm_names_round_trip_and_unknown_ones_are_named_in_the_error() {
        assert_eq!(Algorithm::parse("RS256").unwrap(), Algorithm::Rs256);
        assert_eq!(Algorithm::parse("ES256").unwrap(), Algorithm::Es256);
        // HS256 is a shared secret wearing asymmetric clothes; saying so beats "unsupported".
        let err = Algorithm::parse("HS256").unwrap_err();
        assert!(format!("{err}").contains("HS256"), "{err}");
    }
}
