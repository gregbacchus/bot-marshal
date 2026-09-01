//! Telling the user how to trust the generated CA.
//!
//! This is not incidental UX. A proxy the agent does not trust fails with certificate errors
//! that look like network problems, and the natural next step for anyone debugging that is to
//! disable verification entirely — which is a far worse outcome than the proxy never having
//! been installed. Making the trust step obvious and copy-pasteable is part of the security
//! design, not decoration.

/// Instructions for trusting `cert_path`, covering the stores that matter in practice.
///
/// Language runtimes are listed alongside the OS stores because most of them ignore the OS
/// store entirely: an agent that shells out to `git`, `npm`, `pip` and `curl` is consulting
/// four different trust databases, and getting only the OS one right leaves three of them
/// failing in ways that look unrelated.
pub fn instructions(cert_path: &str) -> String {
    format!(
        "\
Trust the CA so the agent's tools accept intercepted connections.

  Per-process (safest — scoped to what you launch, no system change):
    export SSL_CERT_FILE={cert_path}          # OpenSSL, curl, python (certifi-aware)
    export REQUESTS_CA_BUNDLE={cert_path}     # python requests
    export NODE_EXTRA_CA_CERTS={cert_path}    # node, npm
    export GIT_SSL_CAINFO={cert_path}         # git
    export CARGO_HTTP_CAINFO={cert_path}      # cargo

  System store (affects every process on the machine — prefer the above):
    Debian/Ubuntu:  sudo cp {cert_path} /usr/local/share/ca-certificates/bot-marshal.crt \\
                    && sudo update-ca-certificates
    Fedora/RHEL:    sudo cp {cert_path} /etc/pki/ca-trust/source/anchors/bot-marshal.crt \\
                    && sudo update-ca-trust
    macOS:          sudo security add-trusted-cert -d -r trustRoot \\
                    -k /Library/Keychains/System.keychain {cert_path}

Anything that pins certificates will still refuse, correctly. List those hosts under
`tls.passthrough` so bot-marshal tunnels them without interception."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instructions_mention_the_path_and_the_runtimes_that_ignore_the_os_store() {
        let out = instructions("/tmp/ca.crt");
        assert!(out.contains("/tmp/ca.crt"));
        for runtime in ["NODE_EXTRA_CA_CERTS", "GIT_SSL_CAINFO", "REQUESTS_CA_BUNDLE"] {
            assert!(out.contains(runtime), "missing {runtime}");
        }
        assert!(out.contains("passthrough"), "pinned hosts need an escape hatch");
    }
}
