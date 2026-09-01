//! Byte-for-byte relaying between the client and upstream.
//!
//! At M1 an allowed connection is copied verbatim: the proxy has decided *whether*, and has
//! nothing to say about *what*.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Bytes moved in each direction.
#[derive(Debug, Default, Clone, Copy)]
pub struct Transferred {
    pub client_to_upstream: u64,
    pub upstream_to_client: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The inspector refused the client's opening bytes.
    #[error("{0}")]
    Rejected(String),
}

/// Cap on the opening bytes gathered for inspection. A TLS ClientHello that does not fit in
/// this is not one we need to understand.
const MAX_OPENING_BYTES: usize = 8 * 1024;

/// Relay, giving `inspect` a look at the client's opening bytes first.
///
/// The two directions run concurrently, so the upstream→client half is never held up waiting
/// for the client to speak. That matters: peeking the client socket *before* starting the
/// relay stalls every server-speaks-first protocol (SMTP, many databases, plain TCP tunnels)
/// for the length of the peek timeout, and the proxy has no business assuming the client
/// talks first.
///
/// `inspect` sees only the opening bytes and is called at most once. Returning `Err` aborts
/// before a single byte reaches the upstream.
pub async fn relay_inspected<A, B, F>(
    client: &mut A,
    upstream: &mut B,
    inspect: F,
) -> Result<Transferred, RelayError>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
    F: FnOnce(&[u8]) -> Result<(), String>,
{
    let (mut client_r, mut client_w) = tokio::io::split(client);
    let (mut upstream_r, mut upstream_w) = tokio::io::split(upstream);

    let downstream = async {
        let n = tokio::io::copy(&mut upstream_r, &mut client_w).await?;
        let _ = client_w.shutdown().await;
        Ok::<u64, RelayError>(n)
    };

    let upstream_side = async {
        let opening = read_opening(&mut client_r).await?;
        inspect(&opening).map_err(RelayError::Rejected)?;

        upstream_w.write_all(&opening).await?;
        let rest = tokio::io::copy(&mut client_r, &mut upstream_w).await?;
        let _ = upstream_w.shutdown().await;
        Ok::<u64, RelayError>(opening.len() as u64 + rest)
    };

    let (upstream_to_client, client_to_upstream) = tokio::try_join!(downstream, upstream_side)?;
    Ok(Transferred { client_to_upstream, upstream_to_client })
}

/// Gather enough of the client's first bytes to recognise a TLS ClientHello.
///
/// Stops as soon as the answer is knowable: a first byte that is not a handshake record means
/// there is no SNI to check, so there is nothing to wait for.
async fn read_opening<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    loop {
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return Ok(buf); // client closed without speaking
        }
        buf.extend_from_slice(&chunk[..n]);

        if buf[0] != 0x16 {
            return Ok(buf); // not a TLS handshake; nothing further to gather
        }
        if buf.len() >= 5 {
            let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if buf.len() >= 5 + record_len || buf.len() >= MAX_OPENING_BYTES {
                return Ok(buf);
            }
        }
        if buf.len() >= MAX_OPENING_BYTES {
            return Ok(buf);
        }
    }
}

/// Relay with no inspection.
pub async fn relay<A, B>(client: &mut A, upstream: &mut B) -> std::io::Result<Transferred>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (up, down) = tokio::io::copy_bidirectional(client, upstream).await?;
    Ok(Transferred { client_to_upstream: up, upstream_to_client: down })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn upstream_speaks_first_without_waiting_for_the_client() {
        // The regression this guards: inspecting by peeking the client socket before starting
        // the relay deadlocks a server-first protocol until the peek times out.
        let (mut client, mut client_end) = tokio::io::duplex(4096);
        let (mut upstream_end, mut upstream) = tokio::io::duplex(4096);

        upstream_end.write_all(b"220 ready\r\n").await.unwrap();

        let relayed = tokio::spawn(async move {
            relay_inspected(&mut client_end, &mut upstream, |_| Ok(())).await
        });

        let mut got = [0u8; 11];
        tokio::time::timeout(std::time::Duration::from_secs(2), client.read_exact(&mut got))
            .await
            .expect("the greeting must arrive before the client says anything")
            .unwrap();
        assert_eq!(&got, b"220 ready\r\n");

        drop(client);
        drop(upstream_end);
        let _ = relayed.await;
    }

    #[tokio::test]
    async fn rejection_stops_bytes_reaching_upstream() {
        let (mut client, mut client_end) = tokio::io::duplex(4096);
        let (mut upstream_end, mut upstream) = tokio::io::duplex(4096);

        client.write_all(b"secret payload").await.unwrap();

        let relayed = tokio::spawn(async move {
            relay_inspected(&mut client_end, &mut upstream, |_| Err("nope".into())).await
        });

        let mut buf = vec![0u8; 64];
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            upstream_end.read(&mut buf),
        )
        .await;
        // Either the read times out or it reports EOF; what must not happen is the payload
        // arriving.
        match n {
            Err(_elapsed) => {}
            Ok(Ok(0)) => {}
            Ok(other) => panic!("upstream received data after a rejection: {other:?}"),
        }
        assert!(matches!(relayed.await.unwrap(), Err(RelayError::Rejected(_))));
    }
}
