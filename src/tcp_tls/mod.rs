//! TCP TLS record layer (RFC 8446).
//!
//! Standalone middleware: TCP socket ↔ TlsConnection ↔ H2Connection / Http1Connection.

pub mod client;
pub mod connection;
pub mod io;
pub mod record;
pub mod server;

pub use client::TlsClient;
pub use connection::{TlsConnection, TlsEvent};
pub use io::{TlsIo, TlsIoBufs};
pub use server::TlsServer;

use crate::buf::Buf;
use crate::crypto::CryptoProvider;
use crate::error::Error;
use crate::tls::handshake::ServerTlsConfig;

/// A set of three `'static mut` slices backing one TLS connection's I/O
/// buffers (net recv/send + app send; decrypted plaintext lives in place in
/// `net_recv`). Lets a memory-tight target keep the large TLS/h2 I/O buffers
/// in `.bss` instead of the heap.
///
/// Each slice must be at least `BUF` bytes when wrapped (see
/// [`TlsParts::new_server_in`]). A kit is handed to the manager via
/// `add_tls_buffer_kit`, lent to a connection on accept, and reclaimed (via
/// [`Buf::take_static`]) when that connection tears down, so the same `.bss`
/// region is reused across the connection's lifetime — never freed/reallocated.
#[cfg(feature = "alloc")]
pub struct TlsBufKit {
    pub net_recv: &'static mut [u8],
    pub net_send: &'static mut [u8],
    pub app_send: &'static mut [u8],
}

/// Pre-handshake TLS state with shared buffers.
///
/// Used by the connection manager to drive TLS handshake before protocol
/// selection (ALPN). Once the handshake completes, call `alpn()` and then
/// construct the appropriate HTTP type via `from_parts`.
pub struct TlsParts<C: CryptoProvider, const BUF: usize = 18432> {
    pub tls: TlsConnection<C>,
    pub net_recv: Buf<BUF>,
    pub net_send: Buf<BUF>,
    pub app_send: Buf<BUF>,
}

impl<C: CryptoProvider, const BUF: usize> TlsParts<C, BUF>
where
    C::Hkdf: Default,
{
    /// Create new server-side TLS parts with heap-backed buffers.
    pub fn new_server(
        provider: C,
        config: ServerTlsConfig,
        secret: [u8; 32],
        random: [u8; 32],
    ) -> Self {
        let mut net_recv = Buf::new();
        // Reserve the receive buffer to its cap up front. A server's receive
        // buffer fills to a whole record on any real upload, and growing it
        // there by doubling (`reserve_clamped`: 8 → 16 → 18 KiB) holds the
        // old and new blocks together across the last step — a transient of
        // one extra buffer's worth on a heap that is sized for its peak
        // (main module, 2026-09-17: 65 KB steady during an h2-TLS OTA, ~81 KB
        // instantaneous, and that 16 KB is what forced the heap sizing).
        // One allocation at accept costs nothing extra at the peak and
        // removes the transient. Fallible: under pressure the buffer simply
        // grows lazily as before. The send buffers stay lazy — a server's
        // responses rarely approach the cap.
        #[cfg(feature = "alloc")]
        let _ = net_recv.try_reserve(BUF);
        Self {
            tls: TlsConnection::new_server(provider, config, secret, random),
            net_recv,
            net_send: Buf::new(),
            app_send: Buf::new(),
        }
    }

    /// Create new server-side TLS parts backed by a caller-provided
    /// [`TlsBufKit`] (`'static` slices) instead of the heap. The three I/O
    /// buffers never touch the allocator for this connection's lifetime.
    ///
    /// # Panics
    /// If any kit slice is shorter than `BUF` (see [`Buf::from_static`]).
    #[cfg(feature = "alloc")]
    pub fn new_server_in(
        provider: C,
        config: ServerTlsConfig,
        secret: [u8; 32],
        random: [u8; 32],
        kit: TlsBufKit,
    ) -> Self {
        Self {
            tls: TlsConnection::new_server(provider, config, secret, random),
            net_recv: Buf::from_static(kit.net_recv),
            net_send: Buf::from_static(kit.net_send),
            app_send: Buf::from_static(kit.app_send),
        }
    }

    /// Reclaim the `'static` slices backing this connection, if all three are
    /// static-backed. Returns `None` (recovering nothing) if any buffer is
    /// heap-backed — the caller should then just drop the parts. After this
    /// call the parts' buffers are empty heap-backed `Buf`s.
    #[cfg(feature = "alloc")]
    pub fn reclaim_buffers(&mut self) -> Option<TlsBufKit> {
        // Only succeed if every buffer is static — a mixed state can't form a
        // complete kit. Probe by taking all three; if any is None, put back the
        // ones we took. In practice the three are constructed together, so they
        // are uniformly static or uniformly heap.
        let net_recv = self.net_recv.take_static();
        let net_send = self.net_send.take_static();
        let app_send = self.app_send.take_static();
        match (net_recv, net_send, app_send) {
            (Some(net_recv), Some(net_send), Some(app_send)) => Some(TlsBufKit {
                net_recv,
                net_send,
                app_send,
            }),
            // Partial/none: any slices we took are already swapped out into the
            // parts as empty heap Bufs; the recovered slices (if any) are
            // dropped here, which only leaks `.bss` (never the heap) and is not
            // reachable given uniform construction.
            _ => None,
        }
    }

    /// Feed encrypted TCP data, driving the TLS handshake forward.
    pub fn feed_data(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_send_buf: &mut self.app_send,
        };
        self.tls.feed_data(&mut tls_io, data)
    }

    /// Pull outgoing encrypted TLS data (handshake messages).
    pub fn poll_output<'a>(&mut self, buf: &'a mut [u8]) -> Option<&'a [u8]> {
        let mut tls_io: TlsIo<'_, BUF> = TlsIo {
            recv_buf: &mut self.net_recv,
            send_buf: &mut self.net_send,
            app_send_buf: &mut self.app_send,
        };
        self.tls.poll_output(&mut tls_io, buf)
    }

    /// Whether the TLS handshake is complete.
    pub fn is_active(&self) -> bool {
        self.tls.is_active()
    }

    /// Whether the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.tls.is_closed()
    }

    /// Get the negotiated ALPN protocol (available after handshake).
    pub fn alpn(&self) -> Option<&[u8]> {
        self.tls.alpn()
    }
}

#[cfg(all(test, feature = "alloc", feature = "rustcrypto-aes"))]
mod reserve_tests {
    use super::*;
    use crate::crypto::rustcrypto::Aes128GcmProvider;
    use crate::tls::handshake::ServerTlsConfig;

    /// The server's receive buffer is allocated to its cap at accept, so the
    /// first full-size record never triggers a doubling reallocation; the
    /// send buffers stay lazy.
    #[test]
    fn server_parts_prereserve_the_receive_buffer() {
        let config = ServerTlsConfig {
            cert_der: &[],
            private_key_der: &[0u8; 32],
            alpn_protocols: &[b"h2"],
            transport_params: crate::tls::transport_params::TransportParams::default_params(),
        };
        let parts: TlsParts<Aes128GcmProvider, 18432> =
            TlsParts::new_server(Aes128GcmProvider, config, [0u8; 32], [0u8; 32]);
        assert!(
            parts.net_recv.allocated_capacity() >= 18432,
            "{}",
            parts.net_recv.capacity()
        );
        assert!(parts.net_recv.is_empty());
        assert_eq!(parts.net_send.allocated_capacity(), 0);
        assert_eq!(parts.app_send.allocated_capacity(), 0);
    }
}
