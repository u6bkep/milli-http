//! Shared HTTP types used across HTTP/1.1, HTTP/2, and HTTP/3.

pub mod header;
pub mod method;
pub mod server_conn;
pub mod sse;
pub mod status;

pub use header::Header;
pub use method::Method;
pub use status::StatusCode;

/// Timeout configuration for HTTP connections.
#[derive(Debug, Clone, Copy)]
pub struct TimeoutConfig {
    /// Close if no bytes have been received from the peer and none handed
    /// to the connection for sending for N microseconds (RFC 9000 §10.1
    /// style: traffic in either direction restarts the timer). A parked
    /// keep-alive connection is reaped; an in-progress transfer in either
    /// direction is not. Applies to HTTP/1.1 and HTTP/2; QUIC keeps its own
    /// transport idle timer.
    pub idle_timeout_us: Option<u64>,
    /// Close if headers not received within N microseconds of connection/request start.
    pub header_timeout_us: Option<u64>,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            idle_timeout_us: None,
            header_timeout_us: None,
        }
    }
}
