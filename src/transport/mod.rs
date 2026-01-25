use crate::CsError;
use std::net::SocketAddr;

#[cfg(feature = "tokio_udp")]
pub mod tokio_udp;

pub trait Transport: Send + Sync + 'static {
    const BUFFER_SIZE: usize;

    fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
    ) -> impl Future<Output = Result<(), CsError>> + Send;
    fn recv_buf_from(
        &self,
        buf: &mut Vec<u8>,
    ) -> impl Future<Output = Result<SocketAddr, CsError>> + Send;
}
