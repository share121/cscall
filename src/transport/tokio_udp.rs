use crate::{CsError, transport::Transport};
use std::net::SocketAddr;
use tokio::net::UdpSocket;

impl Transport for UdpSocket {
    const BUFFER_SIZE: usize = 1500;

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<(), CsError> {
        self.send_to(buf, addr).await?;
        Ok(())
    }

    async fn recv_buf_from(&self, buf: &mut Vec<u8>) -> Result<(usize, SocketAddr), CsError> {
        let (size, addr) = self.recv_buf_from(buf).await?;
        Ok((size, addr))
    }
}
