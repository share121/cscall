use crate::{Connection, UID_LEN, crypt::Crypt};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub struct Server<const SALT_LEN: usize, const KEY_LEN: usize, C: Crypt<SALT_LEN, KEY_LEN>> {
    socket: Arc<UdpSocket>,
    connections: DashMap<[u8; UID_LEN], Connection<SALT_LEN, KEY_LEN, C>>,
}

impl<const SALT_LEN: usize, const KEY_LEN: usize, C: Crypt<SALT_LEN, KEY_LEN>>
    Server<SALT_LEN, KEY_LEN, C>
{
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            connections: DashMap::new(),
        }
    }

    // pub fn recv() -> Result<(), ServerError> {}
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Failed to send data")]
    Socket(#[from] std::io::Error),
    #[error("Failed to derive key")]
    DeriveKey,
    #[error("Failed to create crypt")]
    CreateCrypt,
    #[error("Failed to encrypt data")]
    Encrypt,
    #[error("Failed to decrypt data")]
    Decrypt,
    #[error("Mismatched data")]
    MismatchData,
    #[error("Connection broken")]
    ConnectionBroken,
    #[error("Invalid counter")]
    InvalidCounter,
}
