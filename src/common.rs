use crate::{
    HEARTBEAT_MS,
    connection::Connection,
    crypt::Crypt,
    package::{DecodeError, PackageEncoder},
};
use std::{sync::Mutex, time::Duration};
use tokio::net::UdpSocket;

#[derive(Debug, thiserror::Error)]
pub enum CsError {
    #[error("Failed to send data")]
    Socket(#[from] std::io::Error),
    #[error("Failed to mix salt")]
    MixSalt,
    #[error("Failed to derive key")]
    DeriveKey,
    #[error("Failed to create crypt")]
    CreateCrypt,
    #[error("Failed to generate UID")]
    GenerateUID(#[from] rand::rand_core::OsError),
    #[error("Failed to decode data {0:?}")]
    Decode(#[from] DecodeError),
    #[error("Failed to encrypt data")]
    Encrypt,
    #[error("Failed to decrypt data")]
    Decrypt,
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Connection broken")]
    ConnectionBroken,
    #[error("Invalid uid")]
    InvalidUid,
    #[error("Invalid counter")]
    InvalidCounter,
    #[error("Invalid timestamp")]
    InvalidTimestamp(u64),
    #[error("System time error")]
    SystemTime(#[from] std::time::SystemTimeError),
}

pub async fn heartbeat<C: Crypt>(conn: &Mutex<Option<Connection<C>>>, socket: &UdpSocket) {
    loop {
        tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS)).await;
        let (session_crypt, count, uid) = {
            let mut guard = match conn.lock() {
                Ok(g) => g,
                Err(e) => {
                    tracing::warn!("Connection broken Error: {:?}", e);
                    return;
                }
            };
            let guard_ref = match guard.as_mut() {
                Some(g) => g,
                None => {
                    tracing::warn!("Connection broken");
                    return;
                }
            };
            if guard_ref.life == 0 {
                *guard = None;
                tracing::warn!("Connection life expired");
                return;
            }
            guard_ref.life -= 1;
            guard_ref.pre_encrypt()
        };
        match PackageEncoder::heartbeat(&*session_crypt, count, &uid) {
            Ok(data) => {
                if let Err(e) = socket.send(&data.to_vec()).await {
                    tracing::warn!("Failed to send heartbeat packet: {:?}", e);
                }
            }
            Err(_) => tracing::warn!("Failed to encrypt heartbeat packet"),
        }
    }
}
