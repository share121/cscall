use crate::{MAX_LIFE, UID_LEN, connection::Connection, crypto::Crypto, package::PackageEncoder};
use tokio::net::UdpSocket;

#[derive(Debug, thiserror::Error)]
pub enum CsError {
    // IO
    #[error("Failed to send data")]
    Socket(#[from] std::io::Error),

    // 加解密
    #[error("Failed to mix salt")]
    MixSalt,
    #[error("Failed to derive key")]
    DeriveKey,
    #[error("Failed to create crypto")]
    CreateCrypto,
    #[error("Failed to generate UID")]
    GenerateUID(#[from] rand::rand_core::OsError),
    #[error("Failed to encrypt data")]
    Encrypt,
    #[error("Failed to decrypt data")]
    Decrypt,
    #[error("Failed to generate salt")]
    GenerateSalt,

    // 连接
    #[error("Connection broken")]
    ConnectionBroken,

    // 消息解码
    #[error("Invalid type")]
    InvalidType(Option<u8>),
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Invalid uid")]
    InvalidUid([u8; UID_LEN]),
    #[error("Invalid counter")]
    InvalidCounter(u64),
    #[error("Invalid timestamp")]
    InvalidTimestamp(u64),

    // 系统
    #[error("System time error")]
    SystemTime(#[from] std::time::SystemTimeError),
}

pub async fn heartbeat<C: Crypto>(conn: &Connection<C>, socket: &UdpSocket) -> Result<(), CsError> {
    let (session_crypto, uid, addr, life) = {
        let mut guard = conn.inner()?;
        let guard_ref = guard.as_mut().ok_or(CsError::ConnectionBroken)?;
        if guard_ref.life == 0 {
            *guard = None;
            tracing::warn!("Connection life expired");
            return Err(CsError::ConnectionBroken);
        }
        guard_ref.life -= 1;
        if guard_ref.life == MAX_LIFE - 1 {
            return Ok(());
        }
        (
            guard_ref.session_crypto.clone(),
            guard_ref.uid,
            guard_ref.addr,
            guard_ref.life,
        )
    };
    for _ in 0..usize::pow(2, MAX_LIFE - life - 2) {
        let count = {
            let mut guard = conn.inner()?;
            let guard_ref = guard.as_mut().ok_or(CsError::ConnectionBroken)?;
            let count = guard_ref.count;
            guard_ref.count += 1;
            count
        };
        let data = PackageEncoder::heartbeat(&*session_crypto, count, &uid)?;
        socket.send_to(&data, addr).await?;
    }
    Ok(())
}
