use crate::{COUNT_LEN, Connection, EventType, REORDER_WINDOW, UID_LEN, crypt::Crypt};
use rand::{TryRngCore, rngs::OsRng};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UdpSocket;

pub const MAX_LIFE: u32 = 4;
pub const HEARTBEAT_MS: u64 = 5000;

pub struct Client<const SALT_LEN: usize, const KEY_LEN: usize, C: Crypt<SALT_LEN, KEY_LEN>> {
    pub socket: Arc<UdpSocket>,
    pwd: Vec<u8>,
    addr: SocketAddr,
    conn: Arc<Mutex<Option<Connection<SALT_LEN, KEY_LEN, C>>>>,
}

impl<const SALT_LEN: usize, const KEY_LEN: usize, C: Crypt<SALT_LEN, KEY_LEN>>
    Client<SALT_LEN, KEY_LEN, C>
{
    pub async fn connect(
        conn: Arc<Mutex<Option<Connection<SALT_LEN, KEY_LEN, C>>>>,
        socket: Arc<UdpSocket>,
        pwd: &[u8],
        addr: SocketAddr,
    ) -> Result<(), ClientError> {
        let mut buf = [0u8; 1500];
        // 发送 Hello 直到服务器回应 AckHello 并解析 server_salt
        let server_salt: [u8; SALT_LEN] = loop {
            match socket.send(&[EventType::Hello as u8]).await {
                Err(e) => tracing::warn!("Failed to send Hello: {e:?}"),
                Ok(_) => match socket.recv(&mut buf).await {
                    Err(e) => tracing::warn!("Failed to receive AckHello: {e:?}"),
                    Ok(len) => {
                        if len == SALT_LEN + 1 && buf[len - 1] == EventType::AckHello as u8 {
                            match buf[..len - 1].try_into() {
                                Ok(s) => break s,
                                Err(e) => tracing::warn!(
                                    "Failed to convert server salt bytes to array: {e:?}"
                                ),
                            }
                        } else {
                            tracing::warn!("Expected AckHello but received: {:?}", &buf[..len]);
                        }
                    }
                },
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        // 混合 client_salt 和 server_salt 并生成 session_crypt 和 server_crypt
        let client_salt = C::gen_salt();
        let mix_salt = C::mix_salt(&server_salt, &client_salt).map_err(|_| ClientError::MixSalt)?;
        let session_key = tokio::task::spawn_blocking({
            let pwd = pwd.to_vec();
            move || C::derive_key(&pwd, &mix_salt)
        });
        let server_key = tokio::task::spawn_blocking({
            let pwd = pwd.to_vec();
            move || C::derive_key(&pwd, &server_salt)
        });
        let (session_key, server_key) =
            tokio::try_join!(session_key, server_key).map_err(|_| ClientError::DeriveKey)?;
        let session_key = session_key.map_err(|_| ClientError::DeriveKey)?;
        let server_key = server_key.map_err(|_| ClientError::DeriveKey)?;
        let session_crypt = C::new(&session_key).map_err(|_| ClientError::CreateCrypt)?;
        let server_crypt = C::new(&server_key).map_err(|_| ClientError::CreateCrypt)?;
        // 发送 Connect 请求，并使用 server_crypt 加密，服务器返回的数据用 session_crypt 验证 AckConnect
        let mut uid = [0u8; UID_LEN];
        OsRng.try_fill_bytes(&mut uid)?;
        let mut data = Vec::with_capacity(KEY_LEN + UID_LEN + 1);
        data.extend_from_slice(&session_key);
        data.extend_from_slice(&uid);
        server_crypt
            .encrypt(&[], &mut data)
            .map_err(|_| ClientError::Encrypt)?;
        data.push(EventType::Connect as u8);
        loop {
            match socket.send(&data).await {
                Err(e) => tracing::warn!("Failed to send Connect: {e:?}"),
                Ok(_) => match socket.recv(&mut buf).await {
                    Err(e) => tracing::warn!("Failed to receive AckConnect: {e:?}"),
                    Ok(len) => {
                        if len > 0 && buf[len - 1] == EventType::AckConnect as u8 {
                            let mut buf = buf[..len - 1].to_vec();
                            session_crypt
                                .decrypt(&[], &mut buf)
                                .map_err(|_| ClientError::Decrypt)?;
                            if buf == uid {
                                break;
                            } else {
                                tracing::warn!("Expected AckConnect but received: {buf:?}");
                            }
                        } else {
                            tracing::warn!("Expected AckConnect but received: {:?}", &buf[..len]);
                        }
                    }
                },
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let new_conn = Connection {
            addr,
            crypt: Arc::new(session_crypt),
            uid,
            count: 1,
            life: MAX_LIFE,
            max_count: 0,
            replay_bitmap: 0,
            heartbeat_handle: None,
        };
        conn.lock().unwrap().replace(new_conn);
        let heartbeat_handle = tokio::spawn({
            let conn = conn.clone();
            async move {
                let mut buf = Vec::with_capacity(COUNT_LEN + UID_LEN + 1);
                loop {
                    tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS)).await;
                    // 构造 heartbeat 数据包
                    // (count) + uid + EventType::Heartbeat
                    buf.clear();
                    if let Err(e) = Connection::encrypt(&conn, &mut buf) {
                        tracing::warn!("Failed to encrypt heartbeat packet: {:?}", e);
                        continue;
                    }
                    *buf.last_mut().unwrap() = EventType::Heartbeat as u8;
                    if let Err(e) = socket.send(&buf).await {
                        tracing::warn!("Failed to send heartbeat packet: {:?}", e);
                        continue;
                    }
                    let mut guard = conn.lock().unwrap();
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
                }
            }
        });
        conn.lock()
            .unwrap()
            .as_mut()
            .ok_or(ClientError::ConnectionBroken)?
            .heartbeat_handle = Some(heartbeat_handle);
        Ok(())
    }

    pub async fn new(pwd: Vec<u8>, addr: SocketAddr) -> Result<Self, ClientError> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(addr).await?;
        let conn = Arc::new(Mutex::new(None));
        Self::connect(conn.clone(), socket.clone(), &pwd, addr).await?;
        Ok(Self {
            socket,
            pwd,
            addr,
            conn,
        })
    }

    pub async fn reconnect(&self) -> Result<(), ClientError> {
        Self::connect(self.conn.clone(), self.socket.clone(), &self.pwd, self.addr).await?;
        Ok(())
    }

    /// (payload + count) + uid + EventType
    pub async fn send(&self, buf: &mut Vec<u8>) -> Result<(), ClientError> {
        Connection::encrypt(&self.conn, buf)?;
        self.socket.send(buf).await?;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<(), ClientError> {
        if buf.capacity() < 1500 {
            buf.reserve(1500 - buf.len());
        }
        unsafe { buf.set_len(1500) };
        let len = self.socket.recv(buf).await?;

        // 处理 EventType
        if len > UID_LEN && buf[len - 1] == EventType::Encrypted as u8 {
            buf.truncate(len - 1);
        } else {
            return Err(ClientError::MismatchData);
        }
        // 处理 uid
        let uid: [u8; UID_LEN] = buf[buf.len() - UID_LEN..]
            .try_into()
            .map_err(|_| ClientError::MismatchData)?;
        let guard = self.conn.lock().unwrap();
        let guard_ref = guard.as_ref().ok_or(ClientError::ConnectionBroken)?;
        if uid != guard_ref.uid {
            return Err(ClientError::MismatchData);
        }
        buf.truncate(buf.len() - UID_LEN);
        let crypt = guard_ref.crypt.clone();
        drop(guard);
        crypt.decrypt(&uid, buf).map_err(|_| ClientError::Decrypt)?;
        // 处理 count
        if buf.len() <= COUNT_LEN {
            return Err(ClientError::MismatchData);
        }
        let count = u64::from_le_bytes(
            buf[buf.len() - COUNT_LEN..]
                .try_into()
                .map_err(|_| ClientError::MismatchData)?,
        );
        let mut guard = self.conn.lock().unwrap();
        let guard = guard.as_mut().ok_or(ClientError::ConnectionBroken)?;
        if count > guard.max_count {
            guard.life = MAX_LIFE;
            let delta = count - guard.max_count;
            if delta >= REORDER_WINDOW {
                guard.replay_bitmap = 1;
            } else {
                guard.replay_bitmap = (guard.replay_bitmap << delta) | 1;
            }
            guard.max_count = count;
        } else {
            let delta = guard.max_count - count;
            if delta >= REORDER_WINDOW {
                tracing::warn!("Invalid counter");
                return Err(ClientError::InvalidCounter);
            } else {
                let mask = 1 << delta;
                if (guard.replay_bitmap & mask) != 0 {
                    tracing::warn!("Invalid counter");
                    return Err(ClientError::InvalidCounter);
                } else {
                    guard.replay_bitmap |= mask;
                }
            }
        }
        buf.truncate(buf.len() - COUNT_LEN);
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
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
