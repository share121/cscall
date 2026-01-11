use crate::{
    EventType, HEARTBEAT_MS, UID_LEN,
    common::{CsError, heartbeat},
    connection::Connection,
    crypto::Crypto,
    package::{PackageDecoder, PackageEncoder},
};
use rand::{TryRngCore, rngs::OsRng};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle};

pub struct Client<C: Crypto> {
    socket: Arc<UdpSocket>,
    pwd: Vec<u8>,
    addr: SocketAddr,
    conn: Connection<C>,
    heartbeat_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl<C: Crypto> Drop for Client<C> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<C: Crypto> Client<C> {
    pub async fn connect(
        conn: Connection<C>,
        socket: Arc<UdpSocket>,
        pwd: &[u8],
        addr: SocketAddr,
    ) -> Result<JoinHandle<()>, CsError> {
        let mut buf = vec![0u8; 1500];
        // 发送 Hello 直到服务器回应 AckHello 并解析 server_salt
        let server_salt: C::Salt = loop {
            match socket.send(&PackageEncoder::hello()).await {
                Err(e) => tracing::warn!("Failed to send Hello: {e:?}"),
                Ok(_) => {
                    if buf.capacity() < 1500 {
                        buf.reserve(1500 - buf.len());
                    }
                    unsafe { buf.set_len(1500) };
                    match socket.recv(&mut buf).await {
                        Err(e) => tracing::warn!("Failed to receive AckHello: {e:?}"),
                        Ok(len) => match PackageDecoder::ack_hello::<C>(&buf[..len]) {
                            Ok(s) => break s,
                            Err(e) => tracing::warn!(
                                "Expected AckHello but received: {:?} Error: {:?}",
                                &buf[..len],
                                e
                            ),
                        },
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        // 混合 client_salt 和 server_salt 并生成 session_crypto 和 server_crypto
        let client_salt = C::gen_salt().map_err(|_| CsError::GenerateSalt)?;
        let mix_salt = C::mix_salt(&server_salt, &client_salt).map_err(|_| CsError::MixSalt)?;
        let session_key = tokio::task::spawn_blocking({
            let pwd = pwd.to_vec();
            move || C::derive_key(&pwd, &mix_salt)
        });
        let server_key = tokio::task::spawn_blocking({
            let pwd = pwd.to_vec();
            move || C::derive_key(&pwd, &server_salt)
        });
        let (session_key, server_key) =
            tokio::try_join!(session_key, server_key).map_err(|_| CsError::DeriveKey)?;
        let session_key = session_key.map_err(|_| CsError::DeriveKey)?;
        let server_key = server_key.map_err(|_| CsError::DeriveKey)?;
        let session_crypto = C::new(session_key.as_ref()).map_err(|_| CsError::CreateCrypto)?;
        let server_crypto = C::new(server_key.as_ref()).map_err(|_| CsError::CreateCrypto)?;
        // 发送 Connect 请求，并使用 server_crypto 加密，服务器返回的数据用 session_crypto 验证 AckConnect
        let mut uid = [0u8; UID_LEN];
        OsRng.try_fill_bytes(&mut uid)?;
        loop {
            let data = PackageEncoder::connect(&server_crypto, &session_key, &uid)?;
            match socket.send(&data).await {
                Err(e) => tracing::warn!("Failed to send Connect: {e:?}"),
                Ok(_) => {
                    if buf.capacity() < 1500 {
                        buf.reserve(1500 - buf.len());
                    }
                    unsafe { buf.set_len(1500) };
                    match socket.recv(&mut buf).await {
                        Err(e) => tracing::warn!("Failed to receive AckConnect: {e:?}"),
                        Ok(len) => {
                            buf.truncate(len);
                            match PackageDecoder::ack_connect(&session_crypto, &mut buf) {
                                Ok(uid) if buf == uid => break,
                                Ok(uid) => {
                                    tracing::warn!(
                                        "Received AckConnect but uid is not same: {uid:?}"
                                    )
                                }
                                Err(e) => tracing::warn!(
                                    "Expected AckConnect but received: {:?} Error: {:?}",
                                    &buf,
                                    e
                                ),
                            };
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        conn.replace(uid, addr, Arc::new(session_crypto))?;
        let heartbeat_handle = tokio::spawn({
            let conn = conn.clone();
            let socket = socket.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS)).await;
                    match heartbeat(&conn, &socket).await {
                        Ok(()) => {}
                        Err(CsError::ConnectionBroken) => break,
                        Err(e) => tracing::warn!("Heartbeat error {e:?}"),
                    }
                }
            }
        });
        Ok(heartbeat_handle)
    }

    pub async fn new(pwd: std::vec::Vec<u8>, addr: SocketAddr) -> Result<Self, CsError> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        socket.connect(addr).await?;
        let conn = Connection::default();
        let handle = Self::connect(conn.clone(), socket.clone(), &pwd, addr).await?;
        Ok(Self {
            socket,
            pwd,
            addr,
            conn,
            heartbeat_handle: Mutex::new(Some(handle)),
        })
    }

    pub fn close(&self) {
        if let Some(heartbeat_handle) = self.heartbeat_handle.lock().unwrap().take() {
            heartbeat_handle.abort();
        }
    }

    pub async fn reconnect(&self) -> Result<(), CsError> {
        self.close();
        let handle =
            Self::connect(self.conn.clone(), self.socket.clone(), &self.pwd, self.addr).await?;
        self.heartbeat_handle.lock().unwrap().replace(handle);
        Ok(())
    }

    pub async fn send(&self, buf: &mut Vec<u8>) -> Result<(), CsError> {
        let (session_crypto, count, uid, addr) = self.conn.pre_encrypt()?;
        PackageEncoder::encrypted(buf, &*session_crypto, count, &uid)?;
        self.socket.send_to(buf, addr).await?;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<Option<([u8; UID_LEN], u64)>, CsError> {
        if buf.capacity() < 1500 {
            buf.reserve(1500 - buf.len());
        }
        unsafe { buf.set_len(1500) };
        let len = self.socket.recv(buf).await?;
        if len == 0 {
            return Err(CsError::InvalidFormat);
        }
        match buf[len - 1] {
            event_type
            @ (EventType::Encrypted | EventType::Heartbeat | EventType::AckHeartbeat) => {
                buf.truncate(len);
                let session_crypto = self.conn.sessiton_crypto()?;
                let (count, uid) = PackageDecoder::encrypted(&*session_crypto, buf)?;
                self.conn.check_and_update(count, uid, None)?;
                match event_type {
                    EventType::Encrypted => Ok(Some((uid, count))),
                    EventType::Heartbeat => {
                        tracing::info!("Received heartbeat Request");
                        let (session_crypto, count, uid, addr) = self.conn.pre_encrypt()?;
                        let data = PackageEncoder::ack_heartbeat(&*session_crypto, count, &uid)?;
                        self.socket.send_to(&data, addr).await?;
                        Ok(None)
                    }
                    EventType::AckHeartbeat => {
                        tracing::info!("Received heartbeat ACK");
                        Ok(None)
                    }
                    _ => Err(CsError::InvalidFormat),
                }
            }
            _ => {
                tracing::warn!("Received invalid package {:?}", &buf[..len]);
                Err(CsError::InvalidFormat)
            }
        }
    }
}
