use crate::{
    EventType, MAX_LIFE, UID_LEN,
    common::{CsError, heartbeat},
    connection::Connection,
    crypt::Crypt,
    package::{PackageDecoder, PackageEncoder},
};
use rand::{TryRngCore, rngs::OsRng};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::UdpSocket;

pub struct Client<C: Crypt> {
    pub socket: Arc<UdpSocket>,
    pwd: std::vec::Vec<u8>,
    addr: SocketAddr,
    conn: Arc<Mutex<Option<Connection<C>>>>,
}

impl<C: Crypt> Client<C> {
    pub async fn connect(
        conn: Arc<Mutex<Option<Connection<C>>>>,
        socket: Arc<UdpSocket>,
        pwd: &[u8],
        addr: SocketAddr,
    ) -> Result<(), CsError> {
        let mut buf = vec![0u8; 1500];
        // 发送 Hello 直到服务器回应 AckHello 并解析 server_salt
        let server_salt: C::Salt = loop {
            match socket.send(&PackageEncoder::hello()).await {
                Err(e) => tracing::warn!("Failed to send Hello: {e:?}"),
                Ok(_) => match socket.recv(&mut buf).await {
                    Err(e) => tracing::warn!("Failed to receive AckHello: {e:?}"),
                    Ok(len) => match PackageDecoder::ack_hello::<C>(&buf[..len]) {
                        Ok(s) => break s,
                        Err(e) => tracing::warn!(
                            "Expected AckHello but received: {:?} Error: {:?}",
                            &buf[..len],
                            e
                        ),
                    },
                },
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        // 混合 client_salt 和 server_salt 并生成 session_crypt 和 server_crypt
        let client_salt = C::gen_salt();
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
        let session_crypt = C::new(&session_key).map_err(|_| CsError::CreateCrypt)?;
        let server_crypt = C::new(&server_key).map_err(|_| CsError::CreateCrypt)?;
        // 发送 Connect 请求，并使用 server_crypt 加密，服务器返回的数据用 session_crypt 验证 AckConnect
        let mut uid = [0u8; UID_LEN];
        OsRng.try_fill_bytes(&mut uid)?;
        loop {
            let data = PackageEncoder::connect(&server_crypt, &session_key, &uid)
                .map_err(|_| CsError::Encrypt)?;
            match socket.send(&data).await {
                Err(e) => tracing::warn!("Failed to send Connect: {e:?}"),
                Ok(_) => match socket.recv(&mut buf).await {
                    Err(e) => tracing::warn!("Failed to receive AckConnect: {e:?}"),
                    Ok(len) => {
                        buf.truncate(len);
                        match PackageDecoder::ack_connect(&session_crypt, &mut buf) {
                            Ok(uid) if buf == uid => break,
                            Ok(uid) => {
                                tracing::warn!("Received AckConnect but uid is not same: {uid:?}")
                            }
                            Err(e) => tracing::warn!(
                                "Expected AckConnect but received: {:?} Error: {:?}",
                                &buf,
                                e
                            ),
                        };
                    }
                },
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let new_conn = Connection {
            addr,
            session_crypt: Arc::new(session_crypt),
            uid,
            count: 1,
            life: MAX_LIFE,
            max_count: 0,
            replay_bitmap: 0,
            heartbeat_handle: None,
        };
        conn.lock()
            .map_err(|_| CsError::ConnectionBroken)?
            .replace(new_conn);
        let heartbeat_handle = tokio::spawn({
            let conn = conn.clone();
            let socket = socket.clone();
            async move { heartbeat(&conn, &socket).await }
        });
        conn.lock()
            .map_err(|_| CsError::ConnectionBroken)?
            .as_mut()
            .ok_or(CsError::ConnectionBroken)?
            .heartbeat_handle = Some(heartbeat_handle);
        Ok(())
    }

    pub async fn new(pwd: std::vec::Vec<u8>, addr: SocketAddr) -> Result<Self, CsError> {
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

    pub async fn reconnect(&self) -> Result<(), CsError> {
        Self::connect(self.conn.clone(), self.socket.clone(), &self.pwd, self.addr).await?;
        Ok(())
    }

    pub async fn send(&self, buf: &mut Vec<u8>) -> Result<(), CsError> {
        let (session_crypt, count, uid) = Connection::try_pre_encrypt(&self.conn)?;
        PackageEncoder::encrypted(buf, &*session_crypt, count, &uid)
            .map_err(|_| CsError::Encrypt)?;
        self.socket.send(buf).await?;
        Ok(())
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<bool, CsError> {
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
                let session_crypt = self
                    .conn
                    .lock()
                    .map_err(|_| CsError::ConnectionBroken)?
                    .as_ref()
                    .ok_or(CsError::ConnectionBroken)?
                    .session_crypt
                    .clone();
                let (count, uid) = PackageDecoder::encrypted(&*session_crypt, buf)
                    .map_err(|_| CsError::Decrypt)?;
                self.conn
                    .lock()
                    .map_err(|_| CsError::ConnectionBroken)?
                    .as_mut()
                    .ok_or(CsError::ConnectionBroken)?
                    .check_and_update(count, uid, None)?;
                match event_type {
                    EventType::Encrypted => Ok(true),
                    EventType::Heartbeat => {
                        tracing::info!("Received heartbeat Request");
                        let (session_crypt, count, uid) = Connection::try_pre_encrypt(&self.conn)?;
                        let data = PackageEncoder::heartbeat(&*session_crypt, count, &uid)
                            .map_err(|_| CsError::Decrypt)?;
                        self.socket.send(&data).await?;
                        Ok(false)
                    }
                    EventType::AckHeartbeat => {
                        tracing::info!("Received heartbeat ACK");
                        Ok(false)
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
