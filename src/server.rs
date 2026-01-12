use crate::{
    EventType, HEARTBEAT_MS, UID_LEN,
    common::{CsError, heartbeat},
    connection::Connection,
    crypto::Crypto,
    package::{PackageDecoder, PackageEncoder},
};
use dashmap::DashMap;
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

pub struct Server<C: Crypto> {
    socket: Arc<UdpSocket>,
    server_crypto: C,
    server_salt: C::Salt,
    connections: Arc<DashMap<[u8; UID_LEN], Connection<C>>>,
    heartbeat_handle: tokio::task::JoinHandle<()>,
}

impl<C: Crypto> Drop for Server<C> {
    fn drop(&mut self) {
        self.heartbeat_handle.abort();
    }
}

impl<C: Crypto> Server<C> {
    pub async fn new(pwd: &[u8], socket: Arc<UdpSocket>) -> Result<Self, CsError> {
        let server_salt = C::gen_salt().map_err(|_| CsError::GenerateSalt)?;
        let server_key = tokio::task::spawn_blocking({
            let pwd = pwd.to_vec();
            let server_salt = server_salt.clone();
            move || C::derive_key(&pwd, &server_salt)
        })
        .await
        .map_err(|_| CsError::DeriveKey)?
        .map_err(|_| CsError::DeriveKey)?;
        let server_crypto = C::new(server_key.as_ref()).map_err(|_| CsError::CreateCrypto)?;
        let connections: Arc<DashMap<[u8; UID_LEN], Connection<C>>> = Arc::new(DashMap::new());
        let heartbeat_handle = tokio::spawn({
            let connections = connections.clone();
            let socket = socket.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS)).await;
                    let mut dead = Vec::new();
                    let uids: Vec<_> = connections.iter().map(|c| *c.key()).collect();
                    for uid in uids {
                        if let Some(conn) = connections.get(&uid) {
                            let conn_clone = conn.clone();
                            drop(conn);
                            match heartbeat(&conn_clone, &socket).await {
                                Ok(()) => {}
                                Err(CsError::ConnectionBroken) => dead.push(uid),
                                Err(e) => tracing::warn!("Heartbeat error {e:?}"),
                            }
                        }
                    }
                    for uid in dead {
                        connections.remove(&uid);
                    }
                }
            }
        });
        Ok(Self {
            socket,
            server_crypto,
            server_salt,
            connections,
            heartbeat_handle,
        })
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<Option<([u8; UID_LEN], u64)>, CsError> {
        if buf.capacity() < 1500 {
            buf.reserve(1500 - buf.len());
        }
        unsafe { buf.set_len(1500) };
        let (len, addr) = self.socket.recv_from(buf).await?;
        if len == 0 {
            return Err(CsError::InvalidFormat);
        }
        match buf[len - 1] {
            EventType::Hello => {
                PackageDecoder::hello(&buf[..len])?;
                let data = PackageEncoder::ack_hello::<C>(&self.server_salt);
                self.socket.send_to(&data, addr).await?;
                Ok(None)
            }
            EventType::Connect => {
                buf.truncate(len);
                let (old, uid) = PackageDecoder::connect(&self.server_crypto, buf)?;
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                if old.abs_diff(now) > 60 {
                    return Err(CsError::InvalidTimestamp(old));
                }
                if let Ok(session_crypto) = self
                    .connections
                    .get(&uid)
                    .ok_or(CsError::ConnectionBroken)
                    .and_then(|c| c.sessiton_crypto())
                {
                    let data = PackageEncoder::ack_connect(&*session_crypto, &uid)?;
                    self.socket.send_to(&data, addr).await?;
                    return Ok(None);
                }
                let session_crypto = C::new(buf).map_err(|_| CsError::CreateCrypto)?;
                let data = PackageEncoder::ack_connect(&session_crypto, &uid)?;
                self.socket.send_to(&data, addr).await?;
                let conn = Connection::new(uid, addr, Arc::new(session_crypto));
                self.connections.insert(uid, conn);
                Ok(None)
            }
            event_type
            @ (EventType::Encrypted | EventType::Heartbeat | EventType::AckHeartbeat) => {
                buf.truncate(len);
                let uid = PackageDecoder::peek_uid(buf, 1)?;
                let conn = self
                    .connections
                    .get(&uid)
                    .ok_or(CsError::ConnectionBroken)?
                    .clone();
                let session_crypto = conn.sessiton_crypto()?;
                let (count, uid) = PackageDecoder::encrypted(&*session_crypto, buf)?;
                conn.check_and_update(count, uid, Some(addr))?;
                match event_type {
                    EventType::Encrypted => Ok(Some((uid, count))),
                    EventType::Heartbeat => {
                        tracing::debug!("Received heartbeat Request");
                        let (session_crypto, count, uid, addr) = conn.pre_encrypt()?;
                        let data = PackageEncoder::ack_heartbeat(&*session_crypto, count, &uid)?;
                        self.socket.send_to(&data, addr).await?;
                        Ok(None)
                    }
                    EventType::AckHeartbeat => {
                        tracing::debug!("Received heartbeat ACK");
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

    pub async fn get(&self, uid: &[u8; UID_LEN]) -> Result<Channel<C>, CsError> {
        Ok(Channel {
            conn: self
                .connections
                .get(uid)
                .ok_or(CsError::ConnectionBroken)?
                .clone(),
            socket: self.socket.clone(),
        })
    }

    pub async fn send_all(&self, data: &[u8]) -> Result<(), CsError> {
        let conns: Vec<Connection<C>> = self.connections.iter().map(|c| c.clone()).collect();
        for conn in conns {
            let (session_crypto, count, uid, addr) = conn.pre_encrypt()?;
            let mut buf = data.to_vec();
            PackageEncoder::encrypted(&mut buf, &*session_crypto, count, &uid)?;
            self.socket.send_to(&buf, addr).await?;
        }
        Ok(())
    }
}

pub struct Channel<C: Crypto> {
    conn: Connection<C>,
    socket: Arc<UdpSocket>,
}

impl<C: Crypto> Channel<C> {
    pub async fn send(&self, buf: &mut Vec<u8>) -> Result<(), CsError> {
        let (session_crypto, count, uid, addr) = self.conn.pre_encrypt()?;
        PackageEncoder::encrypted(buf, &*session_crypto, count, &uid)?;
        self.socket.send_to(buf, addr).await?;
        Ok(())
    }
}
