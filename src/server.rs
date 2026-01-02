use crate::{
    EventType, HEARTBEAT_MS, MAX_LIFE, UID_LEN,
    common::{CsError, heartbeat},
    connection::{Connection, ConnectionMut},
    crypto::Crypto,
    package::{PackageDecoder, PackageEncoder},
};
use dashmap::DashMap;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

pub struct Server<C: Crypto> {
    socket: Arc<UdpSocket>,
    server_crypt: C,
    server_salt: C::Salt,
    connections: Arc<DashMap<[u8; UID_LEN], ConnectionMut<C>>>,
    heartbeat_handle: tokio::task::JoinHandle<()>,
}

impl<C: Crypto> Drop for Server<C> {
    fn drop(&mut self) {
        self.heartbeat_handle.abort();
    }
}

impl<C: Crypto> Server<C> {
    pub fn new(pwd: &[u8], socket: Arc<UdpSocket>) -> Result<Self, CsError> {
        let server_salt = C::gen_salt().map_err(|_| CsError::GenerateSalt)?;
        let server_key = C::derive_key(pwd, &server_salt).map_err(|_| CsError::DeriveKey)?;
        let server_crypt = C::new(server_key.as_ref()).map_err(|_| CsError::CreateCrypto)?;
        let connections: Arc<DashMap<[u8; UID_LEN], ConnectionMut<C>>> = Arc::new(DashMap::new());
        let heartbeat_handle = tokio::spawn({
            let connections = connections.clone();
            let socket = socket.clone();
            async move {
                loop {
                    tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS)).await;
                    let mut dead = Vec::new();
                    for conn in connections.iter() {
                        match heartbeat(&conn, &socket).await {
                            Ok(()) => {}
                            Err(CsError::ConnectionBroken) => dead.push(*conn.key()),
                            Err(e) => tracing::warn!("未知错误 {e:?}"),
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
            server_crypt,
            server_salt,
            connections,
            heartbeat_handle,
        })
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<bool, CsError> {
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
                Ok(false)
            }
            EventType::Connect => {
                buf.truncate(len);
                let (old, uid) = PackageDecoder::connect(&self.server_crypt, buf)?;
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                if old.max(now) - old.min(now) > 60 {
                    return Err(CsError::InvalidTimestamp(old));
                }
                if let Ok(session_crypt) = self
                    .connections
                    .get(&uid)
                    .ok_or(CsError::ConnectionBroken)
                    .and_then(|c| {
                        let guard = c.lock().map_err(|_| CsError::ConnectionBroken)?;
                        let inner = guard.as_ref().ok_or(CsError::ConnectionBroken)?;
                        Ok(inner.session_crypt.clone())
                    })
                {
                    let data = PackageEncoder::ack_connect(&*session_crypt, &uid)?;
                    self.socket.send_to(&data, addr).await?;
                    return Ok(false);
                }
                let session_crypt = C::new(buf).map_err(|_| CsError::CreateCrypto)?;
                let data = PackageEncoder::ack_connect(&session_crypt, &uid)?;
                self.socket.send_to(&data, addr).await?;
                let conn = Arc::new(Mutex::new(Some(Connection {
                    addr,
                    count: 1,
                    session_crypt: Arc::new(session_crypt),
                    uid,
                    life: MAX_LIFE,
                    max_count: 0,
                    replay_bitmap: 0,
                })));
                self.connections.insert(uid, conn);
                Ok(false)
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
                let session_crypt = conn
                    .lock()
                    .map_err(|_| CsError::ConnectionBroken)?
                    .as_ref()
                    .ok_or(CsError::ConnectionBroken)?
                    .session_crypt
                    .clone();
                let (count, uid) = PackageDecoder::encrypted(&*session_crypt, buf)?;
                conn.lock()
                    .map_err(|_| CsError::ConnectionBroken)?
                    .as_mut()
                    .ok_or(CsError::ConnectionBroken)?
                    .check_and_update(count, uid, Some(addr))?;
                match event_type {
                    EventType::Encrypted => Ok(true),
                    EventType::Heartbeat => {
                        tracing::info!("Received heartbeat Request");
                        let (session_crypt, count, uid, addr) = Connection::try_pre_encrypt(&conn)?;
                        let data = PackageEncoder::ack_heartbeat(&*session_crypt, count, &uid)?;
                        self.socket.send_to(&data, addr).await?;
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
}

pub struct Channel<C: Crypto> {
    conn: ConnectionMut<C>,
    socket: Arc<UdpSocket>,
}

impl<C: Crypto> Channel<C> {
    pub async fn send(&self, buf: &mut Vec<u8>) -> Result<(), CsError> {
        let (session_crypt, count, uid, addr) = Connection::try_pre_encrypt(&self.conn)?;
        PackageEncoder::encrypted(buf, &*session_crypt, count, &uid)?;
        self.socket.send_to(buf, addr).await?;
        Ok(())
    }
}
