use crate::{
    EventType, MAX_LIFE, UID_LEN,
    common::{CsError, heartbeat},
    connection::Connection,
    crypt::Crypt,
    package::{PackageDecoder, PackageEncoder},
};
use dashmap::DashMap;
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

pub type Connections<C> = Arc<DashMap<[u8; UID_LEN], Arc<Mutex<Option<Connection<C>>>>>>;

pub struct Server<C: Crypt> {
    socket: Arc<UdpSocket>,
    server_crypt: C,
    server_salt: C::Salt,
    connections: Connections<C>,
}

impl<C: Crypt> Server<C> {
    pub fn new(pwd: &[u8], socket: Arc<UdpSocket>) -> Result<Self, CsError> {
        let server_salt = C::gen_salt();
        let server_key = C::derive_key(pwd, &server_salt).map_err(|_| CsError::DeriveKey)?;
        let server_crypt = C::new(server_key.as_ref()).map_err(|_| CsError::CreateCrypt)?;
        Ok(Self {
            socket,
            server_crypt,
            server_salt,
            connections: Arc::new(DashMap::new()),
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
                PackageDecoder::hello(&buf[..len]).map_err(|_| CsError::InvalidFormat)?;
                let data = PackageEncoder::ack_hello::<C>(&self.server_salt);
                self.socket.send(&data).await?;
                Ok(false)
            }
            EventType::Connect => {
                buf.truncate(len);
                let (old, uid) = PackageDecoder::connect(&self.server_crypt, buf)
                    .map_err(|_| CsError::InvalidFormat)?;
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
                    let data = PackageEncoder::ack_connect(&*session_crypt, &uid)
                        .map_err(|_| CsError::Encrypt)?;
                    self.socket.send(&data).await?;
                    return Ok(false);
                }
                let session_crypt = C::new(buf).map_err(|_| CsError::CreateCrypt)?;
                let conn = Arc::new(Mutex::new(Some(Connection {
                    addr,
                    count: 1,
                    session_crypt: Arc::new(session_crypt),
                    uid,
                    life: MAX_LIFE,
                    max_count: 0,
                    replay_bitmap: 0,
                    heartbeat_handle: None,
                })));
                let heartbeat_handle = tokio::spawn({
                    let conn = conn.clone();
                    let socket = self.socket.clone();
                    let connections = self.connections.clone();
                    async move {
                        heartbeat(&conn, &socket).await;
                        connections.remove(&uid);
                    }
                });
                conn.lock()
                    .map_err(|_| CsError::ConnectionBroken)?
                    .as_mut()
                    .ok_or(CsError::ConnectionBroken)?
                    .heartbeat_handle = Some(heartbeat_handle);
                self.connections.insert(uid, conn);
                Ok(false)
            }
            event_type
            @ (EventType::Encrypted | EventType::Heartbeat | EventType::AckHeartbeat) => {
                buf.truncate(len);
                let uid = PackageDecoder::peek_uid(buf, 1).map_err(|_| CsError::InvalidFormat)?;
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
                let (count, uid) = PackageDecoder::encrypted(&*session_crypt, buf)
                    .map_err(|_| CsError::Decrypt)?;
                conn.lock()
                    .map_err(|_| CsError::ConnectionBroken)?
                    .as_mut()
                    .ok_or(CsError::ConnectionBroken)?
                    .check_and_update(count, uid, None)?;
                match event_type {
                    EventType::Encrypted => Ok(true),
                    EventType::Heartbeat => {
                        tracing::info!("Received heartbeat Request");
                        let (session_crypt, count, uid) = Connection::try_pre_encrypt(&conn)?;
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
