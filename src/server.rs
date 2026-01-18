use crate::{
    COUNT_LEN, CsError, EventType, UID_LEN,
    coder::{Decoder, Encoder},
    connection::Connection,
    crypto::{Crypto, hash},
};
use dashmap::DashMap;
use std::{
    sync::{Arc, Mutex, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, time::Instant};
use x25519_dalek::{EphemeralSecret, PublicKey};

struct Secure<C: Crypto> {
    inner: Arc<Mutex<(Arc<C>, C::Salt)>>,
    pwd: Arc<[u8]>,
}
impl<C: Crypto> Clone for Secure<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            pwd: self.pwd.clone(),
        }
    }
}
impl<C: Crypto> Secure<C> {
    async fn gen_crypto(pwd: Arc<[u8]>) -> Result<(Arc<C>, C::Salt), CsError> {
        let salt = C::gen_salt()?;
        let crypto = tokio::task::spawn_blocking({
            let salt = salt.clone();
            move || C::derive_key(&pwd, &salt).and_then(|key| C::new(key.as_ref()))
        })
        .await
        .or(Err(CsError::Crypto))??;
        Ok((Arc::new(crypto), salt))
    }
    async fn with_pwd(pwd: Arc<[u8]>) -> Result<Self, CsError> {
        let (crypto, salt) = Self::gen_crypto(pwd.clone()).await?;
        Ok(Self {
            pwd,
            inner: Arc::new(Mutex::new((crypto, salt))),
        })
    }
    fn crypto(&self) -> Arc<C> {
        self.inner.lock().unwrap().0.clone()
    }
    fn salt(&self) -> C::Salt {
        self.inner.lock().unwrap().1.clone()
    }
    async fn update(&self) -> Result<(), CsError> {
        let (crypto, salt) = Self::gen_crypto(self.pwd.clone()).await?;
        *self.inner.lock().unwrap() = (crypto, salt);
        Ok(())
    }
}

pub struct Server<C: Crypto> {
    socket: Arc<UdpSocket>,
    secure: Secure<C>,
    connections: Arc<DashMap<[u8; UID_LEN], Arc<Connection<C>>>>,
    heartbeat_handle: tokio::task::JoinHandle<()>,
}

impl<C: Crypto> Drop for Server<C> {
    fn drop(&mut self) {
        self.heartbeat_handle.abort();
    }
}

impl<C: Crypto> Server<C> {
    pub async fn new(pwd: Arc<[u8]>, socket: Arc<UdpSocket>) -> Result<Self, CsError> {
        let secure = Secure::with_pwd(pwd.clone()).await?;
        let connections: Arc<DashMap<[u8; UID_LEN], Arc<Connection<C>>>> = Arc::new(DashMap::new());
        let heartbeat_handle = tokio::spawn({
            let connections = connections.clone();
            let secure = secure.clone();
            async move {
                let mut last_rotation = Instant::now();
                loop {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    let len = connections.len();
                    connections.retain(|_, c| !c.is_timeout());
                    let new_len = connections.len();
                    tracing::debug!("Clean {}, Active {}", len - new_len, new_len);
                    if len > 0 && new_len == 0 || last_rotation.elapsed() > Duration::from_secs(600)
                    {
                        match secure.update().await {
                            Err(e) => tracing::error!("Failed to generate new crypto: {:?}", e),
                            Ok(_) => {
                                tracing::debug!("Server master key/salt rotated");
                                last_rotation = Instant::now();
                            }
                        }
                    }
                }
            }
        });
        Ok(Self {
            socket,
            secure,
            connections,
            heartbeat_handle,
        })
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<Option<([u8; UID_LEN], u64)>, CsError> {
        buf.clear();
        buf.reserve(1500);
        let (len, addr) = self.socket.recv_buf_from(buf).await?;
        if len == 0 {
            return Err(CsError::InvalidFormat);
        }
        match buf[len - 1] {
            EventType::Hello => {
                Decoder::hello(buf)?;
                Encoder::ack_hello::<C>(&self.secure.salt(), buf);
                self.socket.send_to(buf, addr).await?;
                Ok(None)
            }
            EventType::Connect => {
                let (client_public, ttl, old, uid) = Decoder::connect(&*self.secure.crypto(), buf)?;
                let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
                if old.abs_diff(now) > (ttl.as_secs() * 2 / 3).min(60) {
                    return Err(CsError::InvalidTimestamp(old));
                }
                if let Ok(server_public) = self
                    .connections
                    .get(&uid)
                    .ok_or(CsError::ConnectionBroken)
                    .and_then(|c| c.server_public())
                {
                    Encoder::ack_connect(
                        &*self.secure.crypto(),
                        server_public.as_bytes(),
                        &uid,
                        buf,
                    )?;
                    self.socket.send_to(buf, addr).await?;
                    return Ok(None);
                }
                let server_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
                let server_public = PublicKey::from(&server_secret);
                let shared_secret = server_secret.diffie_hellman(&client_public);
                let session_crypto = C::new(&hash(shared_secret.as_bytes()))?;
                Encoder::ack_connect(&*self.secure.crypto(), server_public.as_bytes(), &uid, buf)?;
                self.socket.send_to(buf, addr).await?;
                let conn = Connection::new(uid, addr, Arc::new(session_crypto), server_public, ttl);
                let conn = Arc::new(conn);
                self.connections.insert(uid, conn);
                Ok(None)
            }
            event_type
            @ (EventType::Encrypted | EventType::Heartbeat | EventType::AckHeartbeat) => {
                let uid = Decoder::peek_uid(buf)?;
                let conn = self
                    .connections
                    .get(&uid)
                    .ok_or(CsError::ConnectionBroken)?
                    .clone();
                let session_crypto = conn.sessiton_crypto()?;
                let (count, uid) = Decoder::encrypted(&*session_crypto, buf)?;
                conn.check_and_update(count, uid, Some(addr))?;
                match event_type {
                    EventType::Encrypted => Ok(Some((uid, count))),
                    EventType::Heartbeat => {
                        tracing::debug!("Received heartbeat Request");
                        let (session_crypto, count, uid, addr) = conn.pre_encrypt()?;
                        Encoder::ack_heartbeat(&*session_crypto, count, &uid, buf)?;
                        self.socket.send_to(buf, addr).await?;
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
                tracing::warn!("Received invalid package {:?}", buf);
                Err(CsError::InvalidFormat)
            }
        }
    }

    pub async fn recv_timeout(
        &self,
        buf: &mut Vec<u8>,
        timeout: Duration,
    ) -> Result<Option<([u8; UID_LEN], u64)>, CsError> {
        tokio::time::timeout(timeout, self.recv(buf)).await?
    }

    pub async fn get(&self, uid: &[u8; UID_LEN]) -> Result<Channel<C>, CsError> {
        Ok(Channel {
            conn: Arc::downgrade(&*self.connections.get(uid).ok_or(CsError::ConnectionBroken)?),
            socket: Arc::downgrade(&self.socket),
        })
    }

    pub async fn send_all(&self, data: &[u8]) -> Result<(), CsError> {
        let conns: Vec<Arc<Connection<C>>> = self.connections.iter().map(|c| c.clone()).collect();
        let mut buf = Vec::with_capacity(data.len() + COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        for conn in conns {
            let (session_crypto, count, uid, addr) = conn.pre_encrypt()?;
            buf.clear();
            buf.extend_from_slice(data);
            Encoder::encrypted(&*session_crypto, count, &uid, &mut buf)?;
            self.socket.send_to(&buf, addr).await?;
        }
        Ok(())
    }
}

pub struct Channel<C: Crypto> {
    conn: Weak<Connection<C>>,
    socket: Weak<UdpSocket>,
}

impl<C: Crypto> Channel<C> {
    pub async fn send(&self, buf: &mut Vec<u8>) -> Result<(), CsError> {
        let (session_crypto, count, uid, addr) = self
            .conn
            .upgrade()
            .ok_or(CsError::ConnectionBroken)?
            .pre_encrypt()?;
        Encoder::encrypted(&*session_crypto, count, &uid, buf)?;
        self.socket
            .upgrade()
            .ok_or(CsError::ConnectionBroken)?
            .send_to(buf, addr)
            .await?;
        Ok(())
    }
}
