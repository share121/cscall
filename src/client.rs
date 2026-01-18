use crate::{
    CsError, EventType, UID_LEN,
    coder::{Decoder, Encoder},
    connection::Connection,
    crypto::{Crypto, hash},
};
use rand::{RngCore, rngs::OsRng};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    net::UdpSocket,
    task::JoinHandle,
    time::{Instant, timeout},
};

#[derive(Clone)]
pub struct ClientConfig {
    pub socket: Arc<UdpSocket>,
    pub target: SocketAddr,
    pub ttl: Duration,
    pub pwd: Arc<[u8]>,
}

pub struct Client<C: Crypto> {
    config: ClientConfig,
    conn: Arc<Connection<C>>,
    heartbeat_handle: Mutex<Option<JoinHandle<()>>>,
    last_send: Arc<Mutex<Instant>>,
}

impl<C: Crypto> Drop for Client<C> {
    fn drop(&mut self) {
        self.close();
    }
}

impl<C: Crypto> Client<C> {
    pub async fn connect(
        conn: &Arc<Connection<C>>,
        config: &ClientConfig,
        last_send: Arc<Mutex<Instant>>,
    ) -> Result<JoinHandle<()>, CsError> {
        let mut buf = Vec::with_capacity(1500);
        'outer: loop {
            // 发送 Hello 直到服务器回应 AckHello 并解析 server_salt
            let server_salt = loop {
                match config.socket.send(&Encoder::hello()).await {
                    Err(e) => tracing::warn!("Failed to send Hello: {e:?}"),
                    Ok(_) => {
                        buf.clear();
                        match timeout(Duration::from_secs(10), config.socket.recv_buf(&mut buf))
                            .await
                        {
                            Err(e) => tracing::warn!("Failed to receive AckHello Timeout: {e:?}"),
                            Ok(Err(e)) => tracing::warn!("Failed to receive AckHello: {e:?}"),
                            Ok(Ok(_)) => match Decoder::ack_hello::<C>(&buf) {
                                Ok(s) => break s,
                                Err(e) => tracing::warn!(
                                    "Expected AckHello but received: {:?} Error: {:?}",
                                    buf,
                                    e
                                ),
                            },
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            // 生成 client_pub 并用 server_key 加密后发送 Connect 请求
            let client_secret = x25519_dalek::EphemeralSecret::random_from_rng(rand::rngs::OsRng);
            let client_public = x25519_dalek::PublicKey::from(&client_secret);
            let server_crypto = tokio::task::spawn_blocking({
                let pwd = config.pwd.clone();
                move || C::derive_key(&pwd, &server_salt).and_then(|key| C::new(key.as_ref()))
            })
            .await
            .or(Err(CsError::Crypto))??;
            // 发送 Connect 请求，并使用 server_crypto 加密，服务器返回的数据用 server_crypto 验证 AckConnect
            let mut uid = [0u8; UID_LEN];
            OsRng.fill_bytes(&mut uid);
            let mut connect_attempts = 0;
            let server_public = loop {
                Encoder::connect(
                    &server_crypto,
                    client_public.as_bytes(),
                    config.ttl,
                    &uid,
                    &mut buf,
                )?;
                if connect_attempts > 5 {
                    tracing::warn!("Too many failed connection attempts");
                    continue 'outer;
                }
                connect_attempts += 1;
                match config.socket.send(&buf).await {
                    Err(e) => tracing::warn!("Failed to send Connect: {e:?}"),
                    Ok(_) => {
                        buf.clear();
                        match timeout(Duration::from_secs(10), config.socket.recv_buf(&mut buf))
                            .await
                        {
                            Err(e) => tracing::warn!("Failed to receive AckConnect Timeout: {e:?}"),
                            Ok(Err(e)) => tracing::warn!("Failed to receive AckConnect: {e:?}"),
                            Ok(Ok(_)) => {
                                match Decoder::ack_connect(&server_crypto, &uid, &mut buf) {
                                    Ok(server_public) => break server_public,
                                    Err(e) => tracing::warn!(
                                        "Expected AckConnect but received: {:?} Error: {:?}",
                                        buf,
                                        e
                                    ),
                                };
                            }
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            };
            let shared_secret = client_secret.diffie_hellman(&server_public);
            let session_crypto = C::new(&hash(shared_secret.as_bytes()))?;
            conn.replace(
                uid,
                config.target,
                Arc::new(session_crypto),
                server_public,
                config.ttl,
            )?;
            *last_send.lock().unwrap() = Instant::now();
            let heartbeat_handle = tokio::spawn({
                let conn = conn.clone();
                let socket = config.socket.clone();
                let gap = Duration::from_secs(1).min(config.ttl / 2);
                async move {
                    let mut buf = Vec::with_capacity(1500);
                    loop {
                        tokio::time::sleep(gap).await;
                        match heartbeat(&conn, &socket, &last_send, &mut buf).await {
                            Ok(()) => {}
                            Err(CsError::ConnectionBroken) => return,
                            Err(e) => tracing::warn!("Heartbeat error {e:?}"),
                        }
                    }
                }
            });
            break Ok(heartbeat_handle);
        }
    }

    pub async fn new(config: ClientConfig) -> Result<Self, CsError> {
        config.socket.connect(config.target).await?;
        let conn = Arc::new(Connection::default());
        let last_send = Arc::new(Mutex::new(Instant::now()));
        let handle = Self::connect(&conn, &config, last_send.clone()).await?;
        Ok(Self {
            config,
            conn,
            last_send,
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
        let handle = Self::connect(&self.conn, &self.config, self.last_send.clone()).await?;
        self.heartbeat_handle.lock().unwrap().replace(handle);
        Ok(())
    }

    pub async fn send(&self, buf: &mut Vec<u8>) -> Result<(), CsError> {
        let (session_crypto, count, uid, _) = self.conn.pre_encrypt()?;
        Encoder::encrypted(&*session_crypto, count, &uid, buf)?;
        self.config.socket.send(buf).await?;
        *self.last_send.lock().unwrap() = Instant::now();
        Ok(())
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<Option<([u8; UID_LEN], u64)>, CsError> {
        buf.clear();
        buf.reserve(1500);
        let len = self.config.socket.recv_buf(buf).await?;
        if len == 0 {
            return Err(CsError::InvalidFormat);
        }
        match buf[len - 1] {
            event_type
            @ (EventType::Encrypted | EventType::Heartbeat | EventType::AckHeartbeat) => {
                let session_crypto = self.conn.sessiton_crypto()?;
                let (count, uid) = Decoder::encrypted(&*session_crypto, buf)?;
                self.conn.check_and_update(count, uid, None)?;
                match event_type {
                    EventType::Encrypted => Ok(Some((uid, count))),
                    EventType::Heartbeat => {
                        tracing::debug!("Received heartbeat Request");
                        let (session_crypto, count, uid, _) = self.conn.pre_encrypt()?;
                        Encoder::ack_heartbeat(&*session_crypto, count, &uid, buf)?;
                        self.config.socket.send(buf).await?;
                        *self.last_send.lock().unwrap() = Instant::now();
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
}

async fn heartbeat<C: Crypto>(
    conn: &Connection<C>,
    socket: &UdpSocket,
    last_send: &Mutex<Instant>,
    buf: &mut Vec<u8>,
) -> Result<(), CsError> {
    let (session_crypto, count, uid, _) = {
        let mut guard = conn.inner()?;
        let guard_ref = guard.as_mut().ok_or(CsError::ConnectionBroken)?;
        if guard_ref.last_recv.elapsed() > guard_ref.ttl {
            *guard = None;
            tracing::warn!("Connection life expired");
            return Err(CsError::ConnectionBroken);
        }
        if guard_ref.last_recv.elapsed() < guard_ref.ttl / 2
            && last_send.lock().unwrap().elapsed() < guard_ref.ttl / 2
        {
            return Ok(());
        }
        guard_ref.pre_encrypt()
    };
    Encoder::heartbeat(&*session_crypto, count, &uid, buf)?;
    socket.send(buf).await?;
    *last_send.lock().unwrap() = Instant::now();
    tracing::debug!("Heartbeat");
    Ok(())
}
