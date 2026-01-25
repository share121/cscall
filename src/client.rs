use crate::{
    CsError, EventType, UID, UID_LEN,
    coder::{Decoder, Encoder},
    connection::Connection,
    crypto::Crypto,
    transport::Transport,
};
use rand::{RngCore, rngs::OsRng};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{task::JoinHandle, time::Instant};

#[derive(Clone)]
pub struct ClientConfig<T: Transport> {
    pub transport: Arc<T>,
    pub target: SocketAddr,
    pub ttl: Duration,
    pub pwd: Arc<[u8]>,
    pub handshake_timeout: Duration,
}

pub struct Client<T: Transport, C: Crypto> {
    config: ClientConfig<T>,
    conn: Arc<Connection<C>>,
    heartbeat_handle: Mutex<Option<JoinHandle<()>>>,
    last_send: Arc<Mutex<Instant>>,
}

impl<T: Transport, C: Crypto> Drop for Client<T, C> {
    fn drop(&mut self) {
        self.close();
    }
}

#[macro_export]
macro_rules! recv_until {
    (
        transport: $transport:expr,
        target: $target:expr,
        buf: $buf:ident,
        timeout: $timeout:expr,
        max_retries: $max_retries:expr,
        prepare: |$send_buf:ident| $prepare_block:block,
        validate: |$recv_data:ident| $validate_block:block
    ) => {{
        let mut attempts = 0;
        let delay = Duration::from_millis(100);
        loop {
            if let Some(max) = $max_retries {
                if attempts > max {
                    break Err(CsError::RecvTimeout);
                }
                attempts += 1;
            }
            $buf.clear();
            let data = {
                let $send_buf = &mut $buf;
                $prepare_block
            };
            if let Err(e) = $transport.send_to(data.as_ref(), $target).await {
                tracing::warn!("Failed to send packet: {:?}", e);
            } else {
                $buf.clear();
                match tokio::time::timeout($timeout, $transport.recv_buf_from(&mut $buf)).await {
                    Ok(Ok(addr)) if addr == $target => {
                        let $recv_data = &mut $buf;
                        match $validate_block {
                            Ok(res) => break Ok(res),
                            Err(e) => tracing::warn!("recv validation error: {:?}", e),
                        }
                    }
                    Ok(Ok(addr)) => {
                        tracing::warn!("Received packet from unexpected address: {}", addr)
                    }
                    Ok(Err(e)) => tracing::warn!("Failed to receive packet: {:?}", e),
                    Err(_) => tracing::warn!("Receive packet timed out"),
                }
            }
            tokio::time::sleep(delay).await;
        }
    }};
}

impl<T: Transport, C: Crypto> Client<T, C> {
    pub async fn connect(
        conn: &Arc<Connection<C>>,
        config: &ClientConfig<T>,
        last_send: Arc<Mutex<Instant>>,
    ) -> Result<JoinHandle<()>, CsError> {
        let mut buf = Vec::with_capacity(T::BUFFER_SIZE);
        loop {
            // 发送 Hello 直到服务器回应 AckHello 并解析 server_salt
            let server_salt = recv_until!(
                transport: &config.transport,
                target: config.target,
                buf: buf,
                timeout: config.handshake_timeout,
                max_retries: None,
                prepare: |_buf| { Encoder::hello() },
                validate: |buf| { Decoder::ack_hello::<C>(buf) }
            )?;
            // 生成 client_pub 并用 server_key 加密后发送 Connect 请求
            let (client_secret, client_public) = C::gen_keypair()?;
            let server_crypto = tokio::task::spawn_blocking({
                let pwd = config.pwd.clone();
                move || {
                    C::derive_key(&pwd, server_salt.as_ref()).and_then(|key| C::new(key.as_ref()))
                }
            })
            .await
            .or(Err(CsError::Crypto))??;
            // 发送 Connect 请求，并使用 server_crypto 加密，服务器返回的数据用 server_crypto 验证 AckConnect
            let mut uid = [0u8; UID_LEN];
            OsRng.fill_bytes(&mut uid);
            let server_public = recv_until!(
                transport: &config.transport,
                target: config.target,
                buf: buf,
                timeout: config.handshake_timeout,
                max_retries: Some(5),
                prepare: |buf| {
                    Encoder::connect(&server_crypto, &client_public, config.ttl, &uid, buf)?;
                    buf
                },
                validate: |buf| { Decoder::ack_connect(&server_crypto, &uid, buf) }
            );
            let server_public = match server_public {
                Err(CsError::RecvTimeout) => continue,
                Err(e) => return Err(e),
                Ok(public) => public,
            };
            let shared_secret = C::diffie_hellman(client_secret, server_public.as_ref())?;
            let session_crypto = C::new(C::hash(&[shared_secret.as_ref()])?.as_ref())?;
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
                let transport = config.transport.clone();
                let gap = Duration::from_secs(1).min(config.ttl / 2);
                async move {
                    let mut buf = Vec::with_capacity(T::BUFFER_SIZE);
                    loop {
                        tokio::time::sleep(gap).await;
                        match heartbeat(&conn, &*transport, &last_send, &mut buf).await {
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

    pub async fn new(config: ClientConfig<T>) -> Result<Self, CsError> {
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
        let old = self.heartbeat_handle.lock().unwrap().replace(handle);
        if let Some(old_handle) = old {
            old_handle.abort();
        }
        Ok(())
    }

    pub async fn send(&self, buf: &mut Vec<u8>) -> Result<(), CsError> {
        let (session_crypto, count, uid, addr) = self.conn.pre_encrypt()?;
        Encoder::encrypted(&*session_crypto, count, &uid, buf)?;
        self.config.transport.send_to(buf, addr).await?;
        *self.last_send.lock().unwrap() = Instant::now();
        Ok(())
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<Option<(UID, u64)>, CsError> {
        buf.clear();
        buf.reserve(T::BUFFER_SIZE);
        let addr = self.config.transport.recv_buf_from(buf).await?;
        if addr != self.config.target {
            return Err(CsError::InvalidFormat);
        }
        if buf.is_empty() {
            return Err(CsError::InvalidFormat);
        }
        match *buf.last().unwrap() {
            event_type
            @ (EventType::Encrypted | EventType::Heartbeat | EventType::AckHeartbeat) => {
                let session_crypto = self.conn.session_crypto()?;
                let (count, uid) = Decoder::encrypted(&*session_crypto, buf)?;
                self.conn.check_and_update(count, uid, None)?;
                match event_type {
                    EventType::Encrypted => Ok(Some((uid, count))),
                    EventType::Heartbeat => {
                        tracing::debug!("Received heartbeat Request");
                        let (session_crypto, count, uid, addr) = self.conn.pre_encrypt()?;
                        Encoder::ack_heartbeat(&*session_crypto, count, &uid, buf)?;
                        self.config.transport.send_to(buf, addr).await?;
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
    ) -> Result<Option<(UID, u64)>, CsError> {
        tokio::time::timeout(timeout, self.recv(buf))
            .await
            .or(Err(CsError::RecvTimeout))?
    }
}

async fn heartbeat<T: Transport, C: Crypto>(
    conn: &Connection<C>,
    transport: &T,
    last_send: &Mutex<Instant>,
    buf: &mut Vec<u8>,
) -> Result<(), CsError> {
    let (session_crypto, count, uid, addr) = {
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
    transport.send_to(buf, addr).await?;
    *last_send.lock().unwrap() = Instant::now();
    tracing::debug!("Heartbeat");
    Ok(())
}
