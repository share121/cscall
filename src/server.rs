use crate::{UID_LEN, common::CsError, connection::Connection, crypt::Crypt};
use dashmap::DashMap;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::UdpSocket;

pub struct Server<C: Crypt> {
    socket: Arc<UdpSocket>,
    master_crypt: C,
    master_salt: C::Salt,
    connections: DashMap<[u8; UID_LEN], Arc<Mutex<Option<Connection<C>>>>>,
}

impl<C: Crypt> Server<C> {
    pub fn new(pwd: &[u8], socket: Arc<UdpSocket>) -> Result<Self, CsError> {
        let master_salt = C::gen_salt();
        let master_key = C::derive_key(pwd, &master_salt).map_err(|_| CsError::DeriveKey)?;
        let master_crypt = C::new(&master_key).map_err(|_| CsError::CreateCrypt)?;
        Ok(Self {
            socket,
            master_crypt,
            master_salt,
            connections: DashMap::new(),
        })
    }

    pub async fn recv(&self, buf: &mut Vec<u8>) -> Result<bool, CsError> {
        if buf.capacity() < 1500 {
            buf.reserve(1500 - buf.len());
        }
        unsafe { buf.set_len(1500) };
        let (len, from) = self.socket.recv_from(buf).await?;
        if len == 0 {
            return Err(CsError::InvalidFormat);
        }
        Ok(false)
        // match buf[len - 1] {
        //     EventType::Hello => {
        //         buf[..SALT_LEN].copy_from_slice(&self.master_salt);
        //         buf[SALT_LEN] = EventType::AckHello;
        //         self.socket.send_to(&buf[..SALT_LEN + 1], from).await?;
        //         Ok(false)
        //     }
        //     EventType::Connect => {
        //         buf.truncate(len - 1);
        //         self.handle_connect(from, buf).await?;
        //         Ok(false)
        //     }
        //     EventType::Heartbeat => {
        //         buf.truncate(len - 1);
        //         // self.handle_heartbeat(from, buf).await?;
        //         Ok(false)
        //     }
        //     EventType::AckHeartbeat => Ok(false),
        //     EventType::Encrypted => {
        //         buf.truncate(len - 1);
        //         Ok(true)
        //     }
        //     event => {
        //         tracing::warn!("Unknown event type: {}, data: {:?}", event, &buf[..len]);
        //         Err(CsError::MismatchData)
        //     }
        // }
    }

    async fn handle_connect(&self, from: SocketAddr, buf: &mut Vec<u8>) -> Result<(), CsError> {
        // // 使用 master_key 解码
        // self.master_crypt
        //     .decrypt(&[], buf)
        //     .map_err(|_| CsError::Decrypt)?;
        // if buf.len() != KEY_LEN + UID_LEN {
        //     return Err(CsError::MismatchData);
        // }
        // // 提取 uid
        // let uid: [u8; UID_LEN] = buf[buf.len() - UID_LEN..]
        //     .try_into()
        //     .map_err(|_| CsError::MismatchData)?;
        // if !self.connections.contains_key(&uid) {
        //     // 提取 session_key
        //     let session_crypt =
        //         Arc::new(C::new(&buf[..KEY_LEN]).map_err(|_| CsError::CreateCrypt)?);
        //     let conn = Connection {
        //         addr: from,
        //         count: 1,
        //         session_crypt,
        //         uid,
        //         life: MAX_LIFE,
        //         max_count: 0,
        //         replay_bitmap: 0,
        //         heartbeat_handle: None,
        //     };
        //     let conn = Arc::new(Mutex::new(Some(conn)));
        //     let heartbeat_handle = tokio::spawn({
        //         let conn = conn.clone();
        //         let socket = self.socket.clone();
        //         async move {
        //             let mut buf = Vec::with_capacity(COUNT_LEN + UID_LEN + 1);
        //             loop {
        //                 tokio::time::sleep(Duration::from_millis(HEARTBEAT_MS)).await;

        //                 {
        //                     let mut guard = conn.lock().unwrap();
        //                     let guard_ref = match guard.as_mut() {
        //                         Some(g) => g,
        //                         None => {
        //                             tracing::warn!("Connection broken");
        //                             return;
        //                         }
        //                     };
        //                     if guard_ref.life == 0 {
        //                         *guard = None;
        //                         tracing::warn!("Connection life expired");
        //                         return;
        //                     }
        //                     guard_ref.life -= 1;
        //                 }

        //                 // 构造 heartbeat 数据包
        //                 // (count) + uid + EventType::Heartbeat
        //                 buf.clear();
        //                 if let Err(e) = Connection::encrypt(&conn, &mut buf) {
        //                     tracing::warn!("Failed to encrypt heartbeat packet: {:?}", e);
        //                     continue;
        //                 }
        //                 *buf.last_mut().unwrap() = EventType::Heartbeat;
        //                 if let Err(e) = socket.send(&buf).await {
        //                     tracing::warn!("Failed to send heartbeat packet: {:?}", e);
        //                 }
        //             }
        //         }
        //     });
        //     conn.lock()
        //         .unwrap()
        //         .as_mut()
        //         .ok_or(CsError::ConnectionBroken)?
        //         .heartbeat_handle
        //         .replace(heartbeat_handle);
        //     self.connections.insert(uid, conn);
        // }
        // buf.truncate(UID_LEN);
        // buf.copy_from_slice(&uid);
        // let crypt = self
        //     .connections
        //     .get(&uid)
        //     .ok_or(CsError::ConnectionBroken)?
        //     .lock()
        //     .unwrap()
        //     .as_ref()
        //     .ok_or(CsError::ConnectionBroken)?
        //     .session_crypt
        //     .clone();
        // crypt.encrypt(&[], buf).map_err(|_| CsError::Encrypt)?;
        // self.socket.send(&buf).await?;
        Ok(())
    }

    fn handle_encrypted(&self, buf: &mut Vec<u8>) -> Result<(), CsError> {
        // 处理 uid
        // let uid: [u8; UID_LEN] = buf[buf.len() - UID_LEN..]
        //     .try_into()
        //     .map_err(|_| CsError::MismatchData)?;
        // let guard = self.conn.lock().unwrap();
        // let guard_ref = guard.as_ref().ok_or(CsError::ConnectionBroken)?;
        // if uid != guard_ref.uid {
        //     return Err(CsError::MismatchData);
        // }
        // buf.truncate(buf.len() - UID_LEN);
        // let crypt = guard_ref.crypt.clone();
        // drop(guard);
        // crypt.decrypt(&uid, buf).map_err(|_| CsError::Decrypt)?;
        // // 处理 count
        // if buf.len() <= COUNT_LEN {
        //     return Err(CsError::MismatchData);
        // }
        // let count = u64::from_le_bytes(
        //     buf[buf.len() - COUNT_LEN..]
        //         .try_into()
        //         .map_err(|_| CsError::MismatchData)?,
        // );
        // let mut guard = self.conn.lock().unwrap();
        // let guard = guard.as_mut().ok_or(CsError::ConnectionBroken)?;
        // if count > guard.max_count {
        //     guard.life = MAX_LIFE;
        //     let delta = count - guard.max_count;
        //     if delta >= REORDER_WINDOW {
        //         guard.replay_bitmap = 1;
        //     } else {
        //         guard.replay_bitmap = (guard.replay_bitmap << delta) | 1;
        //     }
        //     guard.max_count = count;
        // } else {
        //     let delta = guard.max_count - count;
        //     if delta >= REORDER_WINDOW {
        //         tracing::warn!("Invalid counter");
        //         return Err(CsError::InvalidCounter);
        //     } else {
        //         let mask = 1 << delta;
        //         if (guard.replay_bitmap & mask) != 0 {
        //             tracing::warn!("Invalid counter");
        //             return Err(CsError::InvalidCounter);
        //         } else {
        //             guard.replay_bitmap |= mask;
        //         }
        //     }
        // }
        // buf.truncate(buf.len() - COUNT_LEN);
        Ok(())
    }
}
