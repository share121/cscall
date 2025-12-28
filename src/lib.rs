use crate::{client::ClientError, crypt::Crypt};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::task::JoinHandle;

pub mod client;
pub mod crypt;
pub mod server;

pub const UID_LEN: usize = 16;
pub const COUNT_LEN: usize = size_of::<u64>();
pub const REORDER_WINDOW: u64 = 128;

pub enum EventType {
    Encrypted = 0,
    Hello = 1,
    AckHello = 2,
    Connect = 3,
    AckConnect = 4,
    Heartbeat = 5,
    AckHeartbeat = 6,
}

pub struct Connection<const SALT_LEN: usize, const KEY_LEN: usize, C: Crypt<SALT_LEN, KEY_LEN>> {
    addr: SocketAddr,
    count: u64,
    crypt: Arc<C>,
    uid: [u8; UID_LEN],
    life: u32,
    max_count: u64,
    replay_bitmap: u128,
    heartbeat_handle: Option<JoinHandle<()>>,
}

impl<const SALT_LEN: usize, const KEY_LEN: usize, C: Crypt<SALT_LEN, KEY_LEN>> Drop
    for Connection<SALT_LEN, KEY_LEN, C>
{
    fn drop(&mut self) {
        if let Some(handle) = self.heartbeat_handle.take() {
            handle.abort();
        }
    }
}

impl<const SALT_LEN: usize, const KEY_LEN: usize, C: Crypt<SALT_LEN, KEY_LEN>>
    Connection<SALT_LEN, KEY_LEN, C>
{
    pub fn encrypt(conn: &Mutex<Option<Self>>, buf: &mut Vec<u8>) -> Result<(), ClientError> {
        let mut guard = conn.lock().unwrap();
        let guard_ref = guard.as_mut().ok_or(ClientError::ConnectionBroken)?;
        let count = guard_ref.count;
        guard_ref.count += 1;
        buf.extend_from_slice(&count.to_le_bytes());
        let crypt = guard_ref.crypt.clone();
        let uid = guard_ref.uid;
        drop(guard);
        crypt.encrypt(&uid, buf).map_err(|_| ClientError::Encrypt)?;
        buf.extend_from_slice(&uid);
        buf.push(EventType::Encrypted as u8);
        Ok(())
    }
}
