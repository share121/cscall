use crate::{MAX_LIFE, REORDER_WINDOW, UID_LEN, common::CsError, crypt::Crypt};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::task::JoinHandle;

pub struct Connection<C: Crypt> {
    pub addr: SocketAddr,
    pub count: u64,
    pub session_crypt: Arc<C>,
    pub uid: [u8; UID_LEN],
    pub life: u32,
    pub max_count: u64,
    pub replay_bitmap: u128,
    pub heartbeat_handle: Option<JoinHandle<()>>,
}

impl<C: Crypt> Drop for Connection<C> {
    fn drop(&mut self) {
        if let Some(handle) = self.heartbeat_handle.take() {
            handle.abort();
        }
    }
}

impl<C: Crypt> Connection<C> {
    /// Return: (session_crypt, count, uid)
    pub fn pre_encrypt(&mut self) -> (Arc<C>, u64, [u8; UID_LEN]) {
        let count = self.count;
        self.count += 1;
        (self.session_crypt.clone(), count, self.uid)
    }

    /// Return: (session_crypt, count, uid)
    pub fn try_pre_encrypt(
        conn: &Mutex<Option<Self>>,
    ) -> Result<(Arc<C>, u64, [u8; UID_LEN]), CsError> {
        conn.lock()
            .map_err(|_| CsError::ConnectionBroken)?
            .as_mut()
            .ok_or(CsError::ConnectionBroken)
            .map(|c| c.pre_encrypt())
    }

    pub fn check_and_update(
        &mut self,
        count: u64,
        uid: [u8; UID_LEN],
        addr: Option<SocketAddr>,
    ) -> Result<(), CsError> {
        if uid != self.uid {
            tracing::warn!("Invalid uid");
            return Err(CsError::InvalidUid);
        }
        if count > self.max_count {
            self.life = MAX_LIFE;
            if let Some(addr) = addr {
                self.addr = addr;
            }
            let delta = count - self.max_count;
            if delta >= REORDER_WINDOW {
                self.replay_bitmap = 1;
            } else {
                self.replay_bitmap = (self.replay_bitmap << delta) | 1;
            }
            self.max_count = count;
        } else {
            let delta = self.max_count - count;
            if delta >= REORDER_WINDOW {
                tracing::warn!("Invalid counter");
                return Err(CsError::InvalidCounter);
            } else {
                let mask = 1 << delta;
                if (self.replay_bitmap & mask) != 0 {
                    tracing::warn!("Invalid counter");
                    return Err(CsError::InvalidCounter);
                } else {
                    self.replay_bitmap |= mask;
                }
            }
        }
        Ok(())
    }
}
