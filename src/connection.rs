use crate::{MAX_LIFE, REORDER_WINDOW, UID_LEN, common::CsError, crypto::Crypto};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
};

pub struct ConnectionInner<C: Crypto> {
    pub addr: SocketAddr,
    pub count: u64,
    pub session_crypto: Arc<C>,
    pub uid: [u8; UID_LEN],
    pub life: u32,
    pub max_count: u64,
    pub replay_bitmap: u128,
}

impl<C: Crypto> ConnectionInner<C> {
    /// Return: (session_crypto, count, uid)
    pub fn pre_encrypt(&mut self) -> (Arc<C>, u64, [u8; UID_LEN], SocketAddr) {
        let count = self.count;
        self.count += 1;
        (self.session_crypto.clone(), count, self.uid, self.addr)
    }

    pub fn check_and_update(
        &mut self,
        count: u64,
        uid: [u8; UID_LEN],
        addr: Option<SocketAddr>,
    ) -> Result<(), CsError> {
        if uid != self.uid {
            tracing::warn!("Invalid uid");
            return Err(CsError::InvalidUid(uid));
        }
        if count > self.max_count {
            self.life = MAX_LIFE;
            if let Some(addr) = addr {
                self.addr = addr;
            }
            let delta = count - self.max_count;
            if delta > 1 {
                tracing::warn!("Skip {} packets", delta - 1);
            }
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
                return Err(CsError::InvalidCounter(count));
            } else {
                let mask = 1 << delta;
                if (self.replay_bitmap & mask) != 0 {
                    tracing::warn!("Invalid counter");
                    return Err(CsError::InvalidCounter(count));
                } else {
                    tracing::warn!("Reordered counter");
                    self.replay_bitmap |= mask;
                }
            }
        }
        Ok(())
    }
}

pub struct Connection<C: Crypto> {
    inner: Arc<Mutex<Option<ConnectionInner<C>>>>,
}

impl<C: Crypto> Clone for Connection<C> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<C: Crypto> Connection<C> {
    pub fn new(uid: [u8; UID_LEN], addr: SocketAddr, session_crypto: Arc<C>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Some(ConnectionInner {
                uid,
                addr,
                session_crypto,
                count: 1,
                life: MAX_LIFE,
                max_count: 0,
                replay_bitmap: 0,
            }))),
        }
    }

    pub fn inner(&self) -> Result<MutexGuard<'_, Option<ConnectionInner<C>>>, CsError> {
        self.inner.lock().map_err(|_| CsError::ConnectionBroken)
    }

    pub fn replace(
        &self,
        uid: [u8; UID_LEN],
        addr: SocketAddr,
        session_crypto: Arc<C>,
    ) -> Result<(), CsError> {
        self.inner()?.replace(ConnectionInner {
            uid,
            addr,
            session_crypto,
            count: 1,
            life: MAX_LIFE,
            max_count: 0,
            replay_bitmap: 0,
        });
        Ok(())
    }

    /// Return: (session_crypto, count, uid)
    pub fn pre_encrypt(&self) -> Result<(Arc<C>, u64, [u8; UID_LEN], SocketAddr), CsError> {
        self.inner()?
            .as_mut()
            .ok_or(CsError::ConnectionBroken)
            .map(|c| c.pre_encrypt())
    }

    pub fn check_and_update(
        &self,
        count: u64,
        uid: [u8; UID_LEN],
        addr: Option<SocketAddr>,
    ) -> Result<(), CsError> {
        self.inner()?
            .as_mut()
            .ok_or(CsError::ConnectionBroken)
            .and_then(|c| c.check_and_update(count, uid, addr))
    }

    pub fn sessiton_crypto(&self) -> Result<Arc<C>, CsError> {
        self.inner()?
            .as_ref()
            .ok_or(CsError::ConnectionBroken)
            .map(|c| c.session_crypto.clone())
    }
}

impl<C: Crypto> Default for Connection<C> {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(None)),
        }
    }
}
