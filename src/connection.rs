use crate::{CsError, REORDER_WINDOW, UID, crypto::Crypto};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};
use tokio::time::Instant;

pub struct ConnectionInner<C: Crypto> {
    pub uid: UID,
    pub addr: SocketAddr,
    pub count: u64,
    pub max_count: u64,
    pub replay_bitmap: u128,
    pub session_crypto: Arc<C>,
    pub last_recv: Instant,
    pub ttl: Duration,
    pub server_public: C::PublicKey,
}

impl<C: Crypto> ConnectionInner<C> {
    pub fn new(
        uid: UID,
        addr: SocketAddr,
        session_crypto: Arc<C>,
        server_public: C::PublicKey,
        ttl: Duration,
    ) -> Self {
        Self {
            uid,
            addr,
            session_crypto,
            server_public,
            ttl,
            last_recv: Instant::now(),
            count: 1,
            max_count: 0,
            replay_bitmap: 0,
        }
    }

    /// Return: (session_crypto, count, uid, addr)
    pub fn pre_encrypt(&mut self) -> (Arc<C>, u64, UID, SocketAddr) {
        let count = self.count;
        self.count += 1;
        (self.session_crypto.clone(), count, self.uid, self.addr)
    }

    pub fn check_and_update(
        &mut self,
        count: u64,
        uid: UID,
        addr: Option<SocketAddr>,
    ) -> Result<(), CsError> {
        if uid != self.uid {
            tracing::warn!("Invalid uid");
            return Err(CsError::InvalidUid(uid));
        }
        if count > self.max_count {
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
        self.last_recv = Instant::now();
        Ok(())
    }
}

pub struct Connection<C: Crypto> {
    inner: Mutex<Option<ConnectionInner<C>>>,
}

impl<C: Crypto> Connection<C> {
    pub fn new(
        uid: UID,
        addr: SocketAddr,
        session_crypto: Arc<C>,
        server_public: C::PublicKey,
        ttl: Duration,
    ) -> Self {
        let conn = ConnectionInner::new(uid, addr, session_crypto, server_public, ttl);
        Self {
            inner: Mutex::new(Some(conn)),
        }
    }

    pub fn inner(&self) -> Result<MutexGuard<'_, Option<ConnectionInner<C>>>, CsError> {
        self.inner.lock().map_err(|_| CsError::ConnectionBroken)
    }

    pub fn with<F, R>(&self, f: F) -> Result<R, CsError>
    where
        F: FnOnce(&mut ConnectionInner<C>) -> R,
    {
        let mut guard = self.inner()?;
        let inner_ref = guard.as_mut().ok_or(CsError::ConnectionBroken)?;
        Ok(f(inner_ref))
    }

    pub fn replace(
        &self,
        uid: UID,
        addr: SocketAddr,
        session_crypto: Arc<C>,
        server_public: C::PublicKey,
        ttl: Duration,
    ) -> Result<(), CsError> {
        let conn = ConnectionInner::new(uid, addr, session_crypto, server_public, ttl);
        self.inner()?.replace(conn);
        Ok(())
    }

    /// Return: (session_crypto, count, uid, addr)
    pub fn pre_encrypt(&self) -> Result<(Arc<C>, u64, UID, SocketAddr), CsError> {
        self.with(|c| c.pre_encrypt())
    }

    pub fn check_and_update(
        &self,
        count: u64,
        uid: UID,
        addr: Option<SocketAddr>,
    ) -> Result<(), CsError> {
        self.with(|c| c.check_and_update(count, uid, addr))?
    }

    pub fn session_crypto(&self) -> Result<Arc<C>, CsError> {
        self.with(|c| c.session_crypto.clone())
    }

    pub fn server_public(&self) -> Result<C::PublicKey, CsError> {
        self.with(|c| c.server_public.clone())
    }

    pub fn is_timeout(&self) -> bool {
        self.with(|c| c.last_recv.elapsed() > c.ttl).unwrap_or(true)
    }
}

impl<C: Crypto> Default for Connection<C> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}
