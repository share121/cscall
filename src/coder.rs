use crate::{COUNT_LEN, CsError, EventType, PUB_KEY_LEN, TIMESTAMP_LEN, UID_LEN, crypto::Crypto};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x25519_dalek::PublicKey;

pub fn build_associated_data(uid: &[u8; UID_LEN], event_type: u8) -> [u8; UID_LEN + 1] {
    let mut associated_data = [0; UID_LEN + 1];
    associated_data[..UID_LEN].copy_from_slice(uid);
    associated_data[UID_LEN] = event_type;
    associated_data
}

pub struct Encoder;
impl Encoder {
    /// SessionKey(PlainText + Count) + Uid + Encrypted
    pub fn encrypted<C: Crypto>(
        session_crypto: &C,
        count: u64,
        uid: &[u8; UID_LEN],
        buf: &mut Vec<u8>,
    ) -> Result<(), CsError> {
        buf.reserve(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        let associated_data = build_associated_data(uid, EventType::Encrypted);
        session_crypto.encrypt(&associated_data, buf)?;
        buf.extend_from_slice(uid);
        buf.push(EventType::Encrypted);
        Ok(())
    }

    /// 63个0 + Hello
    pub fn hello() -> [u8; 64] {
        let mut buf = [0; 64];
        *buf.last_mut().unwrap() = EventType::Hello;
        buf
    }

    /// ServerSalt + AckHello
    pub fn ack_hello<C: Crypto>(server_salt: &C::Salt, buf: &mut Vec<u8>) {
        buf.clear();
        buf.reserve(C::SALT_LEN + 1);
        buf.extend_from_slice(server_salt.as_ref());
        buf.push(EventType::AckHello);
    }

    /// ServerKey(ClientPub + Ttl + TimeStamp + Uid) + Connect
    pub fn connect<C: Crypto>(
        server_crypto: &C,
        client_pub: &[u8; PUB_KEY_LEN],
        ttl: Duration,
        uid: &[u8; UID_LEN],
        buf: &mut Vec<u8>,
    ) -> Result<(), CsError> {
        buf.clear();
        buf.reserve(PUB_KEY_LEN + size_of::<u64>() + TIMESTAMP_LEN + UID_LEN + C::ADDITION_LEN + 1);
        buf.extend_from_slice(client_pub);
        buf.extend_from_slice(&ttl.as_secs().to_le_bytes());
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        buf.extend_from_slice(&timestamp.to_le_bytes());
        buf.extend_from_slice(uid);
        server_crypto.encrypt(&[EventType::Connect], buf)?;
        buf.push(EventType::Connect);
        Ok(())
    }

    /// ServerKey(ServerPub) + AckConnect
    pub fn ack_connect<C: Crypto>(
        server_crypto: &C,
        server_pub: &[u8; PUB_KEY_LEN],
        uid: &[u8; UID_LEN],
        buf: &mut Vec<u8>,
    ) -> Result<(), CsError> {
        buf.clear();
        buf.reserve(PUB_KEY_LEN + C::ADDITION_LEN + 1);
        buf.extend_from_slice(server_pub);
        let associated_data = build_associated_data(uid, EventType::AckConnect);
        server_crypto.encrypt(&associated_data, buf)?;
        buf.push(EventType::AckConnect);
        Ok(())
    }

    /// SessionKey(Count) + Uid + Heartbeat
    pub fn heartbeat<C: Crypto>(
        session_crypto: &C,
        count: u64,
        uid: &[u8; UID_LEN],
        buf: &mut Vec<u8>,
    ) -> Result<(), CsError> {
        buf.clear();
        buf.reserve(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        let associated_data = build_associated_data(uid, EventType::Heartbeat);
        session_crypto.encrypt(&associated_data, buf)?;
        buf.extend_from_slice(uid);
        buf.push(EventType::Heartbeat);
        Ok(())
    }

    /// SessionKey(Count) + Uid + AckHeartbeat
    pub fn ack_heartbeat<C: Crypto>(
        session_crypto: &C,
        count: u64,
        uid: &[u8; UID_LEN],
        buf: &mut Vec<u8>,
    ) -> Result<(), CsError> {
        buf.clear();
        buf.reserve(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        let associated_data = build_associated_data(uid, EventType::AckHeartbeat);
        session_crypto.encrypt(&associated_data, buf)?;
        buf.extend_from_slice(uid);
        buf.push(EventType::AckHeartbeat);
        Ok(())
    }
}

pub struct Decoder;
impl Decoder {
    pub fn peek_uid(buf: &[u8]) -> Result<[u8; UID_LEN], CsError> {
        if buf.len() < UID_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        let uid_start = buf.len() - UID_LEN - 1;
        let uid: [u8; UID_LEN] = buf[uid_start..uid_start + UID_LEN].try_into().unwrap();
        Ok(uid)
    }

    /// SessionKey(PlainText + Count) + Uid + Encrypted|Heartbeat|AckHeartbeat
    /// Plaintext 留在 buf 中
    /// Return: (Count, Uid)
    pub fn encrypted<C: Crypto>(
        session_crypto: &C,
        buf: &mut Vec<u8>,
    ) -> Result<(u64, [u8; UID_LEN]), CsError> {
        if !matches!(
            buf.last(),
            Some(&EventType::Encrypted | &EventType::Heartbeat | &EventType::AckHeartbeat)
        ) {
            return Err(CsError::InvalidType(buf.last().cloned()));
        }
        if buf.len() < COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        let event_type = buf.pop().unwrap();

        // 提取 Uid (外部)
        let uid_start = buf.len() - UID_LEN;
        let uid: [u8; UID_LEN] = buf[uid_start..].try_into().unwrap();
        buf.truncate(uid_start);

        let associated_data = build_associated_data(&uid, event_type);
        session_crypto.decrypt(&associated_data, buf)?;

        // 解析 Count
        let count_start = buf.len() - COUNT_LEN;
        let count = u64::from_le_bytes(buf[count_start..].try_into().unwrap());
        buf.truncate(count_start);

        Ok((count, uid))
    }

    /// 63个0 + Hello
    pub fn hello(buf: &[u8]) -> Result<(), CsError> {
        if buf.last() != Some(&EventType::Hello) {
            return Err(CsError::InvalidType(buf.last().cloned()));
        }
        if buf[..buf.len() - 1] == [0; 63] {
            Ok(())
        } else {
            Err(CsError::InvalidFormat)
        }
    }

    /// ServerSalt + AckHello
    /// Return ServerSalt
    pub fn ack_hello<C: Crypto>(buf: &[u8]) -> Result<C::Salt, CsError> {
        if buf.last() != Some(&EventType::AckHello) {
            return Err(CsError::InvalidType(buf.last().cloned()));
        }
        if buf.len() != C::SALT_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        let mut salt = C::Salt::default();
        salt.as_mut().copy_from_slice(&buf[..C::SALT_LEN]);
        Ok(salt)
    }

    /// ServerKey(ClientPub + Ttl + TimeStamp + Uid) + Connect
    /// Return: (ClientPub, Ttl, TimeStamp, Uid)
    pub fn connect<C: Crypto>(
        server_crypto: &C,
        buf: &mut Vec<u8>,
    ) -> Result<(PublicKey, Duration, u64, [u8; UID_LEN]), CsError> {
        if buf.last() != Some(&EventType::Connect) {
            return Err(CsError::InvalidType(buf.last().cloned()));
        }
        if buf.len()
            != PUB_KEY_LEN + size_of::<u64>() + TIMESTAMP_LEN + UID_LEN + C::ADDITION_LEN + 1
        {
            return Err(CsError::InvalidFormat);
        }
        buf.pop();
        server_crypto.decrypt(&[EventType::Connect], buf)?;

        // 提取 Uid
        let uid_start = buf.len() - UID_LEN;
        let uid: [u8; UID_LEN] = buf[uid_start..].try_into().unwrap();
        buf.truncate(uid_start);

        // 提取 Timestamp
        let ts_start = buf.len() - TIMESTAMP_LEN;
        let timestamp = u64::from_le_bytes(buf[ts_start..].try_into().unwrap());
        buf.truncate(ts_start);

        // 提取 Ttl
        let ttl = u64::from_le_bytes(buf[PUB_KEY_LEN..].try_into().unwrap());
        let ttl = Duration::from_secs(ttl);

        // 提取 ClientPub
        let client_pub: [u8; PUB_KEY_LEN] = buf[..PUB_KEY_LEN].try_into().unwrap();
        let client_pub = PublicKey::from(client_pub);
        Ok((client_pub, ttl, timestamp, uid))
    }

    /// ServerKey(ServerPub) + AckConnect
    /// Return: ServerPub
    pub fn ack_connect<C: Crypto>(
        server_crypto: &C,
        uid: &[u8; UID_LEN],
        buf: &mut Vec<u8>,
    ) -> Result<PublicKey, CsError> {
        if buf.last() != Some(&EventType::AckConnect) {
            return Err(CsError::InvalidType(buf.last().cloned()));
        }
        if buf.len() != PUB_KEY_LEN + C::ADDITION_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        buf.pop();

        let associated_data = build_associated_data(uid, EventType::AckConnect);
        server_crypto.decrypt(&associated_data, buf)?;

        let server_pub: [u8; PUB_KEY_LEN] = buf[..].try_into().unwrap();
        let server_pub = PublicKey::from(server_pub);
        Ok(server_pub)
    }
}
