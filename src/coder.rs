use x25519_dalek::PublicKey;

use crate::{
    COUNT_LEN, EventType, PUB_KEY_LEN, TIMESTAMP_LEN, UID_LEN, common::CsError, crypto::Crypto,
};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Encoder;
impl Encoder {
    /// SessionKey(PlainText + Count) + Uid + Encrypted
    pub fn encrypted<C: Crypto>(
        buf: &mut Vec<u8>,
        session_crypto: &C,
        count: u64,
        uid: &[u8; UID_LEN],
    ) -> Result<(), CsError> {
        buf.reserve(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        let mut associated_data = [0; UID_LEN + 1];
        associated_data[..UID_LEN].copy_from_slice(uid);
        associated_data[UID_LEN] = EventType::Encrypted;
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
    pub fn ack_hello<C: Crypto>(server_salt: &C::Salt) -> Vec<u8> {
        let mut buf = Vec::with_capacity(C::SALT_LEN + 1);
        buf.extend_from_slice(server_salt.as_ref());
        buf.push(EventType::AckHello);
        buf
    }

    /// ServerKey(ClientPub + TimeStamp + Uid) + Connect
    pub fn connect<C: Crypto>(
        server_crypto: &C,
        client_pub: &[u8; PUB_KEY_LEN],
        uid: &[u8; UID_LEN],
    ) -> Result<Vec<u8>, CsError> {
        let mut buf =
            Vec::with_capacity(PUB_KEY_LEN + TIMESTAMP_LEN + UID_LEN + C::ADDITION_LEN + 1);
        buf.extend_from_slice(client_pub);
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        buf.extend_from_slice(&timestamp.to_le_bytes());
        buf.extend_from_slice(uid);
        server_crypto.encrypt(&[EventType::Connect], &mut buf)?;
        buf.push(EventType::Connect);
        Ok(buf)
    }

    /// ServerKey(ServerPub + Uid) + AckConnect
    pub fn ack_connect<C: Crypto>(
        server_crypto: &C,
        server_pub: &[u8; PUB_KEY_LEN],
        uid: &[u8; UID_LEN],
    ) -> Result<Vec<u8>, CsError> {
        let mut buf = Vec::with_capacity(PUB_KEY_LEN + UID_LEN + C::ADDITION_LEN + 1);
        buf.extend_from_slice(server_pub);
        buf.extend_from_slice(uid);
        server_crypto.encrypt(&[EventType::AckConnect], &mut buf)?;
        buf.push(EventType::AckConnect);
        Ok(buf)
    }

    /// SessionKey(Count) + Uid + Heartbeat
    pub fn heartbeat<C: Crypto>(
        session_crypto: &C,
        count: u64,
        uid: &[u8; UID_LEN],
    ) -> Result<Vec<u8>, CsError> {
        let mut buf = Vec::with_capacity(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        let mut associated_data = [0; UID_LEN + 1];
        associated_data[..UID_LEN].copy_from_slice(uid);
        associated_data[UID_LEN] = EventType::Heartbeat;
        session_crypto.encrypt(&associated_data, &mut buf)?;
        buf.extend_from_slice(uid);
        buf.push(EventType::Heartbeat);
        Ok(buf)
    }

    /// SessionKey(Count) + Uid + AckHeartbeat
    pub fn ack_heartbeat<C: Crypto>(
        session_crypto: &C,
        count: u64,
        uid: &[u8; UID_LEN],
    ) -> Result<Vec<u8>, CsError> {
        let mut buf = Vec::with_capacity(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        let mut associated_data = [0; UID_LEN + 1];
        associated_data[..UID_LEN].copy_from_slice(uid);
        associated_data[UID_LEN] = EventType::AckHeartbeat;
        session_crypto.encrypt(&associated_data, &mut buf)?;
        buf.extend_from_slice(uid);
        buf.push(EventType::AckHeartbeat);
        Ok(buf)
    }
}

pub struct Decoder;
impl Decoder {
    pub fn peek_uid(buf: &[u8], offset: usize) -> Result<[u8; UID_LEN], CsError> {
        if buf.len() < UID_LEN + offset {
            return Err(CsError::InvalidFormat);
        }
        let uid_start = buf.len() - UID_LEN - offset;
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

        let mut associated_data = [0; UID_LEN + 1];
        associated_data[..UID_LEN].copy_from_slice(&uid);
        associated_data[UID_LEN] = event_type;
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

    /// ServerKey(ClientPub + TimeStamp + Uid) + Connect
    /// Return: (ClientPub, TimeStamp, Uid)
    pub fn connect<C: Crypto>(
        server_crypto: &C,
        buf: &mut Vec<u8>,
    ) -> Result<(PublicKey, u64, [u8; UID_LEN]), CsError> {
        if buf.last() != Some(&EventType::Connect) {
            return Err(CsError::InvalidType(buf.last().cloned()));
        }
        if buf.len() != PUB_KEY_LEN + TIMESTAMP_LEN + UID_LEN + C::ADDITION_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        buf.pop();
        server_crypto.decrypt(&[EventType::Connect], buf)?;
        // 结构: [ClientPub] [TimeStamp] [Uid]
        // 提取 Uid
        let uid_start = buf.len() - UID_LEN;
        let uid: [u8; UID_LEN] = buf[uid_start..].try_into().unwrap();
        buf.truncate(uid_start);

        // 提取 Timestamp
        let timestamp = u64::from_le_bytes(buf[PUB_KEY_LEN..].try_into().unwrap());

        // 提取 ClientPub
        let client_pub: [u8; PUB_KEY_LEN] = buf[..PUB_KEY_LEN].try_into().unwrap();
        let client_pub = PublicKey::from(client_pub);
        Ok((client_pub, timestamp, uid))
    }

    /// ServerKey(ServerPub + Uid) + AckConnect
    /// Return: (ServerPub, Uid)
    pub fn ack_connect<C: Crypto>(
        server_crypto: &C,
        buf: &mut Vec<u8>,
    ) -> Result<(PublicKey, [u8; UID_LEN]), CsError> {
        if buf.last() != Some(&EventType::AckConnect) {
            return Err(CsError::InvalidType(buf.last().cloned()));
        }
        if buf.len() != PUB_KEY_LEN + UID_LEN + C::ADDITION_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        buf.pop();
        server_crypto.decrypt(&[EventType::AckConnect], buf)?;
        let uid: [u8; UID_LEN] = buf[PUB_KEY_LEN..].try_into().unwrap();
        let server_pub: [u8; PUB_KEY_LEN] = buf[..PUB_KEY_LEN].try_into().unwrap();
        let server_pub = PublicKey::from(server_pub);
        Ok((server_pub, uid))
    }
}
