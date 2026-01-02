use crate::{COUNT_LEN, EventType, TIMESTAMP_LEN, UID_LEN, common::CsError, crypto::Crypto};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct PackageEncoder;
impl PackageEncoder {
    /// SessionKey(PlainText + Count) + Uid + Encrypted
    pub fn encrypted<C: Crypto>(
        buf: &mut Vec<u8>,
        session_crypt: &C,
        count: u64,
        uid: &[u8; UID_LEN],
    ) -> Result<(), CsError> {
        buf.reserve(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        session_crypt
            .encrypt(uid, buf)
            .map_err(|_| CsError::Encrypt)?;
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

    /// ServerKey(SessionKey + TimeStamp + Uid) + Connect
    pub fn connect<C: Crypto>(
        server_crypt: &C,
        session_key: &C::Key,
        uid: &[u8; UID_LEN],
    ) -> Result<Vec<u8>, CsError> {
        let mut buf =
            Vec::with_capacity(C::KEY_LEN + TIMESTAMP_LEN + UID_LEN + C::ADDITION_LEN + 1);
        buf.extend_from_slice(session_key.as_ref());
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        buf.extend_from_slice(&timestamp.to_le_bytes());
        buf.extend_from_slice(uid);
        server_crypt
            .encrypt(&[], &mut buf)
            .map_err(|_| CsError::Encrypt)?;
        buf.push(EventType::Connect);
        Ok(buf)
    }

    /// SessionKey(Uid) + AckConnect
    pub fn ack_connect<C: Crypto>(
        session_crypt: &C,
        uid: &[u8; UID_LEN],
    ) -> Result<Vec<u8>, CsError> {
        let mut buf = Vec::with_capacity(UID_LEN + C::ADDITION_LEN + 1);
        buf.extend_from_slice(uid);
        session_crypt
            .encrypt(&[], &mut buf)
            .map_err(|_| CsError::Encrypt)?;
        buf.push(EventType::AckConnect);
        Ok(buf)
    }

    /// SessionKey(Count) + Uid + Heartbeat
    pub fn heartbeat<C: Crypto>(
        session_crypt: &C,
        count: u64,
        uid: &[u8; UID_LEN],
    ) -> Result<Vec<u8>, CsError> {
        let mut buf = Vec::with_capacity(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        session_crypt
            .encrypt(uid, &mut buf)
            .map_err(|_| CsError::Encrypt)?;
        buf.extend_from_slice(uid);
        buf.push(EventType::Heartbeat);
        Ok(buf)
    }

    /// SessionKey(Count) + Uid + AckHeartbeat
    pub fn ack_heartbeat<C: Crypto>(
        session_crypt: &C,
        count: u64,
        uid: &[u8; UID_LEN],
    ) -> Result<Vec<u8>, CsError> {
        let mut buf = Vec::with_capacity(COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1);
        buf.extend_from_slice(&count.to_le_bytes());
        session_crypt
            .encrypt(uid, &mut buf)
            .map_err(|_| CsError::Encrypt)?;
        buf.extend_from_slice(uid);
        buf.push(EventType::AckHeartbeat);
        Ok(buf)
    }
}

pub struct PackageDecoder;
impl PackageDecoder {
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
        session_crypt: &C,
        buf: &mut Vec<u8>,
    ) -> Result<(u64, [u8; UID_LEN]), CsError> {
        if matches!(
            buf.last(),
            Some(&EventType::Encrypted | &EventType::Heartbeat | &EventType::AckHeartbeat)
        ) {
            return Err(CsError::InvalidType);
        }
        if buf.len() < COUNT_LEN + C::ADDITION_LEN + UID_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        buf.pop();

        // 提取 Uid (外部)
        let uid_start = buf.len() - UID_LEN;
        let uid: [u8; UID_LEN] = buf[uid_start..].try_into().unwrap();
        buf.truncate(uid_start);

        session_crypt
            .decrypt(&uid, buf)
            .map_err(|_| CsError::Decrypt)?;

        // 解析 Count
        let count_start = buf.len() - COUNT_LEN;
        let count = u64::from_le_bytes(buf[count_start..].try_into().unwrap());
        buf.truncate(count_start);

        Ok((count, uid))
    }

    /// 63个0 + Hello
    pub fn hello(buf: &[u8]) -> Result<(), CsError> {
        if buf.last() != Some(&EventType::Hello) {
            return Err(CsError::InvalidType);
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
            return Err(CsError::InvalidType);
        }
        if buf.len() != C::SALT_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        let mut salt = C::Salt::default();
        salt.as_mut().copy_from_slice(&buf[..C::SALT_LEN]);
        Ok(salt)
    }

    /// ServerKey(SessionKey + TimeStamp + Uid) + Connect
    /// SessionKey 留在 buf 中
    /// Return: (TimeStamp, Uid)
    pub fn connect<C: Crypto>(
        server_crypt: &C,
        buf: &mut Vec<u8>,
    ) -> Result<(u64, [u8; UID_LEN]), CsError> {
        if buf.last() != Some(&EventType::Connect) {
            return Err(CsError::InvalidType);
        }
        if buf.len() != C::KEY_LEN + TIMESTAMP_LEN + UID_LEN + C::ADDITION_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        buf.pop();
        server_crypt
            .decrypt(&[], buf)
            .map_err(|_| CsError::Decrypt)?;
        // 结构: [SessionKey] [TimeStamp] [Uid]
        // 提取 Uid
        let uid_start = buf.len() - UID_LEN;
        let uid: [u8; UID_LEN] = buf[uid_start..].try_into().unwrap();
        buf.truncate(uid_start);

        // 提取 Timestamp
        let ts_start = buf.len() - TIMESTAMP_LEN;
        let timestamp = u64::from_le_bytes(buf[ts_start..].try_into().unwrap());
        buf.truncate(ts_start);

        Ok((timestamp, uid))
    }

    /// SessionKey(Uid) + AckConnect
    /// Return: Uid
    pub fn ack_connect<C: Crypto>(
        session_crypt: &C,
        buf: &mut Vec<u8>,
    ) -> Result<[u8; UID_LEN], CsError> {
        if buf.last() != Some(&EventType::AckConnect) {
            return Err(CsError::InvalidType);
        }
        if buf.len() != UID_LEN + C::ADDITION_LEN + 1 {
            return Err(CsError::InvalidFormat);
        }
        buf.pop();
        session_crypt
            .decrypt(&[], buf)
            .map_err(|_| CsError::Decrypt)?;
        let uid: [u8; UID_LEN] = buf[..].try_into().unwrap();
        Ok(uid)
    }
}
