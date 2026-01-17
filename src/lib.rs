pub mod client;
pub mod coder;
pub mod connection;
pub mod crypto;
pub mod server;

pub const UID_LEN: usize = 16;
pub const COUNT_LEN: usize = size_of::<u64>();
pub const TIMESTAMP_LEN: usize = size_of::<u64>();
pub const REORDER_WINDOW: u64 = 128;
pub const PUB_KEY_LEN: usize = 32;

#[allow(non_snake_case, non_upper_case_globals)]
pub mod EventType {
    /// SessionKey(PlainText + Count) + Uid + Encrypted
    pub const Encrypted: u8 = 1;

    /// 63个0 + Hello
    /// 填充 63 个 0 防止利用服务器来反射攻击
    pub const Hello: u8 = 2;

    /// ServerSalt + AckHello
    pub const AckHello: u8 = 3;

    /// ServerKey(ClientPub + Ttl + TimeStamp + Uid) + Connect
    pub const Connect: u8 = 4;

    /// ServerKey(ServerPub) + AckConnect
    pub const AckConnect: u8 = 5;

    /// SessionKey(Count) + Uid + Heartbeat
    pub const Heartbeat: u8 = 6;

    /// SessionKey(Count) + Uid + AckHeartbeat
    pub const AckHeartbeat: u8 = 7;
}

#[derive(Debug, thiserror::Error)]
pub enum CsError {
    // IO
    #[error("Failed to send data")]
    Socket(#[from] std::io::Error),

    // 加解密
    #[error("Failed to crypto")]
    Crypto,

    // 连接
    #[error("Connection broken")]
    ConnectionBroken,

    // 消息解码
    #[error("Invalid type")]
    InvalidType(Option<u8>),
    #[error("Invalid format")]
    InvalidFormat,
    #[error("Invalid uid")]
    InvalidUid([u8; UID_LEN]),
    #[error("Invalid counter")]
    InvalidCounter(u64),
    #[error("Invalid timestamp")]
    InvalidTimestamp(u64),

    // 系统
    #[error("System time error")]
    SystemTime(#[from] std::time::SystemTimeError),
}
