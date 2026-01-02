pub mod client;
pub mod common;
pub mod connection;
pub mod crypto;
pub mod package;
pub mod server;

pub const UID_LEN: usize = 16;
pub const COUNT_LEN: usize = size_of::<u64>();
pub const TIMESTAMP_LEN: usize = size_of::<u64>();
pub const REORDER_WINDOW: u64 = 128;

pub const MAX_LIFE: u32 = 4;
pub const HEARTBEAT_MS: u64 = 5000;

#[allow(non_snake_case, non_upper_case_globals)]
pub mod EventType {
    /// SessionKey(PlainText + Count) + Uid + Encrypted
    pub const Encrypted: u8 = 0;

    /// 63个0 + Hello
    /// 填充 63 个 0 防止利用服务器来反射攻击
    pub const Hello: u8 = 1;

    /// ServerSalt + AckHello
    pub const AckHello: u8 = 2;

    /// ServerKey(SessionKey + TimeStamp + Uid) + Connect
    pub const Connect: u8 = 3;

    /// SessionKey(Uid) + AckConnect
    pub const AckConnect: u8 = 4;

    /// SessionKey(Count) + Uid + Heartbeat
    pub const Heartbeat: u8 = 5;

    /// SessionKey(Count) + Uid + AckHeartbeat
    pub const AckHeartbeat: u8 = 6;
}
