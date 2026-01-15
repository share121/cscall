pub mod client;
pub mod coder;
pub mod common;
pub mod connection;
pub mod crypto;
pub mod server;

pub const UID_LEN: usize = 16;
pub const COUNT_LEN: usize = size_of::<u64>();
pub const TIMESTAMP_LEN: usize = size_of::<u64>();
pub const REORDER_WINDOW: u64 = 128;
pub const PUB_KEY_LEN: usize = 32;

pub const MAX_LIFE: u32 = 6;
pub const HEARTBEAT_MS: u64 = 10000;

#[allow(non_snake_case, non_upper_case_globals)]
pub mod EventType {
    /// SessionKey(PlainText + Count) + Uid + Encrypted
    pub const Encrypted: u8 = 1;

    /// 63个0 + Hello
    /// 填充 63 个 0 防止利用服务器来反射攻击
    pub const Hello: u8 = 2;

    /// ServerSalt + AckHello
    pub const AckHello: u8 = 3;

    /// ServerKey(ClientPub + TimeStamp + Uid) + Connect
    pub const Connect: u8 = 4;

    /// ServerKey(ServerPub + Uid) + AckConnect
    pub const AckConnect: u8 = 5;

    /// SessionKey(Count) + Uid + Heartbeat
    pub const Heartbeat: u8 = 6;

    /// SessionKey(Count) + Uid + AckHeartbeat
    pub const AckHeartbeat: u8 = 7;
}
