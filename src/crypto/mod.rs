#[cfg(feature = "aes256gcm")]
pub mod aes256gcm;

pub trait ByteArray:
    AsRef<[u8]> + AsMut<[u8]> + Default + Send + Sync + Clone + std::fmt::Debug
{
}
impl<T> ByteArray for T where
    T: AsRef<[u8]> + AsMut<[u8]> + Default + Send + Sync + Clone + std::fmt::Debug
{
}

pub trait Crypto: Send + Sync + 'static {
    const SALT_LEN: usize;
    const KEY_LEN: usize;
    const ADDITION_LEN: usize;

    type Salt: ByteArray;
    type Key: ByteArray;

    type Error: Send + 'static;
    fn new(key: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn mix_salt(salt_a: &Self::Salt, salt_b: &Self::Salt) -> Result<Self::Salt, Self::Error>;
    fn gen_salt() -> Result<Self::Salt, Self::Error>;
    fn derive_key(pwd: &[u8], salt: &Self::Salt) -> Result<Self::Key, Self::Error>;
    fn encrypt(&self, associated_data: &[u8], data: &mut Vec<u8>) -> Result<(), Self::Error>;
    fn decrypt(&self, associated_data: &[u8], data: &mut Vec<u8>) -> Result<(), Self::Error>;
}
