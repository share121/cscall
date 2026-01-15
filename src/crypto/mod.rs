use crate::common::CsError;

#[cfg(feature = "aes256gcm")]
pub mod aes256gcm;
pub mod nocrypto;

pub trait ByteArray: AsRef<[u8]> + AsMut<[u8]> + Default + Send + Clone {}
impl<T> ByteArray for T where T: AsRef<[u8]> + AsMut<[u8]> + Default + Send + Clone {}

pub trait Crypto: Send + Sync + 'static {
    const SALT_LEN: usize;
    const KEY_LEN: usize;
    const ADDITION_LEN: usize;

    type Salt: ByteArray;
    type Key: ByteArray;

    fn new(key: &[u8]) -> Result<Self, CsError>
    where
        Self: Sized;
    fn gen_salt() -> Result<Self::Salt, CsError>;
    fn derive_key(pwd: &[u8], salt: &Self::Salt) -> Result<Self::Key, CsError>;
    fn encrypt(&self, associated_data: &[u8], data: &mut Vec<u8>) -> Result<(), CsError>;
    fn decrypt(&self, associated_data: &[u8], data: &mut Vec<u8>) -> Result<(), CsError>;
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
