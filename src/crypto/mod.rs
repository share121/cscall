use crate::CsError;

#[cfg(feature = "aes256gcm")]
pub mod aes256gcm;
pub mod nocrypto;

pub trait ByteArray: AsRef<[u8]> + AsMut<[u8]> + Default + Send + Clone {}
impl<T> ByteArray for T where T: AsRef<[u8]> + AsMut<[u8]> + Default + Send + Clone {}

pub trait Crypto: Send + Sync + 'static {
    const SALT_LEN: usize;
    const KEY_LEN: usize;
    const ADDITION_LEN: usize;
    const PUB_KEY_LEN: usize;

    type Salt: ByteArray;
    type Key: ByteArray;
    type PublicKey: ByteArray;
    type SecretKey: Send;
    type SharedSecret: ByteArray;

    fn new(key: &[u8]) -> Result<Self, CsError>
    where
        Self: Sized;
    fn gen_salt() -> Result<Self::Salt, CsError>;
    fn derive_key(pwd: &[u8], salt: &[u8]) -> Result<Self::Key, CsError>;
    fn encrypt(&self, associated_data: &[u8], buf: &mut Vec<u8>) -> Result<(), CsError>;
    fn decrypt(&self, associated_data: &[u8], buf: &mut Vec<u8>) -> Result<(), CsError>;
    fn gen_keypair() -> Result<(Self::SecretKey, Self::PublicKey), CsError>;
    fn diffie_hellman(
        secret: Self::SecretKey,
        public: &[u8],
    ) -> Result<Self::SharedSecret, CsError>;
}

pub fn hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}
