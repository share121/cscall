pub trait Crypt<const SALT_LEN: usize, const KEY_LEN: usize>: Send + Sync + 'static {
    type Error: Send + 'static;
    fn new(key: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized;
    fn mix_salt(salt_a: &[u8], salt_b: &[u8]) -> Result<[u8; SALT_LEN], Self::Error>;
    fn gen_salt() -> [u8; SALT_LEN];
    fn derive_key(pwd: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN], Self::Error>;
    fn encrypt(&self, associated_data: &[u8], data: &mut Vec<u8>) -> Result<(), Self::Error>;
    fn decrypt(&self, associated_data: &[u8], data: &mut Vec<u8>) -> Result<(), Self::Error>;
}
