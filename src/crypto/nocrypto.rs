use crate::{COUNT_LEN, CsError, crypto::Crypto};

pub struct NoCrypto;
impl Crypto for NoCrypto {
    const SALT_LEN: usize = 0;
    const KEY_LEN: usize = 0;
    const ADDITION_LEN: usize = COUNT_LEN;
    const PUB_KEY_LEN: usize = 0;
    type Salt = [u8; 0];
    type Key = [u8; 0];
    type PublicKey = [u8; 0];
    type SecretKey = [u8; 0];
    type SharedSecret = [u8; 0];
    type Hash = [u8; 0];

    fn new(_: &[u8]) -> Result<Self, CsError> {
        Ok(Self)
    }
    fn gen_salt() -> Result<Self::Salt, CsError> {
        Ok([])
    }
    fn derive_key(_: &[u8], _: &[u8]) -> Result<Self::Key, CsError> {
        Ok([])
    }
    fn encrypt(&self, count: u64, _: &[u8], buf: &mut Vec<u8>) -> Result<(), CsError> {
        buf.extend_from_slice(&count.to_le_bytes());
        Ok(())
    }
    fn decrypt(&self, _: &[u8], buf: &mut Vec<u8>) -> Result<u64, CsError> {
        if buf.len() < COUNT_LEN {
            return Err(CsError::Crypto);
        }
        let start = buf.len() - COUNT_LEN;
        let count = u64::from_le_bytes(buf[start..].try_into().unwrap());
        buf.truncate(start);
        Ok(count)
    }
    fn gen_keypair() -> Result<(Self::SecretKey, Self::PublicKey), CsError> {
        Ok(([], []))
    }
    fn diffie_hellman(_: Self::SecretKey, _: &[u8]) -> Result<Self::SharedSecret, CsError> {
        Ok([])
    }
    fn hash(_: &[&[u8]]) -> Result<Self::Hash, CsError> {
        Ok([])
    }
}
