use crate::{CsError, crypto::Crypto};

pub struct NoCrypto;
impl Crypto for NoCrypto {
    const SALT_LEN: usize = 0;
    const KEY_LEN: usize = 0;
    const ADDITION_LEN: usize = 0;
    const PUB_KEY_LEN: usize = 0;
    type Salt = [u8; 0];
    type Key = [u8; 0];
    type PublicKey = [u8; 0];
    type SecretKey = [u8; 0];
    type SharedSecret = [u8; 0];

    fn new(_: &[u8]) -> Result<Self, CsError> {
        Ok(Self)
    }
    fn gen_salt() -> Result<Self::Salt, CsError> {
        Ok([])
    }
    fn derive_key(_: &[u8], _: &[u8]) -> Result<Self::Key, CsError> {
        Ok([])
    }
    fn encrypt(&self, _: &[u8], _: &mut Vec<u8>) -> Result<(), CsError> {
        Ok(())
    }
    fn decrypt(&self, _: &[u8], _: &mut Vec<u8>) -> Result<(), CsError> {
        Ok(())
    }
    fn gen_keypair() -> Result<(Self::SecretKey, Self::PublicKey), CsError> {
        Ok(([], []))
    }
    fn diffie_hellman(_: Self::SecretKey, _: &[u8]) -> Result<Self::SharedSecret, CsError> {
        Ok([])
    }
}
