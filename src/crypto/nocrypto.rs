use crate::{common::CsError, crypto::Crypto};

pub struct NoCrypto;
impl Crypto for NoCrypto {
    const SALT_LEN: usize = 0;
    const KEY_LEN: usize = 0;
    const ADDITION_LEN: usize = 0;
    type Salt = [u8; Self::SALT_LEN];
    type Key = [u8; Self::KEY_LEN];

    fn new(_: &[u8]) -> Result<Self, CsError> {
        Ok(Self)
    }
    fn gen_salt() -> Result<Self::Salt, CsError> {
        Ok([])
    }
    fn derive_key(_: &[u8], _: &Self::Salt) -> Result<Self::Key, CsError> {
        Ok([])
    }
    fn encrypt(&self, _: &[u8], _: &mut Vec<u8>) -> Result<(), CsError> {
        Ok(())
    }
    fn decrypt(&self, _: &[u8], _: &mut Vec<u8>) -> Result<(), CsError> {
        Ok(())
    }
}
