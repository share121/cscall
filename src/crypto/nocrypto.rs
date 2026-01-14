use crate::crypto::Crypto;

pub struct NoCrypto;
impl Crypto for NoCrypto {
    const SALT_LEN: usize = 0;
    const KEY_LEN: usize = 0;
    const ADDITION_LEN: usize = 0;
    type Salt = [u8; Self::SALT_LEN];
    type Key = [u8; Self::KEY_LEN];
    type Error = ();

    fn new(_: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self)
    }

    fn gen_salt() -> Result<Self::Salt, Self::Error> {
        Ok([])
    }

    fn derive_key(_: &[u8], _: &Self::Salt) -> Result<Self::Key, Self::Error> {
        Ok([])
    }

    fn encrypt(&self, _: &[u8], _: &mut Vec<u8>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn decrypt(&self, _: &[u8], _: &mut Vec<u8>) -> Result<(), Self::Error> {
        Ok(())
    }
}
