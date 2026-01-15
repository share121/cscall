use crate::{common::CsError, crypto::Crypto};
use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit, Nonce,
    aead::{AeadInPlace, OsRng, rand_core::RngCore},
};
use argon2::Argon2;

pub struct Aes256GcmCrypto {
    cipher: Aes256Gcm,
}

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

impl Crypto for Aes256GcmCrypto {
    const SALT_LEN: usize = 32;
    const KEY_LEN: usize = 32;
    const ADDITION_LEN: usize = TAG_LEN + NONCE_LEN;
    type Salt = [u8; Self::SALT_LEN];
    type Key = [u8; Self::KEY_LEN];

    fn new(key: &[u8]) -> Result<Self, CsError> {
        let cipher = Aes256Gcm::new(key.into());
        Ok(Self { cipher })
    }

    fn gen_salt() -> Result<Self::Salt, CsError> {
        let mut salt = [0u8; Self::SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Ok(salt)
    }

    fn derive_key(pwd: &[u8], salt: &Self::Salt) -> Result<Self::Key, CsError> {
        let mut key = [0u8; Self::KEY_LEN];
        let params = argon2::Params::new(
            64 * 1024, // 64MB
            3,         // iterations
            1,         // parallelism
            Some(32),
        )
        .or(Err(CsError::Crypto))?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon2
            .hash_password_into(pwd, salt, &mut key)
            .or(Err(CsError::Crypto))?;
        Ok(key)
    }

    /// Return [Ciphertext + Tag] + [Nonce]
    fn encrypt(&self, associated_data: &[u8], buffer: &mut Vec<u8>) -> Result<(), CsError> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        buffer.reserve(Self::ADDITION_LEN);
        self.cipher
            .encrypt_in_place(&nonce, associated_data, buffer)
            .or(Err(CsError::Crypto))?;
        buffer.extend_from_slice(&nonce);
        Ok(())
    }

    fn decrypt(&self, associated_data: &[u8], buffer: &mut Vec<u8>) -> Result<(), CsError> {
        if buffer.len() < Self::ADDITION_LEN {
            return Err(CsError::Crypto);
        }
        let nonce_start = buffer.len() - NONCE_LEN;
        let nonce = *Nonce::from_slice(&buffer[nonce_start..]);
        buffer.truncate(nonce_start);
        self.cipher
            .decrypt_in_place(&nonce, associated_data, buffer)
            .or(Err(CsError::Crypto))
    }
}
