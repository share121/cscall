use crate::{CsError, crypto::Crypto};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit, Nonce, aead::AeadInPlace};
use argon2::Argon2;
use rand::{RngCore, rngs::OsRng};
use x25519_dalek::{EphemeralSecret, PublicKey};

pub struct Aes256GcmCrypto {
    cipher: Aes256Gcm,
}

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

impl Crypto for Aes256GcmCrypto {
    const SALT_LEN: usize = 32;
    const KEY_LEN: usize = 32;
    const ADDITION_LEN: usize = TAG_LEN + NONCE_LEN;
    const PUB_KEY_LEN: usize = 32;

    type Salt = [u8; Self::SALT_LEN];
    type Key = [u8; Self::KEY_LEN];
    type PublicKey = [u8; Self::PUB_KEY_LEN];
    type SecretKey = EphemeralSecret;
    type SharedSecret = [u8; 32];

    fn new(key: &[u8]) -> Result<Self, CsError> {
        let cipher = Aes256Gcm::new(key.into());
        Ok(Self { cipher })
    }

    fn gen_salt() -> Result<Self::Salt, CsError> {
        let mut salt = [0u8; Self::SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Ok(salt)
    }

    fn derive_key(pwd: &[u8], salt: &[u8]) -> Result<Self::Key, CsError> {
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
    fn encrypt(&self, associated_data: &[u8], buf: &mut Vec<u8>) -> Result<(), CsError> {
        let nonce = Aes256Gcm::generate_nonce(OsRng);
        buf.reserve(Self::ADDITION_LEN);
        self.cipher
            .encrypt_in_place(&nonce, associated_data, buf)
            .or(Err(CsError::Crypto))?;
        buf.extend_from_slice(&nonce);
        Ok(())
    }

    fn decrypt(&self, associated_data: &[u8], buf: &mut Vec<u8>) -> Result<(), CsError> {
        if buf.len() < Self::ADDITION_LEN {
            return Err(CsError::Crypto);
        }
        let nonce_start = buf.len() - NONCE_LEN;
        let nonce = *Nonce::from_slice(&buf[nonce_start..]);
        buf.truncate(nonce_start);
        self.cipher
            .decrypt_in_place(&nonce, associated_data, buf)
            .or(Err(CsError::Crypto))
    }

    fn gen_keypair() -> Result<(Self::SecretKey, Self::PublicKey), CsError> {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Ok((secret, public.to_bytes()))
    }

    fn diffie_hellman(
        secret: Self::SecretKey,
        public: &[u8],
    ) -> Result<Self::SharedSecret, CsError> {
        let public_key: [u8; 32] = public.try_into().or(Err(CsError::Crypto))?;
        let public_key = PublicKey::from(public_key);
        let shared_secret = secret.diffie_hellman(&public_key);
        Ok(shared_secret.to_bytes())
    }
}
