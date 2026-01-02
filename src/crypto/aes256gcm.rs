use crate::crypto::Crypto;
use aes_gcm::{
    AeadCore, Aes256Gcm, KeyInit, Nonce,
    aead::{AeadInPlace, OsRng, rand_core::RngCore},
};
use argon2::Argon2;
use sha2::{Digest, Sha256};

pub struct Aes256GcmCrypt {
    cipher: Aes256Gcm,
}

pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

impl Crypto for Aes256GcmCrypt {
    const SALT_LEN: usize = 32;
    const KEY_LEN: usize = 32;
    const ADDITION_LEN: usize = TAG_LEN + NONCE_LEN;
    type Salt = [u8; Self::SALT_LEN];
    type Key = [u8; Self::KEY_LEN];
    type Error = aes_gcm::Error;

    fn new(key: &[u8]) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self {
            cipher: Aes256Gcm::new(key.into()),
        })
    }

    fn mix_salt(salt_a: &Self::Salt, salt_b: &Self::Salt) -> Result<Self::Salt, Self::Error> {
        let mut hasher = Sha256::new();
        hasher.update(salt_a);
        hasher.update(salt_b);
        let res = hasher.finalize();
        Ok(res.into())
    }

    fn gen_salt() -> Result<Self::Salt, Self::Error> {
        let mut salt = [0u8; Self::SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        Ok(salt)
    }

    fn derive_key(pwd: &[u8], salt: &Self::Salt) -> Result<Self::Key, Self::Error> {
        let mut key = [0u8; Self::KEY_LEN];
        let params = argon2::Params::new(
            64 * 1024, // 64MB
            3,         // iterations
            1,         // parallelism
            Some(32),
        )
        .map_err(|_| aes_gcm::Error)?;
        let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
        argon2
            .hash_password_into(pwd, salt, &mut key)
            .map_err(|_| aes_gcm::Error)?;
        Ok(key)
    }

    /// Return [Ciphertext + Tag] + [Nonce]
    fn encrypt(&self, associated_data: &[u8], buffer: &mut Vec<u8>) -> Result<(), Self::Error> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        buffer.reserve(Self::ADDITION_LEN);
        self.cipher
            .encrypt_in_place(&nonce, associated_data, buffer)
            .or(Err(aes_gcm::Error))?;
        buffer.extend_from_slice(&nonce);
        Ok(())
    }

    fn decrypt(&self, associated_data: &[u8], buffer: &mut Vec<u8>) -> Result<(), Self::Error> {
        if buffer.len() < Self::ADDITION_LEN {
            return Err(aes_gcm::Error);
        }
        let nonce_start = buffer.len() - NONCE_LEN;
        let nonce = *Nonce::from_slice(&buffer[nonce_start..]);
        buffer.truncate(nonce_start);
        self.cipher
            .decrypt_in_place(&nonce, associated_data, buffer)
            .or(Err(aes_gcm::Error))
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_encryption_and_decryption() {
//         let pwd = b"a long and secure password";
//         let salt = Aes::gen_salt();

//         let original_text = b"Secret Message";

//         let mut data = original_text.to_vec();
//         let aes = Aes::from_pwd(pwd, &salt).unwrap();
//         aes.encrypt(&[], &mut data).unwrap();
//         assert_ne!(data, original_text);
//         assert_eq!(data.len(), original_text.len() + META_LEN);

//         let aes2 = Aes::from_pwd(pwd, &salt).unwrap();
//         aes2.decrypt(&[], &mut data).expect("Decryption failed");
//         assert_eq!(data, original_text);
//     }

//     #[test]
//     fn test_wrong_password() {
//         let original_text = b"Secret Message";
//         let salt = Aes::gen_salt();

//         let mut data = original_text.to_vec();
//         let aes = Aes::from_pwd(b"real password", &salt).unwrap();
//         aes.encrypt(&[], &mut data).unwrap();
//         assert_ne!(data, original_text);
//         assert_eq!(data.len(), original_text.len() + META_LEN);

//         let aes2 = Aes::from_pwd(b"wrong password", &salt).unwrap();
//         aes2.decrypt(&[], &mut data)
//             .expect_err("Decryption should fail");
//         assert_ne!(data, original_text);
//     }

//     #[test]
//     fn test_empty_ciphertext() {
//         let pwd = b"a long and secure password";
//         let original_text = b"";
//         let salt = Aes::gen_salt();

//         let mut data = original_text.to_vec();
//         let aes = Aes::from_pwd(pwd, &salt).unwrap();
//         aes.encrypt(&[], &mut data).unwrap();
//         assert_ne!(data, original_text);
//         assert_eq!(data.len(), original_text.len() + META_LEN);

//         let aes2 = Aes::from_pwd(pwd, &salt).unwrap();
//         aes2.decrypt(&[], &mut data).expect("Decryption failed");
//         assert_eq!(data, original_text);
//     }
// }
