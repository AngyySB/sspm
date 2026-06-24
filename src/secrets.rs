//! Hashing, encryption/decryption, and session key (un)locking.

use aes_gcm::{
    Aes256Gcm, Key,
    aead::{Aead, AeadCore, KeyInit, generic_array::GenericArray},
};
use anyhow::bail;
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, SaltString},
};
use base64::{Engine, prelude::BASE64_STANDARD};
use hkdf::Hkdf;
use linux_keyutils::{KeyError, KeyRing, KeyRingIdentifier};
use rand::rngs::OsRng;
use sha2::Sha256;

use crate::storage::get_json;
use crate::structs::{KEY_DESC, TIMEOUT};

/// Generates a fresh random salt for hashing the master password.
pub fn gen_salt() -> SaltString {
    SaltString::generate(&mut OsRng)
}

/// Derives an encryption key and an authentication hash from the master password and salt.
pub fn master_hash(p: &String, s: &SaltString) -> (String, String) {
    let argon = Argon2::default();

    let pass_hash = argon
        .hash_password(p.as_bytes(), s.as_salt())
        .expect("failed to compute hash");

    let output = pass_hash.hash.unwrap();

    let hkdf_builder = Hkdf::<Sha256>::from_prk(output.as_bytes())
        .expect("error matching argon output length to sha block size");

    let mut encryption_key = [0u8; 32];
    hkdf_builder
        .expand(b"YourApp v1 Encryption Key", &mut encryption_key)
        .expect("32 bytes is valid for SHA-256 expansion");

    // 4. Expand independent Authentication Key (e.g., for HMAC)
    let mut auth_key = [0u8; 32];
    hkdf_builder
        .expand(b"YourApp v1 Authentication Key", &mut auth_key)
        .expect("32 bytes is valid for SHA-256 expansion");

    (
        encode_base64(encryption_key.to_vec()),
        encode_base64(auth_key.to_vec()),
    )
}

/// Checks user input against the stored master password hash, returning the encryption key on success.
pub fn check_master_password(input: &String) -> anyhow::Result<String> {
    let f = get_json()?;
    let salt = SaltString::from_b64(f.salt.as_str())?;

    let (u_enc, u_pass) = master_hash(input, &salt);

    if u_pass == f.master_password {
        Ok(u_enc)
    } else {
        bail!("incorrect master password")
    }
}

/// Encrypts a plaintext password with AES-256-GCM, returning the ciphertext and nonce.
pub fn encrypt(key_bytes: &Vec<u8>, pass: String) -> Result<(Vec<u8>, Vec<u8>), aes_gcm::Error> {
    let key: &Key<Aes256Gcm> = key_bytes.as_slice().into();
    let cipher = Aes256Gcm::new(key);

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, pass.as_bytes())?;
    Ok((ciphertext, nonce.to_vec()))
}

/// Decrypts an AES-256-GCM ciphertext back into the plaintext password.
pub fn decrypt(
    key_bytes: &Vec<u8>,
    nonce: &String,
    ciphertext: &String,
) -> Result<String, aes_gcm::Error> {
    let key: &Key<Aes256Gcm> = key_bytes.as_slice().into();
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes = BASE64_STANDARD.decode(nonce).expect("error decoding nonce");

    let correct_nonce = GenericArray::from_slice(&nonce_bytes);

    let plaintext_bytes = cipher.decrypt(correct_nonce, decode_base64(ciphertext).as_slice())?;

    let plaintext = String::from_utf8(plaintext_bytes).expect("decrypted data was not valid");
    Ok(plaintext)
}

/// Encodes raw bytes as a base64 string.
pub fn encode_base64(ba: Vec<u8>) -> String {
    BASE64_STANDARD.encode(ba.as_slice())
}

/// Decodes a base64 string back into raw bytes.
pub fn decode_base64(s: &String) -> Vec<u8> {
    BASE64_STANDARD
        .decode(s)
        .expect("error decoding string to vector")
}

/// Stores the unlocked encryption key in the session keyring until it times out.
pub fn unlock(ba: String) -> std::result::Result<(), KeyError> {
    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, true)?;
    let key = ring.add_key(KEY_DESC, &ba)?;
    key.set_timeout(TIMEOUT)?;
    Ok(())
}

/// Reads the unlocked encryption key from the session keyring, if present.
pub fn get_unlocked_key() -> std::result::Result<String, KeyError> {
    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)?;
    let key = ring.search(KEY_DESC)?;
    let secret_bytes = key.read_to_vec()?;
    key.set_timeout(TIMEOUT)?;

    let data = String::from_utf8(secret_bytes).map_err(|_| KeyError::InvalidArguments)?;

    Ok(data)
}

/// Invalidates the session keyring entry, locking the vault.
pub fn lock() -> std::result::Result<(), KeyError> {
    let ring = KeyRing::from_special_id(KeyRingIdentifier::Session, false)?;
    let key = ring.search(KEY_DESC)?;
    key.invalidate()?;
    Ok(())
}
