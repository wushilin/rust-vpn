#![allow(deprecated)]

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray},
    ChaCha20Poly1305,
};
use rand::RngCore;

pub struct Crypto {
    cipher: ChaCha20Poly1305,
}

impl Crypto {
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            anyhow::bail!("Key must be 32 bytes");
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("Invalid key: {:?}", e))?;
        Ok(Crypto { cipher })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext = self
            .cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Prepend nonce to ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 12 {
            anyhow::bail!("Data too short to contain nonce");
        }

        // Extract nonce (first 12 bytes)
        let nonce = GenericArray::from_slice(&data[..12]);

        // Extract ciphertext (remaining bytes)
        let ciphertext = &data[12..];

        // Decrypt the data
        let plaintext = self
            .cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let crypto = Crypto::new(&key).unwrap();

        let plaintext = b"Hello, VPN!";
        let encrypted = crypto.encrypt(plaintext).unwrap();
        let decrypted = crypto.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_different_nonces() {
        let key = [0u8; 32];
        let crypto = Crypto::new(&key).unwrap();

        let plaintext = b"Hello, VPN!";
        let encrypted1 = crypto.encrypt(plaintext).unwrap();
        let encrypted2 = crypto.encrypt(plaintext).unwrap();

        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same plaintext
        assert_eq!(crypto.decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(crypto.decrypt(&encrypted2).unwrap(), plaintext);
    }
}
