use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use generic_array::GenericArray;

/// Encrypts data using AES-256-GCM
pub fn encrypt(data: &str, key: &str) -> Result<String> {
    // Decode the base64-encoded key
    let key_bytes = BASE64
        .decode(key)
        .context("Failed to decode encryption key")?;

    if key_bytes.len() != 32 {
        anyhow::bail!("Encryption key must be 32 bytes");
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).context("Failed to create cipher")?;

    // Generate a random 12-byte nonce
    let nonce_bytes = aes_gcm::aead::rand_core::RngCore::next_u64(&mut OsRng);
    let nonce_bytes2 = aes_gcm::aead::rand_core::RngCore::next_u32(&mut OsRng);
    let mut nonce_array = [0u8; 12];
    nonce_array[0..8].copy_from_slice(&nonce_bytes.to_le_bytes());
    nonce_array[8..12].copy_from_slice(&nonce_bytes2.to_le_bytes());
    let nonce = generic_array::GenericArray::from_slice(&nonce_array).into_0_14();

    // Encrypt the data
    let ciphertext = cipher
        .encrypt(&nonce, data.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {e}"))?;

    // Prepend nonce to ciphertext and encode as base64
    let mut result = nonce_array.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(BASE64.encode(result))
}

/// Decrypts data using AES-256-GCM
pub fn decrypt(encrypted_data: &str, key: &str) -> Result<String> {
    // Decode the base64-encoded key
    let key_bytes = BASE64
        .decode(key)
        .context("Failed to decode encryption key")?;

    if key_bytes.len() != 32 {
        anyhow::bail!("Encryption key must be 32 bytes");
    }

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).context("Failed to create cipher")?;

    // Decode the base64-encoded encrypted data
    let encrypted_bytes = BASE64
        .decode(encrypted_data)
        .context("Failed to decode encrypted data")?;

    if encrypted_bytes.len() < 12 {
        anyhow::bail!("Invalid encrypted data: too short");
    }

    // Extract nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted_bytes.split_at(12);
    let nonce = GenericArray::from_slice(nonce_bytes).into_0_14();

    // Decrypt the data
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed: {e}"))?;

    String::from_utf8(plaintext).context("Failed to convert decrypted data to string")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        // Generate a test key (32 bytes = 256 bits)
        let key = BASE64.encode([0u8; 32]);
        let original = "test_refresh_token_12345";

        let encrypted = encrypt(original, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();

        assert_eq!(original, decrypted);
    }

    #[test]
    fn test_encrypt_produces_different_results() {
        let key = BASE64.encode([0u8; 32]);
        let original = "test_refresh_token_12345";

        let encrypted1 = encrypt(original, &key).unwrap();
        let encrypted2 = encrypt(original, &key).unwrap();

        // Due to random nonces, each encryption should produce different results
        assert_ne!(encrypted1, encrypted2);

        // But both should decrypt to the same value
        assert_eq!(decrypt(&encrypted1, &key).unwrap(), original);
        assert_eq!(decrypt(&encrypted2, &key).unwrap(), original);
    }
}
