//! Refresh tokens as storage sees them: ciphertext only.

use std::fmt;

use chrono::{DateTime, Utc};

use crate::encryption;

/// Ciphertext of a Discord refresh token.
///
/// Only catacombs encrypts plaintext into one or decrypts one, so a storage
/// implementation cannot persist a token in the clear. Storage writes
/// [`as_str`](Self::as_str) and reads it back with
/// [`from_stored`](Self::from_stored).
#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedToken(String);

impl EncryptedToken {
    pub(crate) fn encrypt(plaintext: &str, key: &str) -> anyhow::Result<Self> {
        encryption::encrypt(plaintext, key).map(Self)
    }

    pub(crate) fn decrypt(&self, key: &str) -> anyhow::Result<String> {
        encryption::decrypt(&self.0, key)
    }

    /// The ciphertext, to persist.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Wrap a value read back from storage. It is not validated: a value
    /// that is not catacombs ciphertext fails when catacombs decrypts it.
    #[must_use]
    pub fn from_stored(ciphertext: String) -> Self {
        Self(ciphertext)
    }
}

impl fmt::Debug for EncryptedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EncryptedToken(..)")
    }
}

/// The Discord refresh token catacombs keeps for a user, and when the access
/// token issued with it expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredTokens {
    /// The refresh token, encrypted.
    pub refresh_token: EncryptedToken,
    /// When the matching access token expires.
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ciphertext_round_trips_and_is_not_the_plaintext() {
        let key = encryption::generate_key();
        let token = EncryptedToken::encrypt("refresh-me", &key).unwrap();
        assert!(!token.as_str().contains("refresh-me"));
        let back = EncryptedToken::from_stored(token.as_str().to_owned());
        assert_eq!(back.decrypt(&key).unwrap(), "refresh-me");
    }

    #[test]
    fn debug_shows_no_ciphertext() {
        let token = EncryptedToken::from_stored("abc".into());
        assert_eq!(format!("{token:?}"), "EncryptedToken(..)");
    }

    #[test]
    fn a_stored_value_that_is_not_ciphertext_fails_to_decrypt() {
        let key = encryption::generate_key();
        assert!(EncryptedToken::from_stored("plain".into())
            .decrypt(&key)
            .is_err());
    }
}
