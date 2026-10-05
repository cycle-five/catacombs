//! catacombs' piece of the host application's state.

use std::sync::Arc;

use crate::{
    config::{Config, ConfigError},
    encryption,
    storage::Storage,
};

/// catacombs' share of an application's state: configuration, storage and
/// the HTTP client for Discord.
///
/// A host keeps one in its own state and implements [`HasAuth`] to point at it.
pub struct Auth {
    config: Config,
    storage: Box<dyn Storage>,
    http_client: reqwest::Client,
}

impl Auth {
    /// Build catacombs' state.
    ///
    /// # Errors
    /// [`ConfigError::InvalidEncryptionKey`] when
    /// `config.security.encryption_key` is not a base64-encoded 32-byte key.
    /// It is checked here so a bad key fails at startup, not on every login.
    pub fn new(config: Config, storage: impl Storage + 'static) -> Result<Self, ConfigError> {
        encryption::validate_key(&config.security.encryption_key)
            .map_err(|e| ConfigError::InvalidEncryptionKey(e.to_string()))?;
        Ok(Self {
            config,
            storage: Box::new(storage),
            http_client: reqwest::Client::new(),
        })
    }

    /// Use `client` for Discord requests (timeouts, proxies, a shared pool).
    #[must_use]
    pub fn with_http_client(mut self, client: reqwest::Client) -> Self {
        self.http_client = client;
        self
    }

    /// The configuration.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The storage backend.
    pub fn storage(&self) -> &dyn Storage {
        self.storage.as_ref()
    }

    /// The HTTP client used for Discord.
    pub fn http_client(&self) -> &reqwest::Client {
        &self.http_client
    }
}

/// Where a host's state keeps its [`Auth`].
///
/// Implement it on your own state type. catacombs implements it for
/// `Arc<T>`, so a router whose state is `Arc<YourState>` works as is.
pub trait HasAuth: Send + Sync + 'static {
    /// catacombs' state.
    fn auth(&self) -> &Auth;
}

impl HasAuth for Auth {
    fn auth(&self) -> &Auth {
        self
    }
}

impl<T: HasAuth> HasAuth for Arc<T> {
    fn auth(&self) -> &Auth {
        (**self).auth()
    }
}

#[cfg(all(test, feature = "memory-storage"))]
mod tests {
    use super::*;
    use crate::{
        config::{DiscordConfig, SecurityConfig, WebConfig},
        MemoryStorage,
    };

    fn config(encryption_key: &str) -> Config {
        Config {
            discord: DiscordConfig {
                client_id: "id".into(),
                client_secret: "secret".into(),
                redirect_uri: "https://example.test/cb".into(),
                premium: None,
                api_base: crate::config::default_api_base(),
            },
            security: SecurityConfig {
                jwt_secret: "jwt".into(),
                encryption_key: encryption_key.into(),
            },
            web: WebConfig::default(),
        }
    }

    #[test]
    fn a_key_that_is_not_32_bytes_is_refused_at_construction() {
        // CrackTunes 0.1 used two hex UUIDs: valid base64, but 48 bytes.
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert!(matches!(
            Auth::new(config(hex), MemoryStorage::new()),
            Err(ConfigError::InvalidEncryptionKey(_))
        ));
        assert!(matches!(
            Auth::new(config("not base64!"), MemoryStorage::new()),
            Err(ConfigError::InvalidEncryptionKey(_))
        ));
        assert!(Auth::new(config(&encryption::generate_key()), MemoryStorage::new()).is_ok());
    }

    #[test]
    fn has_auth_reaches_through_nested_arcs() {
        fn client_id<S: HasAuth>(s: &S) -> &str {
            &s.auth().config().discord.client_id
        }
        let auth = Auth::new(config(&encryption::generate_key()), MemoryStorage::new()).unwrap();
        let wrapped = Arc::new(Arc::new(auth));
        assert_eq!(client_id(&wrapped), "id");
    }
}
