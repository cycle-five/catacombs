//! Configuration types for Discord OAuth template.

use serde::Deserialize;

/// Root configuration for the Discord OAuth application.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Discord `OAuth2` configuration.
    pub discord: DiscordConfig,
    /// Security-related configuration.
    pub security: SecurityConfig,
    /// The website flow: `/login`, `/callback` and the session cookie.
    #[serde(default)]
    pub web: WebConfig,
}

/// Discord `OAuth2` and API configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct DiscordConfig {
    /// Discord application client ID.
    pub client_id: String,
    /// Discord application client secret.
    pub client_secret: String,
    /// `OAuth2` redirect URI.
    pub redirect_uri: String,
    /// Premium through Discord entitlements. `None` turns entitlement checks off.
    #[serde(default)]
    pub premium: Option<PremiumConfig>,
    /// Base URL of Discord's REST API. Overridable so tests can point the
    /// token and user calls at a local mock.
    #[serde(default = "default_api_base")]
    pub api_base: String,
}

/// Which SKU makes a user premium, and the bot token that may read the
/// application's entitlements.
#[derive(Debug, Clone, Deserialize)]
pub struct PremiumConfig {
    /// The SKU whose active entitlement grants premium.
    pub sku_id: i64,
    /// Bot token for the entitlements API.
    pub bot_token: String,
}

/// Security configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Secret key for JWT token signing.
    pub jwt_secret: String,
    /// Base64-encoded 32-byte key for AES-256-GCM encryption of refresh tokens.
    pub encryption_key: String,
}

/// Settings for the browser redirect flow and its session cookie.
#[derive(Debug, Clone, Deserialize)]
pub struct WebConfig {
    /// OAuth scopes requested at `/login`.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Name of the cookie holding the session JWT.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    /// Mark cookies `Secure`. Browsers accept `Secure` cookies on
    /// `http://localhost`, so this stays on even for local development.
    #[serde(default = "default_true")]
    pub secure_cookies: bool,
}

fn default_scopes() -> Vec<String> {
    vec!["identify".to_string()]
}

fn default_cookie_name() -> String {
    "catacombs_session".to_string()
}

fn default_true() -> bool {
    true
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            scopes: default_scopes(),
            cookie_name: default_cookie_name(),
            secure_cookies: true,
        }
    }
}

/// Discord's REST API, version 10.
pub fn default_api_base() -> String {
    "https://discord.com/api/v10".to_string()
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// - `DISCORD_CLIENT_ID`, `DISCORD_CLIENT_SECRET`, `DISCORD_REDIRECT_URI`
    /// - `DISCORD_PREMIUM_SKU_ID` (optional). When set, `DISCORD_BOT_TOKEN`
    ///   is required too.
    /// - `DISCORD_API_BASE` (optional, defaults to Discord's v10 API)
    /// - `JWT_SECRET`
    /// - `ENCRYPTION_KEY` (base64 of 32 bytes: `openssl rand -base64 32`)
    ///
    /// # Errors
    /// [`ConfigError::MissingEnv`] for a missing variable,
    /// [`ConfigError::InvalidEnv`] for a malformed one.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let need = |name: &'static str| get(name).ok_or(ConfigError::MissingEnv(name));
        let premium = match get("DISCORD_PREMIUM_SKU_ID") {
            Some(raw) => Some(PremiumConfig {
                sku_id: raw
                    .parse()
                    .map_err(|_| ConfigError::InvalidEnv("DISCORD_PREMIUM_SKU_ID"))?,
                bot_token: need("DISCORD_BOT_TOKEN")?,
            }),
            None => None,
        };
        Ok(Self {
            discord: DiscordConfig {
                client_id: need("DISCORD_CLIENT_ID")?,
                client_secret: need("DISCORD_CLIENT_SECRET")?,
                redirect_uri: need("DISCORD_REDIRECT_URI")?,
                premium,
                api_base: get("DISCORD_API_BASE").unwrap_or_else(default_api_base),
            },
            security: SecurityConfig {
                jwt_secret: need("JWT_SECRET")?,
                encryption_key: need("ENCRYPTION_KEY")?,
            },
            web: WebConfig::default(),
        })
    }
}

/// Configuration loading errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingEnv(&'static str),
    #[error("invalid value for environment variable: {0}")]
    InvalidEnv(&'static str),
    #[error("invalid ENCRYPTION_KEY: {0}")]
    InvalidEncryptionKey(String),
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const BASE: &[(&str, &str)] = &[
        ("DISCORD_CLIENT_ID", "id"),
        ("DISCORD_CLIENT_SECRET", "secret"),
        ("DISCORD_REDIRECT_URI", "https://example.test/auth/callback"),
        ("JWT_SECRET", "jwt"),
        ("ENCRYPTION_KEY", "key"),
    ];

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn without_a_premium_sku_no_bot_token_is_needed() {
        let config = Config::from_lookup(lookup(BASE)).unwrap();
        assert!(config.discord.premium.is_none());
        assert_eq!(config.discord.api_base, default_api_base());
    }

    #[test]
    fn a_premium_sku_requires_a_bot_token() {
        let mut vars = BASE.to_vec();
        vars.push(("DISCORD_PREMIUM_SKU_ID", "42"));
        let err = Config::from_lookup(lookup(&vars)).unwrap_err();
        assert!(matches!(err, ConfigError::MissingEnv("DISCORD_BOT_TOKEN")));

        vars.push(("DISCORD_BOT_TOKEN", "bot"));
        let premium = Config::from_lookup(lookup(&vars))
            .unwrap()
            .discord
            .premium
            .unwrap();
        assert_eq!(premium.sku_id, 42);
        assert_eq!(premium.bot_token, "bot");
    }

    #[test]
    fn a_malformed_sku_is_an_error_not_silence() {
        let mut vars = BASE.to_vec();
        vars.push(("DISCORD_PREMIUM_SKU_ID", "not-a-number"));
        vars.push(("DISCORD_BOT_TOKEN", "bot"));
        let err = Config::from_lookup(lookup(&vars)).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::InvalidEnv("DISCORD_PREMIUM_SKU_ID")
        ));
    }

    #[test]
    fn test_config_error_display() {
        let err = ConfigError::MissingEnv("TEST_VAR");
        assert_eq!(
            err.to_string(),
            "missing required environment variable: TEST_VAR"
        );
    }
}
