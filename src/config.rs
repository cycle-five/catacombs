//! Configuration types for Discord OAuth template.

use serde::Deserialize;

/// Root configuration for the Discord OAuth application.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// Discord `OAuth2` configuration.
    pub discord: DiscordConfig,
    /// Security-related configuration.
    pub security: SecurityConfig,
    /// Server configuration.
    #[serde(default)]
    pub server: ServerConfig,
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
    /// Discord bot token (required for entitlements API).
    pub bot_token: String,
    /// Optional SKU ID for premium subscription entitlements.
    #[serde(default)]
    pub premium_sku_id: Option<i64>,
}

/// Security configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    /// Secret key for JWT token signing.
    pub jwt_secret: String,
    /// Base64-encoded 32-byte key for AES-256-GCM encryption of refresh tokens.
    pub encryption_key: String,
}

/// Server configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Host to bind to.
    #[serde(default = "default_host")]
    pub host: String,
    /// Port to listen on.
    #[serde(default = "default_port")]
    pub port: u16,
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    3000
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
        }
    }
}

impl Config {
    /// Load configuration from environment variables.
    ///
    /// Expected environment variables:
    /// - `DISCORD_CLIENT_ID`
    /// - `DISCORD_CLIENT_SECRET`
    /// - `DISCORD_REDIRECT_URI`
    /// - `DISCORD_BOT_TOKEN`
    /// - `DISCORD_PREMIUM_SKU_ID` (optional)
    /// - `JWT_SECRET`
    /// - `ENCRYPTION_KEY`
    /// - `HOST` (optional, defaults to "0.0.0.0")
    /// - `PORT` (optional, defaults to 3000)
    pub fn from_env() -> Result<Self, ConfigError> {
        let discord = DiscordConfig {
            client_id: std::env::var("DISCORD_CLIENT_ID")
                .map_err(|_| ConfigError::MissingEnv("DISCORD_CLIENT_ID"))?,
            client_secret: std::env::var("DISCORD_CLIENT_SECRET")
                .map_err(|_| ConfigError::MissingEnv("DISCORD_CLIENT_SECRET"))?,
            redirect_uri: std::env::var("DISCORD_REDIRECT_URI")
                .map_err(|_| ConfigError::MissingEnv("DISCORD_REDIRECT_URI"))?,
            bot_token: std::env::var("DISCORD_BOT_TOKEN")
                .map_err(|_| ConfigError::MissingEnv("DISCORD_BOT_TOKEN"))?,
            premium_sku_id: std::env::var("DISCORD_PREMIUM_SKU_ID")
                .ok()
                .and_then(|s| s.parse().ok()),
        };

        let security = SecurityConfig {
            jwt_secret: std::env::var("JWT_SECRET")
                .map_err(|_| ConfigError::MissingEnv("JWT_SECRET"))?,
            encryption_key: std::env::var("ENCRYPTION_KEY")
                .map_err(|_| ConfigError::MissingEnv("ENCRYPTION_KEY"))?,
        };

        let server = ServerConfig {
            host: std::env::var("HOST").unwrap_or_else(|_| default_host()),
            port: std::env::var("PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_port),
        };

        Ok(Self {
            discord,
            security,
            server,
        })
    }
}

/// Configuration loading errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable: {0}")]
    MissingEnv(&'static str),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_defaults() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 3000);
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
