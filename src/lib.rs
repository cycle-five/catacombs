//! Discord OAuth Template
//!
//! A library for implementing Discord Activity OAuth2 authentication
//! with user management and subscription support.
//!
//! # Features
//!
//! - `sqlx-storage` (default): PostgreSQL storage via SQLx
//! - `memory-storage`: In-memory storage for testing
//!
//! # Example
//!
//! ```rust,ignore
//! use discord_oauth_template::{AppState, Config, SqlxStorage, routes};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     dotenvy::dotenv().ok();
//!     let config = Config::from_env()?;
//!     let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
//!     let storage = SqlxStorage::new(pool);
//!     storage.migrate().await?;
//!
//!     let state = Arc::new(AppState::new(config, storage));
//!
//!     let app = axum::Router::new()
//!         .nest("/auth", routes::auth_router())
//!         .with_state(state);
//!
//!     let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
//!     axum::serve(listener, app).await?;
//!     Ok(())
//! }
//! ```

pub mod auth;
pub mod config;
pub mod encryption;
pub mod error;
pub mod models;
pub mod routes;
pub mod storage;

// Re-exports for convenience
use std::sync::Arc;

pub use config::{Config, ConfigError, DiscordConfig, SecurityConfig, ServerConfig};
pub use error::{Error, Result, StorageError};
pub use models::{SubscriptionSource, SubscriptionTier, User};
#[cfg(feature = "memory-storage")]
pub use storage::MemoryStorage;
#[cfg(feature = "sqlx-storage")]
pub use storage::SqlxStorage;
pub use storage::{EntitlementStorage, Storage, UserStorage};

/// Application state containing configuration and storage.
///
/// This is designed to be wrapped in `Arc` and used with Axum's state extractor.
pub struct AppState {
    /// Application configuration.
    pub config: Config,
    /// Storage backend for users and entitlements.
    pub storage: Box<dyn Storage>,
    /// HTTP client for Discord API requests.
    pub http_client: reqwest::Client,
}

impl AppState {
    /// Create a new AppState with the given configuration and storage.
    pub fn new(config: Config, storage: impl Storage + 'static) -> Self {
        Self {
            config,
            storage: Box::new(storage),
            http_client: reqwest::Client::new(),
        }
    }

    /// Create a new AppState with a custom HTTP client.
    pub fn with_http_client(
        config: Config,
        storage: impl Storage + 'static,
        http_client: reqwest::Client,
    ) -> Self {
        Self {
            config,
            storage: Box::new(storage),
            http_client,
        }
    }
}

/// Type alias for Arc-wrapped AppState, commonly used with Axum.
pub type SharedState = Arc<AppState>;
