//! Discord OAuth Template
//!
//! A library for implementing Discord Activity `OAuth2` authentication
//! with user management and subscription support.
//!
//! # Features
//!
//! - `sqlx-storage` (default): `PostgreSQL` storage via `SQLx`
//! - `memory-storage`: In-memory storage for testing
//!
//! # Example
//!
//! ```rust,ignore
//! use catacombs::{Auth, Config, SqlxStorage, routes};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Config::from_env()?;
//!     let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
//!     let storage = SqlxStorage::new(pool);
//!     storage.migrate().await?;
//!
//!     let state = Arc::new(Auth::new(config, storage));
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

mod state;

// Re-exports for convenience
pub use config::{Config, ConfigError, DiscordConfig, PremiumConfig, SecurityConfig, WebConfig};
pub use error::{Error, Result, StorageError};
pub use models::{
    DiscordProfile, GuildId, GuildProfile, Subscription, SubscriptionSource, SubscriptionTier, User,
};
pub use state::{Auth, HasAuth};
#[cfg(feature = "memory-storage")]
pub use storage::MemoryStorage;
#[cfg(feature = "sqlx-storage")]
pub use storage::SqlxStorage;
pub use storage::{EntitlementStorage, Storage, UserStorage};
