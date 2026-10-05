//! catacombs: "Log in with Discord" for axum services.
//!
//! catacombs runs the `OAuth2` exchange with Discord, keeps users and their
//! (encrypted) refresh tokens in a [`Storage`], and gives handlers an
//! [`AuthenticatedUser`](auth::AuthenticatedUser). It owns the login
//! lifecycle; the host owns what a user looks like.
//!
//! # Features
//!
//! - `sqlx-storage` (default): [`SqlxStorage`], `PostgreSQL` 14+ through `SQLx`
//! - `memory-storage`: [`MemoryStorage`], in-process
//! - `rustls-tls` (default) or `native-tls`
//!
//! # Example
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use catacombs::{router, Auth, Config, Flows, HasAuth, SqlxStorage};
//!
//! struct AppState { auth: Auth /* , your own fields */ }
//! impl HasAuth for AppState {
//!     fn auth(&self) -> &Auth { &self.auth }
//! }
//!
//! let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
//! let storage = SqlxStorage::new(pool);
//! storage.migrate().await?;
//! let auth = Auth::new(Config::from_env()?, storage)?;
//!
//! let app = axum::Router::new()
//!     .nest("/auth", router(Flows::Activity))
//!     .with_state(Arc::new(AppState { auth }));
//! ```

pub mod auth;
pub mod config;
mod discord;
pub mod encryption;
pub mod error;
pub mod models;
pub mod routes;
pub mod storage;

mod login;
mod observer;
mod state;

// Re-exports for convenience
pub use config::{Config, ConfigError, DiscordConfig, PremiumConfig, SecurityConfig, WebConfig};
pub use error::{Error, LoginError, Rejection, Result, StorageError};
pub use models::{
    DiscordProfile, EncryptedToken, Entitlement, GuildId, GuildProfile, StoredTokens, Subscription,
    SubscriptionSource, SubscriptionTier, User,
};
pub use observer::{AuthEvent, AuthObserver, Flow, LoginWarning};
pub use routes::{router, Flows};
pub use state::{Auth, HasAuth};
#[cfg(feature = "memory-storage")]
pub use storage::MemoryStorage;
#[cfg(feature = "sqlx-storage")]
pub use storage::SqlxStorage;
pub use storage::Storage;
