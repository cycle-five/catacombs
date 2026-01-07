//! Storage abstraction for Discord OAuth user and entitlement data.
//!
//! This module provides a trait-based storage abstraction with two implementations:
//! - `SqlxStorage`: PostgreSQL storage via SQLx (feature: `sqlx-storage`)
//! - `MemoryStorage`: In-memory storage for testing (feature: `memory-storage`)

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::{
    error::{Result, StorageError},
    models::{
        EntitlementUpsertParams, SubscriptionSource, SubscriptionTier, User, UserUpsertParams,
    },
};

#[cfg(feature = "sqlx-storage")]
mod sqlx_impl;
#[cfg(feature = "sqlx-storage")]
pub use sqlx_impl::SqlxStorage;

#[cfg(feature = "memory-storage")]
mod memory;
#[cfg(feature = "memory-storage")]
pub use memory::MemoryStorage;

/// Storage trait for user operations.
#[async_trait]
pub trait UserStorage: Send + Sync {
    /// Get a user by their Discord user ID.
    ///
    /// Parameters:
    ///     - user_id: `i64` - Discord user ID
    ///     - encryption_key: `&str` - Encryption key used to decrypt the refresh token
    /// Returns:
    ///     - `Result<Option<User>>` - Retrieved user or None if not found
    /// Errors:
    ///     - `StorageError` - If an error occurs during retrieval
    async fn get_user(&self, user_id: i64, encryption_key: &str) -> Result<Option<User>>;

    /// Create or update a user.
    ///
    /// Parameters:
    ///     - params: `UserUpsertParams` - Upsert parameters
    ///     - encryption_key: `&str` - Encryption key used to encrypt the refresh token
    /// Returns:
    ///     - `Result<()>` - Success or error
    /// Errors:
    ///     - `StorageError` - If an error occurs during upsert
    async fn upsert_user(&self, params: UserUpsertParams<'_>, encryption_key: &str) -> Result<()>;

    /// Update a user's refresh token.
    ///
    /// Parameters:
    ///    - user_id: `i64` - Discord user ID
    ///    - refresh_token: &str - New refresh token
    ///    - token_expires_at: `DateTime<Utc>` - New token expiration time
    ///    - encryption_key: &str - Encryption key used to encrypt the refresh token
    /// Returns:
    ///    - `Result<()>` - Success or error
    /// Errors:
    ///    - `StorageError` - If an error occurs during update
    async fn update_refresh_token(
        &self,
        user_id: i64,
        refresh_token: &str,
        token_expires_at: DateTime<Utc>,
        encryption_key: &str,
    ) -> Result<()>;

    /// Clear a user's OAuth tokens (logout).
    /// Parameters:
    ///   - user_id: `i64` - Discord user ID
    /// Returns:
    ///   - `Result<()>` - Success or error
    /// Errors:
    ///   - `StorageError` - If an error occurs during clear
    async fn clear_user_tokens(&self, user_id: i64) -> Result<()>;

    /// Update a user's subscription status.
    ///
    /// Parameters:
    ///    - user_id: `i64` - Discord user ID
    ///    - tier: `SubscriptionTier` - New subscription tier
    ///    - source: `SubscriptionSource` - Source of the subscription
    ///    - expires_at: `Option<DateTime<Utc>>` - Subscription expiration time
    /// Returns:
    ///   - `Result<()>` - Success or error
    /// Errors:
    ///   - `StorageError` - If an error occurs during update
    async fn update_subscription(
        &self,
        user_id: i64,
        tier: SubscriptionTier,
        source: SubscriptionSource,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()>;
}

/// Storage trait for entitlement operations.
#[async_trait]
pub trait EntitlementStorage: Send + Sync {
    /// Create or update an entitlement record.
    ///
    /// Parameters:
    ///     - params: EntitlementUpsertParams - Upsert parameters
    /// Returns:
    ///    - Result<()> - Success or error
    /// Errors:
    ///    - StorageError - If an error occurs during upsert
    async fn upsert_entitlement(&self, params: EntitlementUpsertParams) -> Result<()>;
}

/// Combined storage trait for convenience.
///
/// This trait is object-safe and can be used with `Box<dyn Storage>` for
/// dynamic dispatch, or with concrete types for static dispatch.
pub trait Storage: UserStorage + EntitlementStorage + Send + Sync {}

impl<T: UserStorage + EntitlementStorage + Send + Sync> Storage for T {}

/// Helper function to create a storage error from a string.
///
/// Parameters:
///     - msg: `impl Into<String>` - Error message
/// Returns:
///     - `StorageError` - Error
pub fn storage_error(msg: impl Into<String>) -> StorageError {
    StorageError::Other(msg.into())
}
