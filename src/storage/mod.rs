//! Storage abstraction for Discord OAuth user and entitlement data.
//!
//! This module provides a trait-based storage abstraction with two implementations:
//! - `SqlxStorage`: PostgreSQL storage via SQLx (feature: `sqlx-storage`)
//! - `MemoryStorage`: In-memory storage for testing (feature: `memory-storage`)

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use crate::error::{Result, StorageError};
use crate::models::{EntitlementUpsertParams, SubscriptionSource, SubscriptionTier, User, UserUpsertParams};

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
    /// The `encryption_key` is used to decrypt the stored refresh token.
    async fn get_user(&self, user_id: i64, encryption_key: &str) -> Result<Option<User>>;

    /// Create or update a user.
    ///
    /// The `encryption_key` is used to encrypt the refresh token before storage.
    async fn upsert_user(&self, params: UserUpsertParams<'_>, encryption_key: &str) -> Result<()>;

    /// Update a user's refresh token.
    ///
    /// The `encryption_key` is used to encrypt the refresh token before storage.
    async fn update_refresh_token(
        &self,
        user_id: i64,
        refresh_token: &str,
        token_expires_at: DateTime<Utc>,
        encryption_key: &str,
    ) -> Result<()>;

    /// Clear a user's OAuth tokens (logout).
    async fn clear_user_tokens(&self, user_id: i64) -> Result<()>;

    /// Update a user's subscription status.
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
    async fn upsert_entitlement(&self, params: EntitlementUpsertParams) -> Result<()>;
}

/// Combined storage trait for convenience.
///
/// This trait is object-safe and can be used with `Box<dyn Storage>` for
/// dynamic dispatch, or with concrete types for static dispatch.
pub trait Storage: UserStorage + EntitlementStorage + Send + Sync {}

impl<T: UserStorage + EntitlementStorage + Send + Sync> Storage for T {}

/// Helper function to create a storage error from a string.
pub fn storage_error(msg: impl Into<String>) -> StorageError {
    StorageError::Other(msg.into())
}
