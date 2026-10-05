//! The storage seam: what catacombs asks of wherever users live.
//!
//! catacombs ships [`SqlxStorage`] (feature `sqlx-storage`) and
//! [`MemoryStorage`] (feature `memory-storage`). A host with its own users
//! table implements [`Storage`] over that table instead.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    error::StorageError,
    models::{DiscordProfile, Entitlement, StoredTokens, Subscription, User},
};

#[cfg(feature = "sqlx-storage")]
mod sqlx_impl;
#[cfg(feature = "sqlx-storage")]
pub use sqlx_impl::SqlxStorage;

#[cfg(feature = "memory-storage")]
mod memory;
#[cfg(feature = "memory-storage")]
pub use memory::MemoryStorage;

/// Where catacombs keeps users, their tokens and their entitlements.
///
/// Refresh tokens arrive and leave as [`StoredTokens`], which hold only
/// ciphertext. An implementation persists `refresh_token.as_str()` and
/// rebuilds it with
/// [`EncryptedToken::from_stored`](crate::EncryptedToken::from_stored).
#[async_trait]
pub trait Storage: Send + Sync + 'static {
    /// The user, or `None` if catacombs has never stored them.
    async fn get_user(&self, user_id: i64) -> Result<Option<User>, StorageError>;

    /// Create or update a user from a fresh Discord profile.
    ///
    /// - Guilds in `profile.guilds` are inserted or replaced. Guilds stored
    ///   earlier and absent from the map are kept.
    /// - `tokens: None` leaves any stored tokens as they are.
    async fn upsert_user(
        &self,
        profile: &DiscordProfile,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError>;

    /// Replace the user's tokens. `None` clears them (logout, revoke).
    async fn set_tokens(
        &self,
        user_id: i64,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError>;

    /// Record a subscription. `None` resets the user to the free tier.
    async fn set_subscription(
        &self,
        user_id: i64,
        subscription: Option<&Subscription>,
    ) -> Result<(), StorageError>;

    /// Create or update an entitlement, keyed by `entitlement_id`.
    async fn upsert_entitlement(&self, entitlement: &Entitlement) -> Result<(), StorageError>;
}

/// So a host (or a test) can keep a handle on the storage it gives [`Auth`](crate::Auth).
#[async_trait]
impl<T: Storage + ?Sized> Storage for Arc<T> {
    async fn get_user(&self, user_id: i64) -> Result<Option<User>, StorageError> {
        (**self).get_user(user_id).await
    }

    async fn upsert_user(
        &self,
        profile: &DiscordProfile,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError> {
        (**self).upsert_user(profile, tokens).await
    }

    async fn set_tokens(
        &self,
        user_id: i64,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError> {
        (**self).set_tokens(user_id, tokens).await
    }

    async fn set_subscription(
        &self,
        user_id: i64,
        subscription: Option<&Subscription>,
    ) -> Result<(), StorageError> {
        (**self).set_subscription(user_id, subscription).await
    }

    async fn upsert_entitlement(&self, entitlement: &Entitlement) -> Result<(), StorageError> {
        (**self).upsert_entitlement(entitlement).await
    }
}
