//! In-memory storage implementation for testing.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::RwLock;

use crate::{
    error::Result,
    models::{
        EntitlementUpsertParams, SubscriptionSource, SubscriptionTier, User, UserUpsertParams,
    },
    storage::{EntitlementStorage, UserStorage},
};

/// In-memory storage backend for testing and development.
///
/// Note: This implementation stores refresh tokens in plaintext (no encryption)
/// since it's intended for testing only.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    users: RwLock<HashMap<i64, User>>,
    entitlements: RwLock<HashMap<i64, StoredEntitlement>>,
}

#[derive(Debug, Clone)]
struct StoredEntitlement {
    entitlement_id: i64,
    user_id: i64,
    sku_id: i64,
    entitlement_type: i32,
    is_test: bool,
    consumed: bool,
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
}

impl MemoryStorage {
    /// Create a new empty in-memory storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all stored data (useful for test cleanup).
    pub fn clear(&self) {
        self.users.write().clear();
        self.entitlements.write().clear();
    }

    /// Get the number of stored users.
    pub fn user_count(&self) -> usize {
        self.users.read().len()
    }

    /// Get the number of stored entitlements.
    pub fn entitlement_count(&self) -> usize {
        self.entitlements.read().len()
    }
}

#[async_trait]
impl UserStorage for MemoryStorage {
    async fn get_user(&self, user_id: i64, _encryption_key: &str) -> Result<Option<User>> {
        Ok(self.users.read().get(&user_id).cloned())
    }

    async fn upsert_user(&self, params: UserUpsertParams<'_>, _encryption_key: &str) -> Result<()> {
        let mut users = self.users.write();
        let now = Utc::now();

        if let Some(existing) = users.get_mut(&params.user_id) {
            existing.username = params.username.to_string();
            existing.global_name = params.global_name.map(String::from);
            existing.avatar_url = params.avatar_url.map(String::from);
            if params.refresh_token.is_some() {
                existing.refresh_token = params.refresh_token.map(String::from);
            }
            if params.token_expires_at.is_some() {
                existing.token_expires_at = params.token_expires_at;
            }
            existing.updated_at = now;
        } else {
            users.insert(
                params.user_id,
                User {
                    user_id: params.user_id,
                    username: params.username.to_string(),
                    global_name: params.global_name.map(String::from),
                    avatar_url: params.avatar_url.map(String::from),
                    refresh_token: params.refresh_token.map(String::from),
                    token_expires_at: params.token_expires_at,
                    subscription_tier: SubscriptionTier::Free,
                    subscription_source: None,
                    subscription_expires_at: None,
                    created_at: now,
                    updated_at: now,
                },
            );
        }

        Ok(())
    }

    async fn update_refresh_token(
        &self,
        user_id: i64,
        refresh_token: &str,
        token_expires_at: DateTime<Utc>,
        _encryption_key: &str,
    ) -> Result<()> {
        let mut users = self.users.write();
        if let Some(user) = users.get_mut(&user_id) {
            user.refresh_token = Some(refresh_token.to_string());
            user.token_expires_at = Some(token_expires_at);
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn clear_user_tokens(&self, user_id: i64) -> Result<()> {
        let mut users = self.users.write();
        if let Some(user) = users.get_mut(&user_id) {
            user.refresh_token = None;
            user.token_expires_at = None;
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn update_subscription(
        &self,
        user_id: i64,
        tier: SubscriptionTier,
        source: SubscriptionSource,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let mut users = self.users.write();
        if let Some(user) = users.get_mut(&user_id) {
            user.subscription_tier = tier;
            user.subscription_source = Some(source);
            user.subscription_expires_at = expires_at;
            user.updated_at = Utc::now();
        }
        Ok(())
    }
}

#[async_trait]
impl EntitlementStorage for MemoryStorage {
    async fn upsert_entitlement(&self, params: EntitlementUpsertParams) -> Result<()> {
        let mut entitlements = self.entitlements.write();
        entitlements.insert(
            params.entitlement_id,
            StoredEntitlement {
                entitlement_id: params.entitlement_id,
                user_id: params.user_id,
                sku_id: params.sku_id,
                entitlement_type: params.entitlement_type,
                is_test: params.is_test,
                consumed: params.consumed,
                starts_at: params.starts_at,
                ends_at: params.ends_at,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[tokio::test]
    async fn test_memory_storage_user_lifecycle() {
        let storage = MemoryStorage::new();
        let key = "unused";

        // Initially no user
        assert!(storage.get_user(123, key).await.unwrap().is_none());

        // Create user
        storage
            .upsert_user(
                UserUpsertParams {
                    user_id: 123,
                    username: "testuser",
                    global_name: Some("Test User"),
                    avatar_url: None,
                    refresh_token: Some("token123"),
                    token_expires_at: Some(Utc::now() + Duration::hours(1)),
                },
                key,
            )
            .await
            .unwrap();

        // User exists
        let user = storage.get_user(123, key).await.unwrap().unwrap();
        assert_eq!(user.username, "testuser");
        assert_eq!(user.refresh_token, Some("token123".to_string()));

        // Update user
        storage
            .upsert_user(
                UserUpsertParams {
                    user_id: 123,
                    username: "newname",
                    global_name: None,
                    avatar_url: None,
                    refresh_token: None,
                    token_expires_at: None,
                },
                key,
            )
            .await
            .unwrap();

        let user = storage.get_user(123, key).await.unwrap().unwrap();
        assert_eq!(user.username, "newname");
        // Token preserved when not provided
        assert_eq!(user.refresh_token, Some("token123".to_string()));

        // Clear tokens
        storage.clear_user_tokens(123).await.unwrap();
        let user = storage.get_user(123, key).await.unwrap().unwrap();
        assert!(user.refresh_token.is_none());
    }

    #[tokio::test]
    async fn test_memory_storage_subscription() {
        let storage = MemoryStorage::new();
        let key = "unused";

        storage
            .upsert_user(
                UserUpsertParams {
                    user_id: 456,
                    username: "subuser",
                    global_name: None,
                    avatar_url: None,
                    refresh_token: None,
                    token_expires_at: None,
                },
                key,
            )
            .await
            .unwrap();

        // Initially free
        let user = storage.get_user(456, key).await.unwrap().unwrap();
        assert_eq!(user.subscription_tier, SubscriptionTier::Free);

        // Upgrade
        storage
            .update_subscription(
                456,
                SubscriptionTier::Premium,
                SubscriptionSource::Discord,
                Some(Utc::now() + Duration::days(30)),
            )
            .await
            .unwrap();

        let user = storage.get_user(456, key).await.unwrap().unwrap();
        assert_eq!(user.subscription_tier, SubscriptionTier::Premium);
        assert!(user.is_premium());
    }

    #[tokio::test]
    async fn test_memory_storage_entitlements() {
        let storage = MemoryStorage::new();

        assert_eq!(storage.entitlement_count(), 0);

        storage
            .upsert_entitlement(EntitlementUpsertParams {
                entitlement_id: 1,
                user_id: 123,
                sku_id: 456,
                entitlement_type: 8,
                is_test: false,
                consumed: false,
                starts_at: None,
                ends_at: None,
            })
            .await
            .unwrap();

        assert_eq!(storage.entitlement_count(), 1);
    }

    #[tokio::test]
    async fn test_memory_storage_clear() {
        let storage = MemoryStorage::new();
        let key = "unused";

        storage
            .upsert_user(
                UserUpsertParams {
                    user_id: 1,
                    username: "user1",
                    global_name: None,
                    avatar_url: None,
                    refresh_token: None,
                    token_expires_at: None,
                },
                key,
            )
            .await
            .unwrap();

        assert_eq!(storage.user_count(), 1);

        storage.clear();

        assert_eq!(storage.user_count(), 0);
    }
}
