//! In-memory storage, for tests and for services that may forget everyone
//! on a restart.

use std::collections::HashMap;

use async_trait::async_trait;
use chrono::Utc;
use parking_lot::RwLock;

use crate::{
    error::StorageError,
    models::{DiscordProfile, Entitlement, StoredTokens, Subscription, SubscriptionTier, User},
    storage::Storage,
};

/// In-memory storage.
///
/// Refresh tokens are held as ciphertext, as in any storage. Since nothing
/// outlives the process, the encryption key can be a fresh one per process
/// ([`generate_key`](crate::encryption::generate_key)).
#[derive(Debug, Default)]
pub struct MemoryStorage {
    users: RwLock<HashMap<i64, Record>>,
    entitlements: RwLock<HashMap<i64, Entitlement>>,
}

#[derive(Debug, Clone)]
struct Record {
    user: User,
    /// The latest profile, with guilds merged across logins.
    profile: DiscordProfile,
}

impl MemoryStorage {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget everything.
    pub fn clear(&self) {
        self.users.write().clear();
        self.entitlements.write().clear();
    }

    /// The number of stored users.
    pub fn user_count(&self) -> usize {
        self.users.read().len()
    }

    /// The number of stored entitlements.
    pub fn entitlement_count(&self) -> usize {
        self.entitlements.read().len()
    }

    /// The latest profile stored for a user, with guilds merged across logins.
    pub fn profile(&self, user_id: i64) -> Option<DiscordProfile> {
        self.users.read().get(&user_id).map(|r| r.profile.clone())
    }

    /// The entitlement stored under `entitlement_id`.
    pub fn entitlement(&self, entitlement_id: i64) -> Option<Entitlement> {
        self.entitlements.read().get(&entitlement_id).cloned()
    }
}

#[async_trait]
impl Storage for MemoryStorage {
    async fn get_user(&self, user_id: i64) -> Result<Option<User>, StorageError> {
        Ok(self.users.read().get(&user_id).map(|r| r.user.clone()))
    }

    async fn upsert_user(
        &self,
        profile: &DiscordProfile,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError> {
        let now = Utc::now();
        let mut users = self.users.write();
        if let Some(record) = users.get_mut(&profile.id) {
            let mut guilds = std::mem::take(&mut record.profile.guilds);
            guilds.extend(profile.guilds.iter().map(|(id, g)| (*id, g.clone())));
            record.profile = DiscordProfile {
                guilds,
                ..profile.clone()
            };
            let user = &mut record.user;
            user.username.clone_from(&profile.username);
            user.global_name.clone_from(&profile.global_name);
            user.avatar_url.clone_from(&profile.avatar_url);
            if let Some(tokens) = tokens {
                user.tokens = Some(tokens.clone());
            }
            user.updated_at = now;
        } else {
            let user = User {
                user_id: profile.id,
                username: profile.username.clone(),
                global_name: profile.global_name.clone(),
                avatar_url: profile.avatar_url.clone(),
                tokens: tokens.cloned(),
                subscription_tier: SubscriptionTier::Free,
                subscription_source: None,
                subscription_expires_at: None,
                created_at: now,
                updated_at: now,
            };
            users.insert(
                profile.id,
                Record {
                    user,
                    profile: profile.clone(),
                },
            );
        }
        Ok(())
    }

    async fn set_tokens(
        &self,
        user_id: i64,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError> {
        if let Some(record) = self.users.write().get_mut(&user_id) {
            record.user.tokens = tokens.cloned();
            record.user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn set_subscription(
        &self,
        user_id: i64,
        subscription: Option<&Subscription>,
    ) -> Result<(), StorageError> {
        if let Some(record) = self.users.write().get_mut(&user_id) {
            let user = &mut record.user;
            match subscription {
                Some(s) => {
                    user.subscription_tier = s.tier;
                    user.subscription_source = Some(s.source);
                    user.subscription_expires_at = s.expires_at;
                }
                None => {
                    user.subscription_tier = SubscriptionTier::Free;
                    user.subscription_source = None;
                    user.subscription_expires_at = None;
                }
            }
            user.updated_at = Utc::now();
        }
        Ok(())
    }

    async fn upsert_entitlement(&self, entitlement: &Entitlement) -> Result<(), StorageError> {
        self.entitlements
            .write()
            .insert(entitlement.entitlement_id, entitlement.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use super::*;
    use crate::{
        encryption,
        models::{EncryptedToken, GuildId, GuildProfile, SubscriptionSource},
    };

    fn tokens(plain: &str) -> StoredTokens {
        StoredTokens {
            refresh_token: EncryptedToken::encrypt(plain, &encryption::generate_key()).unwrap(),
            expires_at: Utc::now(),
        }
    }

    fn guild(nickname: &str) -> GuildProfile {
        GuildProfile {
            nickname: Some(nickname.into()),
            ..GuildProfile::default()
        }
    }

    #[tokio::test]
    async fn guilds_accumulate_across_logins_and_a_repeat_replaces() {
        let storage = MemoryStorage::new();
        let mut first = DiscordProfile::new(1, "u");
        first.guilds.insert(GuildId(10), guild("ten"));
        storage.upsert_user(&first, None).await.unwrap();

        let mut second = DiscordProfile::new(1, "u2");
        second.guilds.insert(GuildId(20), guild("twenty"));
        second.guilds.insert(GuildId(10), guild("TEN"));
        storage.upsert_user(&second, None).await.unwrap();

        let stored = storage.profile(1).unwrap();
        assert_eq!(stored.username, "u2");
        assert_eq!(stored.guilds.len(), 2);
        assert_eq!(stored.guilds[&GuildId(10)].nickname.as_deref(), Some("TEN"));
        assert_eq!(storage.get_user(1).await.unwrap().unwrap().username, "u2");
    }

    #[tokio::test]
    async fn upsert_without_tokens_keeps_them_and_set_tokens_none_clears() {
        let storage = MemoryStorage::new();
        let profile = DiscordProfile::new(1, "u");
        let t = tokens("secret");
        storage.upsert_user(&profile, Some(&t)).await.unwrap();
        storage.upsert_user(&profile, None).await.unwrap();
        assert_eq!(storage.get_user(1).await.unwrap().unwrap().tokens, Some(t));

        storage.set_tokens(1, None).await.unwrap();
        assert_eq!(storage.get_user(1).await.unwrap().unwrap().tokens, None);
    }

    #[tokio::test]
    async fn set_subscription_none_resets_to_free() {
        let storage = MemoryStorage::new();
        storage
            .upsert_user(&DiscordProfile::new(1, "u"), None)
            .await
            .unwrap();
        let premium = Subscription {
            tier: SubscriptionTier::Premium,
            source: SubscriptionSource::Manual,
            expires_at: None,
        };
        storage.set_subscription(1, Some(&premium)).await.unwrap();
        let user = storage.get_user(1).await.unwrap().unwrap();
        assert!(user.is_premium());
        assert_eq!(user.subscription_source, Some(SubscriptionSource::Manual));

        storage.set_subscription(1, None).await.unwrap();
        let user = storage.get_user(1).await.unwrap().unwrap();
        assert_eq!(user.subscription_tier, SubscriptionTier::Free);
        assert_eq!(user.subscription_source, None);
    }
}
