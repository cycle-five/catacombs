//! User model for Discord OAuth authenticated users.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::subscription::{SubscriptionSource, SubscriptionTier};

/// A user authenticated via Discord OAuth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Discord user ID (snowflake stored as i64).
    pub user_id: i64,
    /// Discord username.
    pub username: String,
    /// Discord display name (global_name).
    pub global_name: Option<String>,
    /// URL to the user's Discord avatar.
    pub avatar_url: Option<String>,
    /// Decrypted Discord OAuth refresh token.
    #[serde(skip_serializing)]
    pub refresh_token: Option<String>,
    /// When the Discord OAuth token expires.
    pub token_expires_at: Option<DateTime<Utc>>,
    /// User's subscription tier.
    pub subscription_tier: SubscriptionTier,
    /// Source of the user's subscription.
    pub subscription_source: Option<SubscriptionSource>,
    /// When the subscription expires (None = lifetime).
    pub subscription_expires_at: Option<DateTime<Utc>>,
    /// When the user record was created.
    pub created_at: DateTime<Utc>,
    /// When the user record was last updated.
    pub updated_at: DateTime<Utc>,
}

impl User {
    /// Returns true if the user has an active premium subscription.
    pub fn is_premium(&self) -> bool {
        if !self.subscription_tier.is_premium() {
            return false;
        }

        // Check if subscription has expired
        match self.subscription_expires_at {
            Some(expires) => expires > Utc::now(),
            None => true, // No expiration = lifetime
        }
    }

    /// Returns the display name for the user, preferring global_name over username.
    pub fn display_name(&self) -> &str {
        self.global_name.as_deref().unwrap_or(&self.username)
    }
}

/// Parameters for creating or updating a user.
#[derive(Debug, Clone)]
pub struct UserUpsertParams<'a> {
    pub user_id: i64,
    pub username: &'a str,
    pub global_name: Option<&'a str>,
    pub avatar_url: Option<&'a str>,
    pub refresh_token: Option<&'a str>,
    pub token_expires_at: Option<DateTime<Utc>>,
}

/// Parameters for upserting an entitlement.
#[derive(Debug, Clone)]
pub struct EntitlementUpsertParams {
    pub entitlement_id: i64,
    pub user_id: i64,
    pub sku_id: i64,
    pub entitlement_type: i32,
    pub is_test: bool,
    pub consumed: bool,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn make_test_user() -> User {
        User {
            user_id: 123456789,
            username: "testuser".to_string(),
            global_name: Some("Test User".to_string()),
            avatar_url: Some("https://cdn.discordapp.com/avatars/123/abc.png".to_string()),
            refresh_token: None,
            token_expires_at: None,
            subscription_tier: SubscriptionTier::Free,
            subscription_source: None,
            subscription_expires_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn test_user_is_premium_free_tier() {
        let user = make_test_user();
        assert!(!user.is_premium());
    }

    #[test]
    fn test_user_is_premium_active() {
        let mut user = make_test_user();
        user.subscription_tier = SubscriptionTier::Premium;
        user.subscription_expires_at = Some(Utc::now() + Duration::days(30));
        assert!(user.is_premium());
    }

    #[test]
    fn test_user_is_premium_expired() {
        let mut user = make_test_user();
        user.subscription_tier = SubscriptionTier::Premium;
        user.subscription_expires_at = Some(Utc::now() - Duration::days(1));
        assert!(!user.is_premium());
    }

    #[test]
    fn test_user_is_premium_lifetime() {
        let mut user = make_test_user();
        user.subscription_tier = SubscriptionTier::Premium;
        user.subscription_expires_at = None;
        assert!(user.is_premium());
    }

    #[test]
    fn test_display_name_prefers_global_name() {
        let user = make_test_user();
        assert_eq!(user.display_name(), "Test User");
    }

    #[test]
    fn test_display_name_falls_back_to_username() {
        let mut user = make_test_user();
        user.global_name = None;
        assert_eq!(user.display_name(), "testuser");
    }

    #[test]
    fn test_user_serialization_excludes_refresh_token() {
        let mut user = make_test_user();
        user.refresh_token = Some("secret_token".to_string());

        let json = serde_json::to_string(&user).unwrap();
        assert!(!json.contains("secret_token"));
        assert!(!json.contains("refresh_token"));
    }
}
