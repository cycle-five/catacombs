//! Subscription-related types for Discord OAuth users.

use serde::{Deserialize, Serialize};

/// Subscription tier for a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionTier {
    /// Free tier (default).
    #[default]
    Free,
    /// Premium tier with additional features.
    Premium,
}

impl SubscriptionTier {
    /// Returns true if this tier grants premium access.
    #[must_use] 
    pub fn is_premium(&self) -> bool {
        matches!(self, Self::Premium)
    }
}

/// Source of a user's subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionSource {
    /// Subscription obtained through Discord's monetization system.
    Discord,
    /// Subscription granted manually (e.g., by an admin).
    Manual,
    /// Subscription from an external payment provider.
    External,
}

#[cfg(feature = "sqlx-storage")]
impl sqlx::Type<sqlx::Postgres> for SubscriptionTier {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

#[cfg(feature = "sqlx-storage")]
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for SubscriptionTier {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        match s.as_str() {
            "free" => Ok(Self::Free),
            "premium" => Ok(Self::Premium),
            _ => Ok(Self::Free),
        }
    }
}

#[cfg(feature = "sqlx-storage")]
impl sqlx::Encode<'_, sqlx::Postgres> for SubscriptionTier {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let s = match self {
            Self::Free => "free",
            Self::Premium => "premium",
        };
        <&str as sqlx::Encode<sqlx::Postgres>>::encode(s, buf)
    }
}

#[cfg(feature = "sqlx-storage")]
impl sqlx::Type<sqlx::Postgres> for SubscriptionSource {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <String as sqlx::Type<sqlx::Postgres>>::type_info()
    }
}

#[cfg(feature = "sqlx-storage")]
impl<'r> sqlx::Decode<'r, sqlx::Postgres> for SubscriptionSource {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        match s.as_str() {
            "discord" => Ok(Self::Discord),
            "manual" => Ok(Self::Manual),
            "external" => Ok(Self::External),
            _ => Ok(Self::Discord),
        }
    }
}

#[cfg(feature = "sqlx-storage")]
impl sqlx::Encode<'_, sqlx::Postgres> for SubscriptionSource {
    fn encode_by_ref(
        &self,
        buf: &mut sqlx::postgres::PgArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let s = match self {
            Self::Discord => "discord",
            Self::Manual => "manual",
            Self::External => "external",
        };
        <&str as sqlx::Encode<sqlx::Postgres>>::encode(s, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subscription_tier_default() {
        let tier: SubscriptionTier = Default::default();
        assert_eq!(tier, SubscriptionTier::Free);
    }

    #[test]
    fn test_subscription_tier_is_premium() {
        assert!(!SubscriptionTier::Free.is_premium());
        assert!(SubscriptionTier::Premium.is_premium());
    }

    #[test]
    fn test_subscription_tier_serde() {
        let tier = SubscriptionTier::Premium;
        let json = serde_json::to_string(&tier).unwrap();
        assert_eq!(json, "\"premium\"");

        let parsed: SubscriptionTier = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SubscriptionTier::Premium);
    }

    #[test]
    fn test_subscription_source_serde() {
        let source = SubscriptionSource::Discord;
        let json = serde_json::to_string(&source).unwrap();
        assert_eq!(json, "\"discord\"");

        let parsed: SubscriptionSource = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, SubscriptionSource::Discord);
    }
}
