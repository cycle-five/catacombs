//! What Discord says about a user: their profile, and their profile in
//! particular guilds.

use std::{collections::BTreeMap, fmt};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// A Discord guild (server) ID.
///
/// Snowflakes are unsigned 64-bit. Like user IDs they are kept as `i64`
/// (Postgres `BIGINT`), so an ID above `i64::MAX` wraps to a negative value
/// but stays unique. On the wire it is a decimal string, as Discord sends it,
/// because JavaScript numbers cannot hold every snowflake exactly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuildId(pub i64);

impl GuildId {
    /// Parse a snowflake as Discord writes it.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        s.parse::<u64>().ok().map(|n| Self(n as i64))
    }
}

impl fmt::Display for GuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0 as u64)
    }
}

impl Serialize for GuildId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for GuildId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Number(u64),
            Text(String),
        }
        match Raw::deserialize(deserializer)? {
            Raw::Number(n) => Ok(Self(n as i64)),
            Raw::Text(s) => {
                Self::parse(&s).ok_or_else(|| de::Error::custom(format!("not a snowflake: {s:?}")))
            }
        }
    }
}

/// A user's Discord profile, as read at login.
///
/// Marked `#[non_exhaustive]` so later releases can add Discord fields. Code
/// outside catacombs builds one with [`DiscordProfile::new`] and sets the
/// other fields directly.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct DiscordProfile {
    /// Discord user ID.
    pub id: i64,
    /// Discord username.
    pub username: String,
    /// Display name (`global_name`).
    pub global_name: Option<String>,
    /// CDN URL of the user's avatar. `None` when they use Discord's default.
    pub avatar_url: Option<String>,
    /// CDN URL of the user's profile banner.
    pub banner_url: Option<String>,
    /// Profile accent colour, `0xRRGGBB`.
    pub accent_color: Option<i32>,
    /// Profiles in the guilds this login fetched: usually zero or one.
    /// Storage merges these with the guilds it already holds.
    pub guilds: BTreeMap<GuildId, GuildProfile>,
}

impl DiscordProfile {
    /// A profile with only the required fields.
    #[must_use]
    pub fn new(id: i64, username: impl Into<String>) -> Self {
        Self {
            id,
            username: username.into(),
            global_name: None,
            avatar_url: None,
            banner_url: None,
            accent_color: None,
            guilds: BTreeMap::new(),
        }
    }

    /// `global_name` if set, otherwise `username`.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.global_name.as_deref().unwrap_or(&self.username)
    }
}

/// A user's profile in one guild.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct GuildProfile {
    /// The user's nickname in this guild.
    pub nickname: Option<String>,
    /// CDN URL of the user's avatar in this guild.
    pub avatar_url: Option<String>,
    /// CDN URL of the user's banner in this guild.
    pub banner_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guild_ids_read_strings_and_numbers_and_write_strings() {
        let from_text: GuildId = serde_json::from_str(r#""1234567890123456789""#).unwrap();
        let from_number: GuildId = serde_json::from_str("1234567890123456789").unwrap();
        assert_eq!(from_text, from_number);
        assert_eq!(
            serde_json::to_string(&from_text).unwrap(),
            r#""1234567890123456789""#
        );
    }

    #[test]
    fn snowflakes_above_i64_max_wrap_but_round_trip() {
        let max = "18446744073709551615";
        let id: GuildId = serde_json::from_str(&format!("\"{max}\"")).unwrap();
        assert!(id.0 < 0);
        assert_eq!(id.to_string(), max);
    }

    #[test]
    fn a_non_numeric_guild_id_is_an_error() {
        assert!(serde_json::from_str::<GuildId>(r#""general""#).is_err());
        assert_eq!(GuildId::parse("general"), None);
    }

    #[test]
    fn display_name_prefers_global_name() {
        let mut profile = DiscordProfile::new(1, "user");
        assert_eq!(profile.display_name(), "user");
        profile.global_name = Some("User".into());
        assert_eq!(profile.display_name(), "User");
    }
}
