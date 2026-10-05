//! `PostgreSQL` storage through `SQLx`, for a service without a users table
//! of its own.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::{
    error::StorageError,
    models::{
        DiscordProfile, EncryptedToken, Entitlement, StoredTokens, Subscription,
        SubscriptionSource, SubscriptionTier, User,
    },
    storage::Storage,
};

/// `PostgreSQL` storage in catacombs' own tables: `catacombs_users`,
/// `catacombs_guild_profiles` and `catacombs_entitlements`. Needs
/// `PostgreSQL` 14 or newer.
#[derive(Debug, Clone)]
pub struct SqlxStorage {
    pool: PgPool,
}

#[derive(sqlx::FromRow)]
struct UserRow {
    user_id: i64,
    username: String,
    global_name: Option<String>,
    avatar_url: Option<String>,
    refresh_token: Option<String>,
    token_expires_at: Option<DateTime<Utc>>,
    subscription_tier: SubscriptionTier,
    subscription_source: Option<SubscriptionSource>,
    subscription_expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<UserRow> for User {
    fn from(row: UserRow) -> Self {
        let tokens = match (row.refresh_token, row.token_expires_at) {
            (Some(ciphertext), Some(expires_at)) => Some(StoredTokens {
                refresh_token: EncryptedToken::from_stored(ciphertext),
                expires_at,
            }),
            _ => None,
        };
        Self {
            user_id: row.user_id,
            username: row.username,
            global_name: row.global_name,
            avatar_url: row.avatar_url,
            tokens,
            subscription_tier: row.subscription_tier,
            subscription_source: row.subscription_source,
            subscription_expires_at: row.subscription_expires_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        }
    }
}

impl SqlxStorage {
    /// Storage on `pool`.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The connection pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Create or update catacombs' tables.
    ///
    /// Safe on a database that also holds the host's own sqlx migrations:
    /// catacombs ignores applied migrations it does not know about. If the
    /// host runs its own migrator on the same database, that migrator must
    /// do the same (`migrator.set_ignore_missing(true)`), or it will refuse
    /// to run because of catacombs' rows in `_sqlx_migrations`.
    ///
    /// # Errors
    /// When a migration fails.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        let mut migrator = sqlx::migrate!("./migrations");
        migrator.set_ignore_missing(true);
        migrator
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.into()))
    }
}

#[async_trait]
impl Storage for SqlxStorage {
    async fn get_user(&self, user_id: i64) -> Result<Option<User>, StorageError> {
        let row = sqlx::query_as::<_, UserRow>(
            r"
            SELECT user_id, username, global_name, avatar_url,
                   refresh_token, token_expires_at,
                   subscription_tier, subscription_source, subscription_expires_at,
                   created_at, updated_at
            FROM catacombs_users
            WHERE user_id = $1
            ",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(User::from))
    }

    async fn upsert_user(
        &self,
        profile: &DiscordProfile,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            r"
            INSERT INTO catacombs_users
                (user_id, username, global_name, avatar_url, banner_url, accent_color,
                 refresh_token, token_expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (user_id) DO UPDATE SET
                username = EXCLUDED.username,
                global_name = EXCLUDED.global_name,
                avatar_url = EXCLUDED.avatar_url,
                banner_url = EXCLUDED.banner_url,
                accent_color = EXCLUDED.accent_color,
                refresh_token = COALESCE(EXCLUDED.refresh_token, catacombs_users.refresh_token),
                token_expires_at =
                    COALESCE(EXCLUDED.token_expires_at, catacombs_users.token_expires_at)
            ",
        )
        .bind(profile.id)
        .bind(&profile.username)
        .bind(&profile.global_name)
        .bind(&profile.avatar_url)
        .bind(&profile.banner_url)
        .bind(profile.accent_color)
        .bind(tokens.map(|t| t.refresh_token.as_str()))
        .bind(tokens.map(|t| t.expires_at))
        .execute(&mut *tx)
        .await?;

        for (guild_id, guild) in &profile.guilds {
            sqlx::query(
                r"
                INSERT INTO catacombs_guild_profiles
                    (user_id, guild_id, nickname, avatar_url, banner_url)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (user_id, guild_id) DO UPDATE SET
                    nickname = EXCLUDED.nickname,
                    avatar_url = EXCLUDED.avatar_url,
                    banner_url = EXCLUDED.banner_url
                ",
            )
            .bind(profile.id)
            .bind(guild_id.0)
            .bind(&guild.nickname)
            .bind(&guild.avatar_url)
            .bind(&guild.banner_url)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn set_tokens(
        &self,
        user_id: i64,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "UPDATE catacombs_users SET refresh_token = $2, token_expires_at = $3 WHERE user_id = $1",
        )
        .bind(user_id)
        .bind(tokens.map(|t| t.refresh_token.as_str()))
        .bind(tokens.map(|t| t.expires_at))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn set_subscription(
        &self,
        user_id: i64,
        subscription: Option<&Subscription>,
    ) -> Result<(), StorageError> {
        let (tier, source, expires_at) = match subscription {
            Some(s) => (s.tier, Some(s.source), s.expires_at),
            None => (SubscriptionTier::Free, None, None),
        };
        sqlx::query(
            r"
            UPDATE catacombs_users
            SET subscription_tier = $2, subscription_source = $3, subscription_expires_at = $4
            WHERE user_id = $1
            ",
        )
        .bind(user_id)
        .bind(tier)
        .bind(source)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn upsert_entitlement(&self, e: &Entitlement) -> Result<(), StorageError> {
        sqlx::query(
            r"
            INSERT INTO catacombs_entitlements
                (entitlement_id, user_id, sku_id, entitlement_type, is_test, consumed,
                 starts_at, ends_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (entitlement_id) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                sku_id = EXCLUDED.sku_id,
                entitlement_type = EXCLUDED.entitlement_type,
                is_test = EXCLUDED.is_test,
                consumed = EXCLUDED.consumed,
                starts_at = EXCLUDED.starts_at,
                ends_at = EXCLUDED.ends_at
            ",
        )
        .bind(e.entitlement_id)
        .bind(e.user_id)
        .bind(e.sku_id)
        .bind(e.entitlement_type)
        .bind(e.is_test)
        .bind(e.consumed)
        .bind(e.starts_at)
        .bind(e.ends_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
