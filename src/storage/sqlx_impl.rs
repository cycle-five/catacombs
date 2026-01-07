//! `SQLx` `PostgreSQL` storage implementation.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::{
    encryption,
    error::{Result, StorageError},
    models::{
        EntitlementUpsertParams, SubscriptionSource, SubscriptionTier, User, UserUpsertParams,
    },
    storage::{EntitlementStorage, UserStorage},
};

/// `SQLx` `PostgreSQL` storage backend.
#[derive(Debug, Clone)]
pub struct SqlxStorage {
    pool: PgPool,
}

impl SqlxStorage {
    /// Create a new `SQLx` storage with the given connection pool.
    #[must_use] 
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get a reference to the underlying connection pool.
    #[must_use] 
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Run database migrations.
    /// 
    /// # Errors
    ///    - Returns `StorageError` if migration fails.
    pub async fn migrate(&self) -> Result<()> {
        sqlx::migrate!("./migrations")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.into()))?;
        Ok(())
    }
}

#[async_trait]
impl UserStorage for SqlxStorage {
    async fn get_user(&self, user_id: i64, encryption_key: &str) -> Result<Option<User>> {
        let row = sqlx::query_as::<_, UserRow>(
            r"
            SELECT
                user_id, username, global_name, avatar_url,
                refresh_token, token_expires_at,
                subscription_tier, subscription_source, subscription_expires_at,
                created_at, updated_at
            FROM users
            WHERE user_id = $1
            ",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        match row {
            Some(row) => {
                let refresh_token = match row.refresh_token {
                    Some(encrypted) => Some(
                        encryption::decrypt(&encrypted, encryption_key).map_err(|e| {
                            StorageError::Other(format!("failed to decrypt refresh token: {e}"))
                        })?,
                    ),
                    None => None,
                };

                Ok(Some(User {
                    user_id: row.user_id,
                    username: row.username,
                    global_name: row.global_name,
                    avatar_url: row.avatar_url,
                    refresh_token,
                    token_expires_at: row.token_expires_at,
                    subscription_tier: row.subscription_tier,
                    subscription_source: row.subscription_source,
                    subscription_expires_at: row.subscription_expires_at,
                    created_at: row.created_at,
                    updated_at: row.updated_at,
                }))
            }
            None => Ok(None),
        }
    }

    async fn upsert_user(&self, params: UserUpsertParams<'_>, encryption_key: &str) -> Result<()> {
        let encrypted_token = match params.refresh_token {
            Some(token) => Some(encryption::encrypt(token, encryption_key).map_err(|e| {
                StorageError::Other(format!("failed to encrypt refresh token: {e}"))
            })?),
            None => None,
        };

        sqlx::query(
            r"
            INSERT INTO users (user_id, username, global_name, avatar_url, refresh_token, token_expires_at)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (user_id) DO UPDATE SET
                username = EXCLUDED.username,
                global_name = EXCLUDED.global_name,
                avatar_url = EXCLUDED.avatar_url,
                refresh_token = COALESCE(EXCLUDED.refresh_token, users.refresh_token),
                token_expires_at = COALESCE(EXCLUDED.token_expires_at, users.token_expires_at),
                updated_at = NOW()
            ",
        )
        .bind(params.user_id)
        .bind(params.username)
        .bind(params.global_name)
        .bind(params.avatar_url)
        .bind(encrypted_token)
        .bind(params.token_expires_at)
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(())
    }

    async fn update_refresh_token(
        &self,
        user_id: i64,
        refresh_token: &str,
        token_expires_at: DateTime<Utc>,
        encryption_key: &str,
    ) -> Result<()> {
        let encrypted_token = encryption::encrypt(refresh_token, encryption_key)
            .map_err(|e| StorageError::Other(format!("failed to encrypt refresh token: {e}")))?;

        sqlx::query(
            r"
            UPDATE users
            SET refresh_token = $2, token_expires_at = $3, updated_at = NOW()
            WHERE user_id = $1
            ",
        )
        .bind(user_id)
        .bind(encrypted_token)
        .bind(token_expires_at)
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(())
    }

    async fn clear_user_tokens(&self, user_id: i64) -> Result<()> {
        sqlx::query(
            r"
            UPDATE users
            SET refresh_token = NULL, token_expires_at = NULL, updated_at = NOW()
            WHERE user_id = $1
            ",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(())
    }

    async fn update_subscription(
        &self,
        user_id: i64,
        tier: SubscriptionTier,
        source: SubscriptionSource,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        sqlx::query(
            r"
            UPDATE users
            SET subscription_tier = $2, subscription_source = $3, subscription_expires_at = $4, updated_at = NOW()
            WHERE user_id = $1
            ",
        )
        .bind(user_id)
        .bind(tier)
        .bind(source)
        .bind(expires_at)
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(())
    }
}

#[async_trait]
impl EntitlementStorage for SqlxStorage {
    async fn upsert_entitlement(&self, params: EntitlementUpsertParams) -> Result<()> {
        sqlx::query(
            r"
            INSERT INTO entitlements (entitlement_id, user_id, sku_id, entitlement_type, is_test, consumed, starts_at, ends_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (entitlement_id) DO UPDATE SET
                consumed = EXCLUDED.consumed,
                ends_at = EXCLUDED.ends_at,
                updated_at = NOW()
            ",
        )
        .bind(params.entitlement_id)
        .bind(params.user_id)
        .bind(params.sku_id)
        .bind(params.entitlement_type)
        .bind(params.is_test)
        .bind(params.consumed)
        .bind(params.starts_at)
        .bind(params.ends_at)
        .execute(&self.pool)
        .await
        .map_err(StorageError::Database)?;

        Ok(())
    }
}

/// Internal row type for `SQLx` queries.
#[derive(Debug, sqlx::FromRow)]
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
