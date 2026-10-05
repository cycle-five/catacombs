//! `SqlxStorage` against a real `PostgreSQL`. Ignored by default. To run:
//!
//! ```sh
//! docker compose up -d postgres
//! DATABASE_URL=postgres://postgres:postgres@localhost:5432/catacombs \
//!     cargo test --test sqlx_storage -- --ignored
//! ```
#![cfg(feature = "sqlx-storage")]

use std::path::Path;

use catacombs::{
    DiscordProfile, EncryptedToken, GuildId, GuildProfile, SqlxStorage, Storage, StoredTokens,
    Subscription, SubscriptionSource, SubscriptionTier,
};
use chrono::Utc;
use sqlx::{migrate::Migrator, PgPool};

/// A new, empty database, so each test starts clean.
async fn fresh_db() -> PgPool {
    let url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let admin = PgPool::connect(&url).await.unwrap();
    let name = format!("catacombs_test_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE DATABASE {name}"))
        .execute(&admin)
        .await
        .unwrap();
    let (server, _) = url.rsplit_once('/').unwrap();
    PgPool::connect(&format!("{server}/{name}")).await.unwrap()
}

fn tokens(ciphertext: &str) -> StoredTokens {
    StoredTokens {
        refresh_token: EncryptedToken::from_stored(ciphertext.into()),
        expires_at: Utc::now(),
    }
}

#[tokio::test]
#[ignore = "needs PostgreSQL; see the module docs"]
async fn migrate_runs_beside_a_hosts_own_migrations() {
    let pool = fresh_db().await;
    let mut host = Migrator::new(Path::new("tests/fixtures/host_migrations"))
        .await
        .unwrap();
    host.run(&pool).await.unwrap();

    let storage = SqlxStorage::new(pool.clone());
    storage.migrate().await.unwrap();
    storage.migrate().await.unwrap();

    // The host's migrator meets catacombs' rows in _sqlx_migrations; with
    // ignore_missing, as SqlxStorage::migrate documents, it still runs.
    host.set_ignore_missing(true);
    host.run(&pool).await.unwrap();
}

#[tokio::test]
#[ignore = "needs PostgreSQL; see the module docs"]
async fn users_tokens_guilds_and_subscriptions_round_trip() {
    let storage = SqlxStorage::new(fresh_db().await);
    storage.migrate().await.unwrap();

    let mut profile = DiscordProfile::new(42, "neo");
    profile.banner_url = Some("https://cdn.example/banner.png".into());
    profile.accent_color = Some(0x11_22_33);
    let mut seven = GuildProfile::default();
    seven.nickname = Some("seven".into());
    profile.guilds.insert(GuildId(7), seven);
    storage
        .upsert_user(&profile, Some(&tokens("c1")))
        .await
        .unwrap();

    let mut again = DiscordProfile::new(42, "neo2");
    let mut eight = GuildProfile::default();
    eight.nickname = Some("eight".into());
    again.guilds.insert(GuildId(8), eight);
    storage.upsert_user(&again, None).await.unwrap();

    let user = storage.get_user(42).await.unwrap().unwrap();
    assert_eq!(user.username, "neo2");
    assert_eq!(user.tokens.unwrap().refresh_token.as_str(), "c1");
    let guilds: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM catacombs_guild_profiles WHERE user_id = 42")
            .fetch_one(storage.pool())
            .await
            .unwrap();
    assert_eq!(guilds, 2);

    storage.set_tokens(42, None).await.unwrap();
    assert!(storage
        .get_user(42)
        .await
        .unwrap()
        .unwrap()
        .tokens
        .is_none());

    let premium = Subscription {
        tier: SubscriptionTier::Premium,
        source: SubscriptionSource::Manual,
        expires_at: None,
    };
    storage.set_subscription(42, Some(&premium)).await.unwrap();
    assert!(storage.get_user(42).await.unwrap().unwrap().is_premium());
    storage.set_subscription(42, None).await.unwrap();
    let user = storage.get_user(42).await.unwrap().unwrap();
    assert_eq!(user.subscription_tier, SubscriptionTier::Free);
    assert_eq!(user.subscription_source, None);
}
