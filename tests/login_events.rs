#![cfg(feature = "memory-storage")]

mod common;

use axum::http::StatusCode;
use catacombs::{
    router, DiscordProfile, Flow, Flows, GuildId, LoginWarning, Storage, Subscription,
    SubscriptionSource, SubscriptionTier,
};
use common::*;
use tower::ServiceExt;

fn user_id() -> i64 {
    MOCK_USER_ID.parse().unwrap()
}

async fn exchange(built: &Built, body: &str) -> StatusCode {
    router(Flows::Activity)
        .with_state(built.state.clone())
        .oneshot(post_json("/exchange", body))
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn a_login_is_reported_once_with_its_user() {
    let (base, _rec) = spawn_mock_discord().await;
    let built = build(&base, false);
    assert_eq!(
        exchange(&built, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );
    assert_eq!(
        built.events.seen(),
        vec![Seen {
            flow: Flow::Exchange,
            user_id: Some(user_id()),
            reason: None,
            warnings: vec![]
        }]
    );
}

#[tokio::test]
async fn a_failed_login_is_reported_with_its_reason() {
    let (base, _rec) = spawn_mock_discord().await;
    let built = build(&base, false);
    let body = format!(r#"{{"code":"{BAD_CODE}"}}"#);
    assert_eq!(exchange(&built, &body).await, StatusCode::UNAUTHORIZED);
    let seen = built.events.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].reason, Some("invalid_grant"));
    assert_eq!(seen[0].user_id, None);
}

#[tokio::test]
async fn a_guild_id_fetches_and_stores_the_guild_profile() {
    let (base, rec) = spawn_mock_discord().await;
    let built = build(&base, false);
    let body = format!(r#"{{"code":"good-code","guild_id":"{MOCK_GUILD_ID}"}}"#);
    assert_eq!(exchange(&built, &body).await, StatusCode::OK);

    assert_eq!(
        *rec.member_requests.lock().unwrap(),
        vec![MOCK_GUILD_ID.to_string()]
    );
    let profile = built.storage.profile(user_id()).unwrap();
    let guild = &profile.guilds[&GuildId::parse(MOCK_GUILD_ID).unwrap()];
    assert_eq!(guild.nickname.as_deref(), Some(MOCK_NICK));
    assert!(built.events.seen()[0].warnings.is_empty());
}

#[tokio::test]
async fn a_guild_discord_refuses_is_a_warning_not_a_failure() {
    let (base, _rec) = spawn_mock_discord().await;
    let built = build(&base, false);
    assert_eq!(
        exchange(&built, r#"{"code":"good-code","guild_id":"999"}"#).await,
        StatusCode::OK
    );
    assert!(built.storage.profile(user_id()).unwrap().guilds.is_empty());
    assert_eq!(
        built.events.seen()[0].warnings,
        vec![LoginWarning::GuildProfileUnavailable(GuildId(999))]
    );
}

#[tokio::test]
async fn an_activity_in_a_dm_sends_a_null_guild_and_logs_in() {
    let (base, rec) = spawn_mock_discord().await;
    let built = build(&base, false);
    assert_eq!(
        exchange(&built, r#"{"code":"good-code","guild_id":null}"#).await,
        StatusCode::OK
    );
    assert!(rec.member_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn an_active_premium_entitlement_makes_the_user_premium() {
    let (base, rec) = spawn_mock_discord().await;
    *rec.entitlements_reply.lock().unwrap() =
        EntitlementsReply::List(vec![MockEntitlement::premium_forever("1")]);
    let built = build(&base, true);
    assert_eq!(
        exchange(&built, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );

    let user = built.storage.get_user(user_id()).await.unwrap().unwrap();
    assert!(user.is_premium());
    assert_eq!(user.subscription_source, Some(SubscriptionSource::Discord));
    assert_eq!(user.subscription_expires_at, None);
    assert!(built.storage.entitlement(1).is_some());
    let (auth_header, query) = rec.entitlement_requests.lock().unwrap()[0].clone();
    assert_eq!(auth_header.as_deref(), Some("Bot bot-token"));
    assert!(query.unwrap().contains(&format!("user_id={MOCK_USER_ID}")));
}

/// Put a user in storage before they log in, with `source`'s premium.
async fn seed_premium(built: &Built, source: SubscriptionSource) {
    seed_premium_until(built, source, None).await;
}

/// As `seed_premium`, ending at `expires_at` (`None` is lifetime).
async fn seed_premium_until(
    built: &Built,
    source: SubscriptionSource,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
) {
    built
        .storage
        .upsert_user(&DiscordProfile::new(user_id(), "mockuser"), None)
        .await
        .unwrap();
    let premium = Subscription {
        tier: SubscriptionTier::Premium,
        source,
        expires_at,
    };
    built
        .storage
        .set_subscription(user_id(), Some(&premium))
        .await
        .unwrap();
}

#[tokio::test]
async fn an_entitlements_outage_never_downgrades_a_paying_user() {
    let (base, rec) = spawn_mock_discord().await;
    *rec.entitlements_reply.lock().unwrap() =
        EntitlementsReply::Fail(StatusCode::SERVICE_UNAVAILABLE);
    let built = build(&base, true);
    seed_premium(&built, SubscriptionSource::Discord).await;

    assert_eq!(
        exchange(&built, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );
    assert!(built
        .storage
        .get_user(user_id())
        .await
        .unwrap()
        .unwrap()
        .is_premium());
    assert_eq!(
        built.events.seen()[0].warnings,
        vec![LoginWarning::EntitlementsUnavailable]
    );
}

#[tokio::test]
async fn premium_from_discord_ends_when_the_entitlement_is_gone() {
    let (base, _rec) = spawn_mock_discord().await;
    let built = build(&base, true);
    seed_premium(&built, SubscriptionSource::Discord).await;

    assert_eq!(
        exchange(&built, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );
    let user = built.storage.get_user(user_id()).await.unwrap().unwrap();
    assert_eq!(user.subscription_tier, SubscriptionTier::Free);
}

/// A consumed entitlement is spent: it is stored, but grants no premium.
#[tokio::test]
async fn a_consumed_premium_entitlement_grants_nothing() {
    let (base, rec) = spawn_mock_discord().await;
    *rec.entitlements_reply.lock().unwrap() = EntitlementsReply::List(vec![MockEntitlement {
        consumed: true,
        ..MockEntitlement::premium_forever("1")
    }]);
    let built = build(&base, true);
    seed_premium(&built, SubscriptionSource::Discord).await;

    assert_eq!(
        exchange(&built, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );

    let user = built.storage.get_user(user_id()).await.unwrap().unwrap();
    assert_eq!(
        user.subscription_tier,
        SubscriptionTier::Free,
        "spent premium from Discord ends"
    );
    assert!(
        built.storage.entitlement(1).is_some(),
        "the consumed entitlement is still stored"
    );
}

#[tokio::test]
async fn premium_granted_by_hand_survives_a_login_without_entitlements() {
    let (base, _rec) = spawn_mock_discord().await;
    let built = build(&base, true);
    seed_premium(&built, SubscriptionSource::Manual).await;

    assert_eq!(
        exchange(&built, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );
    let user = built.storage.get_user(user_id()).await.unwrap().unwrap();
    assert!(user.is_premium());
    assert_eq!(user.subscription_source, Some(SubscriptionSource::Manual));
}

// Premium edge cases.

async fn login_with(entitlements: Vec<MockEntitlement>) -> Built {
    let (base, rec) = spawn_mock_discord().await;
    *rec.entitlements_reply.lock().unwrap() = EntitlementsReply::List(entitlements);
    let built = build(&base, true);
    assert_eq!(
        exchange(&built, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );
    built
}

async fn stored_user(built: &Built) -> catacombs::User {
    built.storage.get_user(user_id()).await.unwrap().unwrap()
}

#[tokio::test]
async fn the_latest_of_several_time_limited_entitlements_is_the_expiry() {
    let soon = MockEntitlement::premium_ending("1", chrono::Duration::days(10));
    let later = MockEntitlement::premium_ending("2", chrono::Duration::days(30));
    let later_end = chrono::DateTime::parse_from_rfc3339(later.ends_at.as_ref().unwrap()).unwrap();
    let built = login_with(vec![later.clone(), soon]).await;

    let user = stored_user(&built).await;
    assert!(user.is_premium());
    assert_eq!(
        user.subscription_expires_at.map(|t| t.timestamp()),
        Some(later_end.timestamp())
    );
}

#[tokio::test]
async fn a_lifetime_entitlement_beats_a_time_limited_one() {
    let limited = MockEntitlement::premium_ending("1", chrono::Duration::days(10));
    let built = login_with(vec![limited, MockEntitlement::premium_forever("2")]).await;

    let user = stored_user(&built).await;
    assert!(user.is_premium());
    assert_eq!(user.subscription_expires_at, None);
}

#[tokio::test]
async fn an_expired_entitlement_grants_nothing() {
    let built = login_with(vec![MockEntitlement::premium_ending(
        "1",
        chrono::Duration::days(-1),
    )])
    .await;
    assert_eq!(
        stored_user(&built).await.subscription_tier,
        SubscriptionTier::Free
    );
}

#[tokio::test]
async fn a_deleted_entitlement_grants_nothing() {
    let deleted = MockEntitlement {
        deleted: true,
        ..MockEntitlement::premium_forever("1")
    };
    let built = login_with(vec![deleted]).await;
    assert_eq!(
        stored_user(&built).await.subscription_tier,
        SubscriptionTier::Free
    );
    assert!(built.storage.entitlement(1).is_none());
}

#[tokio::test]
async fn an_entitlement_for_another_sku_grants_nothing() {
    let other = MockEntitlement {
        sku_id: "888".into(),
        ..MockEntitlement::premium_forever("1")
    };
    let built = login_with(vec![other]).await;
    assert_eq!(
        stored_user(&built).await.subscription_tier,
        SubscriptionTier::Free
    );
}

/// Seed `source` premium ending `expires_at`, then log in with `entitlements`.
async fn login_seeded(
    source: SubscriptionSource,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    entitlements: Vec<MockEntitlement>,
) -> Built {
    let (base, rec) = spawn_mock_discord().await;
    *rec.entitlements_reply.lock().unwrap() = EntitlementsReply::List(entitlements);
    let built = build(&base, true);
    seed_premium_until(&built, source, expires_at).await;
    assert_eq!(
        exchange(&built, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );
    built
}

#[tokio::test]
async fn a_lifetime_manual_grant_is_not_overwritten_by_a_shorter_discord_one() {
    let limited = MockEntitlement::premium_ending("1", chrono::Duration::days(10));
    let built = login_seeded(SubscriptionSource::Manual, None, vec![limited]).await;
    let user = stored_user(&built).await;
    assert!(user.is_premium());
    assert_eq!(user.subscription_source, Some(SubscriptionSource::Manual));
    assert_eq!(user.subscription_expires_at, None);

    // The Discord grant is not stored, so it ending later takes nothing away.
    let (base, _rec) = spawn_mock_discord().await;
    let built2 = build(&base, true);
    seed_premium(&built2, SubscriptionSource::Manual).await;
    assert_eq!(
        exchange(&built2, r#"{"code":"good-code"}"#).await,
        StatusCode::OK
    );
    let user = stored_user(&built2).await;
    assert!(user.is_premium());
    assert_eq!(user.subscription_source, Some(SubscriptionSource::Manual));
}

#[tokio::test]
async fn a_lifetime_discord_grant_replaces_a_manual_one_that_ends_sooner() {
    let soon = chrono::Utc::now() + chrono::Duration::days(5);
    let built = login_seeded(
        SubscriptionSource::Manual,
        Some(soon),
        vec![MockEntitlement::premium_forever("1")],
    )
    .await;
    let user = stored_user(&built).await;
    assert!(user.is_premium());
    assert_eq!(user.subscription_source, Some(SubscriptionSource::Discord));
    assert_eq!(user.subscription_expires_at, None);
}

#[tokio::test]
async fn a_longer_manual_grant_is_kept_over_a_shorter_discord_one() {
    let manual_end = chrono::Utc::now() + chrono::Duration::days(30);
    let built = login_seeded(
        SubscriptionSource::External,
        Some(manual_end),
        vec![MockEntitlement::premium_ending(
            "1",
            chrono::Duration::days(5),
        )],
    )
    .await;
    let user = stored_user(&built).await;
    assert_eq!(user.subscription_source, Some(SubscriptionSource::External));
    assert_eq!(
        user.subscription_expires_at.map(|t| t.timestamp()),
        Some(manual_end.timestamp())
    );
}

#[tokio::test]
async fn premium_from_an_external_source_survives_a_login_without_entitlements() {
    let built = login_seeded(SubscriptionSource::External, None, vec![]).await;
    let user = stored_user(&built).await;
    assert!(user.is_premium());
    assert_eq!(user.subscription_source, Some(SubscriptionSource::External));
}

#[tokio::test]
async fn a_malformed_entitlement_for_another_sku_is_skipped() {
    let bad = MockEntitlement {
        sku_id: "888".into(),
        ..MockEntitlement::premium_forever("not-a-snowflake")
    };
    let built = login_with(vec![bad, MockEntitlement::premium_forever("5")]).await;
    assert!(stored_user(&built).await.is_premium());
    assert!(built.storage.entitlement(5).is_some());
    assert!(built.events.seen()[0].warnings.is_empty());
}

#[tokio::test]
async fn a_malformed_premium_entitlement_leaves_storage_unchanged() {
    for bad in [
        MockEntitlement::premium_forever("not-a-snowflake"),
        MockEntitlement {
            sku_id: "not-a-sku".into(),
            ..MockEntitlement::premium_forever("1")
        },
    ] {
        let built = login_seeded(
            SubscriptionSource::Discord,
            None,
            vec![bad, MockEntitlement::premium_forever("5")],
        )
        .await;
        let user = stored_user(&built).await;
        assert!(user.is_premium());
        assert_eq!(user.subscription_source, Some(SubscriptionSource::Discord));
        assert_eq!(
            built.events.seen()[0].warnings,
            vec![LoginWarning::EntitlementsUnavailable]
        );
    }
}
