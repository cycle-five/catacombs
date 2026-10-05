#![cfg(feature = "memory-storage")]

mod common;

use axum::http::StatusCode;
use catacombs::{
    routes::auth_router, DiscordProfile, Flow, GuildId, LoginWarning, Storage, Subscription,
    SubscriptionSource, SubscriptionTier,
};
use common::*;
use tower::ServiceExt;

fn user_id() -> i64 {
    MOCK_USER_ID.parse().unwrap()
}

async fn exchange(built: &Built, body: &str) -> StatusCode {
    auth_router()
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
    built
        .storage
        .upsert_user(&DiscordProfile::new(user_id(), "mockuser"), None)
        .await
        .unwrap();
    let premium = Subscription {
        tier: SubscriptionTier::Premium,
        source,
        expires_at: None,
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
