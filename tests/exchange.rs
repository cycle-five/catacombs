#![cfg(feature = "memory-storage")]

mod common;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use base64::Engine;
use catacombs::{auth::validate_token, routes::auth_router, Storage};
use common::*;
use tower::ServiceExt;

fn app(api_base: &str) -> Router {
    auth_router().with_state(test_state(api_base))
}

fn exchange(code: &str) -> Request<Body> {
    Request::post("/exchange")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(r#"{{"code":"{code}"}}"#)))
        .unwrap()
}

#[tokio::test]
async fn exchange_sends_the_code_with_basic_auth_and_the_configured_redirect() {
    let (base, rec) = spawn_mock_discord().await;

    let resp = app(&base).oneshot(exchange("good-code")).await.unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let sent = rec.token_requests.lock().unwrap().clone();
    assert_eq!(sent.len(), 1, "exactly one token request");
    let form = &sent[0].form;
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );
    assert_eq!(form.get("code").map(String::as_str), Some("good-code"));
    assert_eq!(
        form.get("redirect_uri").map(String::as_str),
        Some(REDIRECT_URI)
    );
    let basic =
        base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"));
    assert_eq!(
        sent[0].authorization.as_deref(),
        Some(format!("Basic {basic}").as_str())
    );

    let me = rec.me_requests.lock().unwrap().clone();
    assert_eq!(me, vec![Some(format!("Bearer {MOCK_ACCESS_TOKEN}"))]);

    let body: TokenBody = serde_json::from_str(&body_string(resp).await).unwrap();
    let claims = validate_token(&body.access_token, JWT_SECRET).unwrap();
    assert_eq!(claims.sub, MOCK_USER_ID);
    assert_eq!(
        body.discord_access_token.as_deref(),
        Some(MOCK_ACCESS_TOKEN)
    );
}

#[tokio::test]
async fn a_rejected_code_is_401_and_never_fetches_the_user() {
    let (base, rec) = spawn_mock_discord().await;

    let resp = app(&base).oneshot(exchange(BAD_CODE)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(rec.token_requests.lock().unwrap().len(), 1);
    assert!(rec.me_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_refresh_token_is_stored_only_as_ciphertext() {
    let (base, _rec) = spawn_mock_discord().await;
    let (state, storage) = test_state_with_storage(&base);

    let resp = auth_router()
        .with_state(state)
        .oneshot(exchange("good-code"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let user = storage
        .get_user(MOCK_USER_ID.parse().unwrap())
        .await
        .unwrap()
        .unwrap();
    let stored = user.tokens.expect("tokens stored");
    assert!(!stored.refresh_token.as_str().contains(MOCK_REFRESH_TOKEN));
}

#[tokio::test]
async fn refresh_decrypts_the_stored_token_and_sends_it_to_discord() {
    let (base, rec) = spawn_mock_discord().await;
    let app = auth_router().with_state(test_state(&base));

    let resp = app.clone().oneshot(exchange("good-code")).await.unwrap();
    let jwt = access_token(resp).await;
    let resp = app
        .oneshot(
            Request::post("/refresh")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let sent = rec.token_requests.lock().unwrap().clone();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[1].form["grant_type"], "refresh_token");
    assert_eq!(sent[1].form["refresh_token"], MOCK_REFRESH_TOKEN);
}

#[tokio::test]
async fn bad_client_credentials_are_401() {
    let (base, _rec) = spawn_mock_discord().await;
    let resp = app(&base)
        .oneshot(exchange(INVALID_CLIENT_CODE))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discord_failing_is_502_not_401() {
    let (base, _rec) = spawn_mock_discord().await;
    let resp = app(&base)
        .oneshot(exchange(DISCORD_DOWN_CODE))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    assert_eq!(body_string(resp).await, "", "error bodies stay empty");
}

#[tokio::test]
async fn discord_unreachable_is_502() {
    // Nothing listens on port 1.
    let resp = app("http://127.0.0.1:1")
        .oneshot(exchange("good-code"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn the_stored_profile_has_banner_and_accent_and_no_fake_avatar() {
    let (base, _rec) = spawn_mock_discord().await;
    let (state, storage) = test_state_with_storage(&base);
    let resp = auth_router()
        .with_state(state)
        .oneshot(exchange("good-code"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let profile = storage.profile(MOCK_USER_ID.parse().unwrap()).unwrap();
    assert_eq!(profile.avatar_url, None);
    assert_eq!(
        profile.banner_url.as_deref(),
        Some(
            format!("https://cdn.discordapp.com/banners/{MOCK_USER_ID}/a_banner.gif?size=1024")
                .as_str()
        )
    );
    assert_eq!(profile.accent_color, Some(0x11_22_33));
}
