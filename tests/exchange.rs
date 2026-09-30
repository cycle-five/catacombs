#![cfg(feature = "memory-storage")]

mod common;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    Router,
};
use base64::Engine;
use catacombs::{auth::validate_token, routes::auth_router};
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

    #[derive(serde::Deserialize)]
    struct Body_ {
        access_token: String,
    }
    let body: Body_ = serde_json::from_str(&body_string(resp).await).unwrap();
    let claims = validate_token(&body.access_token, JWT_SECRET).unwrap();
    assert_eq!(claims.sub, MOCK_USER_ID);
}

#[tokio::test]
async fn a_rejected_code_is_401_and_never_fetches_the_user() {
    let (base, rec) = spawn_mock_discord().await;

    let resp = app(&base).oneshot(exchange(BAD_CODE)).await.unwrap();

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(rec.token_requests.lock().unwrap().len(), 1);
    assert!(rec.me_requests.lock().unwrap().is_empty());
}
