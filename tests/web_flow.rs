#![cfg(feature = "memory-storage")]

mod common;

use axum::{
    body::Body,
    http::{header, Request, Response, StatusCode},
    Router,
};
use catacombs::{
    auth::validate_token,
    routes::{
        auth_router,
        web::{AUTHORIZE_URL, RETURN_COOKIE, STATE_COOKIE},
    },
};
use common::*;
use tower::ServiceExt;

fn app(api_base: &str) -> Router {
    auth_router().with_state(test_state(api_base))
}

fn set_cookies<B>(resp: &Response<B>) -> Vec<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|v| v.to_str().unwrap().to_owned())
        .collect()
}

fn cookie<'a>(set: &'a [String], name: &str) -> Option<&'a String> {
    set.iter().find(|c| c.starts_with(&format!("{name}=")))
}

/// The cookie's value, percent-decoded (the jar encodes it on the wire).
fn value(set_cookie: &str) -> String {
    ::cookie::Cookie::parse_encoded(set_cookie)
        .unwrap()
        .value()
        .to_owned()
}

fn location<B>(resp: &Response<B>) -> String {
    resp.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned()
}

async fn get(app: Router, uri: &str, cookie: Option<&str>) -> Response<Body> {
    let mut req = Request::get(uri);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
}

#[tokio::test]
async fn login_redirects_to_discord_with_a_state_it_also_remembers() {
    let (base, _rec) = spawn_mock_discord().await;

    let resp = get(app(&base), "/login?return_to=/g/42", None).await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = location(&resp);
    assert!(loc.starts_with(&format!("{AUTHORIZE_URL}?")), "{loc}");
    let query: std::collections::HashMap<String, String> =
        serde_urlencoded::from_str(loc.split_once('?').unwrap().1).unwrap();
    assert_eq!(query["response_type"], "code");
    assert_eq!(query["client_id"], CLIENT_ID);
    assert_eq!(query["scope"], "identify");
    assert_eq!(query["redirect_uri"], REDIRECT_URI);

    let set = set_cookies(&resp);
    let state = cookie(&set, STATE_COOKIE).expect("state cookie");
    assert_eq!(value(state), query["state"]);
    assert!(query["state"].len() >= 32, "state has real entropy");
    for c in [state, cookie(&set, RETURN_COOKIE).expect("return cookie")] {
        assert!(c.contains("HttpOnly"), "{c}");
        assert!(c.contains("SameSite=Lax"), "{c}");
        assert!(c.contains("Secure"), "{c}");
    }
    assert_eq!(value(cookie(&set, RETURN_COOKIE).unwrap()), "/g/42");
}

#[tokio::test]
async fn login_will_not_remember_an_offsite_return() {
    let (base, _rec) = spawn_mock_discord().await;
    let resp = get(app(&base), "/login?return_to=//evil.example/x", None).await;
    let set = set_cookies(&resp);
    assert_eq!(value(cookie(&set, RETURN_COOKIE).unwrap()), "/");
}

#[tokio::test]
async fn a_callback_without_a_state_cookie_exchanges_nothing() {
    let (base, rec) = spawn_mock_discord().await;
    let resp = get(app(&base), "/callback?code=good&state=abc", None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(rec.token_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_callback_with_the_wrong_state_exchanges_nothing() {
    let (base, rec) = spawn_mock_discord().await;
    let resp = get(
        app(&base),
        "/callback?code=good&state=abc",
        Some(&format!("{STATE_COOKIE}=abd")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(rec.token_requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn a_good_callback_sets_the_session_and_returns_the_user() {
    let (base, rec) = spawn_mock_discord().await;

    let resp = get(
        app(&base),
        "/callback?code=good&state=abc",
        Some(&format!("{STATE_COOKIE}=abc; {RETURN_COOKIE}=/g/42")),
    )
    .await;

    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/g/42");
    {
        let sent = rec.token_requests.lock().unwrap();
        assert_eq!(sent.len(), 1);
        // The code from the query, not the state, goes to Discord.
        assert_eq!(sent[0].form["code"], "good");
        assert_eq!(sent[0].form["redirect_uri"], REDIRECT_URI);
        assert_eq!(sent[0].form["grant_type"], "authorization_code");
    }
    let set = set_cookies(&resp);
    let session = cookie(&set, "catacombs_session").expect("session cookie");
    for attr in [
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Path=/",
        "Max-Age=86400",
    ] {
        assert!(session.contains(attr), "{attr} missing from {session}");
    }
    let claims = validate_token(&value(session), JWT_SECRET).unwrap();
    assert_eq!(claims.sub, MOCK_USER_ID);
    // Both one-shot cookies are deleted.
    for name in [STATE_COOKIE, RETURN_COOKIE] {
        let c = cookie(&set, name).unwrap_or_else(|| panic!("{name} not cleared"));
        assert!(c.contains("Max-Age=0"), "{c}");
    }
}

#[tokio::test]
async fn a_planted_offsite_return_cookie_is_ignored_at_callback() {
    let (base, _rec) = spawn_mock_discord().await;
    let resp = get(
        app(&base),
        "/callback?code=good&state=abc",
        Some(&format!(
            "{STATE_COOKIE}=abc; {RETURN_COOKIE}=https://evil.example"
        )),
    )
    .await;
    assert_eq!(location(&resp), "/");
}

#[tokio::test]
async fn cancelling_on_discord_returns_the_user_logged_out() {
    let (base, rec) = spawn_mock_discord().await;
    let resp = get(
        app(&base),
        "/callback?error=access_denied&state=abc",
        Some(&format!("{STATE_COOKIE}=abc; {RETURN_COOKIE}=/g/42")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    assert_eq!(location(&resp), "/g/42");
    assert!(rec.token_requests.lock().unwrap().is_empty());
    assert!(cookie(&set_cookies(&resp), "catacombs_session").is_none());
}

#[tokio::test]
async fn the_session_cookie_authenticates_me() {
    let (base, _rec) = spawn_mock_discord().await;
    let app = app(&base);
    let login = get(
        app.clone(),
        "/callback?code=good&state=abc",
        Some(&format!("{STATE_COOKIE}=abc")),
    )
    .await;
    let set = set_cookies(&login);
    let jwt = value(cookie(&set, "catacombs_session").unwrap());

    let me = get(app, "/me", Some(&format!("catacombs_session={jwt}"))).await;

    assert_eq!(me.status(), StatusCode::OK);
    assert!(body_string(me).await.contains(MOCK_USER_ID));
}

#[tokio::test]
async fn an_empty_state_does_not_match_a_missing_state_cookie() {
    let (base, rec) = spawn_mock_discord().await;
    let resp = get(app(&base), "/callback?code=good&state=", None).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(rec.token_requests.lock().unwrap().is_empty());
}

async fn post(app: Router, uri: &str, cookie: Option<&str>) -> Response<Body> {
    let mut req = Request::post(uri);
    if let Some(c) = cookie {
        req = req.header(header::COOKIE, c);
    }
    app.oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
}

#[tokio::test]
async fn logout_clears_the_session_cookie_and_the_stored_tokens() {
    let (base, _rec) = spawn_mock_discord().await;
    let state = test_state(&base);
    let app = auth_router().with_state(state.clone());
    let login = get(
        app.clone(),
        "/callback?code=good&state=abc",
        Some(&format!("{STATE_COOKIE}=abc")),
    )
    .await;
    let jwt = value(cookie(&set_cookies(&login), "catacombs_session").unwrap());
    let user_id: i64 = MOCK_USER_ID.parse().unwrap();
    let before = state.storage.get_user(user_id, "k").await.unwrap().unwrap();
    assert!(
        before.refresh_token.is_some(),
        "login stored a refresh token"
    );

    let resp = post(app, "/logout", Some(&format!("catacombs_session={jwt}"))).await;

    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let set = set_cookies(&resp);
    let cleared = cookie(&set, "catacombs_session").expect("session cookie cleared");
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert!(cleared.contains("Secure"), "{cleared}");
    let after = state.storage.get_user(user_id, "k").await.unwrap().unwrap();
    assert!(after.refresh_token.is_none());
}

#[tokio::test]
async fn logout_without_a_valid_session_still_clears_the_cookie() {
    let (base, _rec) = spawn_mock_discord().await;
    let resp = post(
        app(&base),
        "/logout",
        Some("catacombs_session=expired.or.garbage"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    let set = set_cookies(&resp);
    assert!(cookie(&set, "catacombs_session")
        .expect("cleared")
        .contains("Max-Age=0"));
}
