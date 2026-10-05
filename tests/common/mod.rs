//! A local stand-in for Discord's token and user endpoints that records
//! exactly what catacombs sent it.
#![allow(dead_code)] // each test binary uses a different subset

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Form, Json, Router,
};
use catacombs::{Auth, Config, DiscordConfig, MemoryStorage, SecurityConfig, WebConfig};
use serde::Serialize;

pub const CLIENT_ID: &str = "client-id-123";
pub const CLIENT_SECRET: &str = "client-secret-456";
pub const REDIRECT_URI: &str = "https://dash.example/auth/callback";
pub const JWT_SECRET: &str = "test-jwt-secret";
pub const MOCK_USER_ID: &str = "112233445566778899";
pub const MOCK_ACCESS_TOKEN: &str = "discord-access-token";
/// A code the mock rejects the way Discord does: 400 invalid_grant.
pub const BAD_CODE: &str = "bad-code";

#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub authorization: Option<String>,
    pub form: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct Recorded {
    pub token_requests: Arc<Mutex<Vec<TokenRequest>>>,
    /// The Authorization header of each `/users/@me` request.
    pub me_requests: Arc<Mutex<Vec<Option<String>>>>,
}

#[derive(Serialize)]
struct MockToken<'a> {
    access_token: &'a str,
    token_type: &'a str,
    expires_in: i64,
    refresh_token: &'a str,
    scope: &'a str,
}

#[derive(Serialize)]
struct MockUser<'a> {
    id: &'a str,
    username: &'a str,
    avatar: Option<&'a str>,
    global_name: Option<&'a str>,
    discriminator: Option<&'a str>,
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

async fn token(
    State(rec): State<Recorded>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let rejected = form.get("code").map(String::as_str) == Some(BAD_CODE);
    rec.token_requests.lock().unwrap().push(TokenRequest {
        authorization: header(&headers, "authorization"),
        form,
    });
    if rejected {
        return (StatusCode::BAD_REQUEST, "invalid_grant").into_response();
    }
    Json(MockToken {
        access_token: MOCK_ACCESS_TOKEN,
        token_type: "Bearer",
        expires_in: 604_800,
        refresh_token: "discord-refresh-token",
        scope: "identify",
    })
    .into_response()
}

async fn me(State(rec): State<Recorded>, headers: HeaderMap) -> Json<MockUser<'static>> {
    rec.me_requests
        .lock()
        .unwrap()
        .push(header(&headers, "authorization"));
    Json(MockUser {
        id: MOCK_USER_ID,
        username: "mockuser",
        avatar: None,
        global_name: Some("Mock User"),
        discriminator: None,
    })
}

/// Start the mock on an ephemeral port; returns its base URL.
pub async fn spawn_mock_discord() -> (String, Recorded) {
    let rec = Recorded::default();
    let app = Router::new()
        .route("/oauth2/token", post(token))
        .route("/users/@me", get(me))
        .with_state(rec.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), rec)
}

pub fn test_config(api_base: &str) -> Config {
    Config {
        discord: DiscordConfig {
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
            redirect_uri: REDIRECT_URI.to_string(),
            premium: None,
            api_base: api_base.to_string(),
        },
        security: SecurityConfig {
            jwt_secret: JWT_SECRET.to_string(),
            encryption_key: catacombs::encryption::generate_key(),
        },
        web: WebConfig::default(),
    }
}

pub fn test_state(api_base: &str) -> Arc<Auth> {
    Arc::new(Auth::new(test_config(api_base), MemoryStorage::new()).unwrap())
}

pub fn post_json(uri: &str, body: &str) -> axum::http::Request<axum::body::Body> {
    axum::http::Request::post(uri)
        .header(axum::http::header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_owned()))
        .unwrap()
}

#[derive(serde::Deserialize)]
pub struct TokenBody {
    pub access_token: String,
    pub discord_access_token: Option<String>,
}

pub async fn access_token(resp: Response) -> String {
    serde_json::from_str::<TokenBody>(&body_string(resp).await)
        .unwrap()
        .access_token
}

pub async fn body_string(resp: Response) -> String {
    use http_body_util::BodyExt;
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}
