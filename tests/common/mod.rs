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
use catacombs::{
    Auth, AuthEvent, AuthObserver, Config, DiscordConfig, Flow, LoginWarning, MemoryStorage,
    PremiumConfig, SecurityConfig, WebConfig,
};
use serde::Serialize;

pub const CLIENT_ID: &str = "client-id-123";
pub const CLIENT_SECRET: &str = "client-secret-456";
pub const REDIRECT_URI: &str = "https://dash.example/auth/callback";
pub const JWT_SECRET: &str = "test-jwt-secret";
pub const MOCK_USER_ID: &str = "112233445566778899";
pub const MOCK_ACCESS_TOKEN: &str = "discord-access-token";
pub const MOCK_REFRESH_TOKEN: &str = "discord-refresh-token";
/// A code the mock rejects the way Discord does: 400 invalid_grant.
pub const BAD_CODE: &str = "bad-code";
pub const INVALID_CLIENT_CODE: &str = "invalid-client-code";
pub const DISCORD_DOWN_CODE: &str = "discord-down-code";
pub const MOCK_GUILD_ID: &str = "555";
pub const MOCK_NICK: &str = "Mocky";

#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub authorization: Option<String>,
    pub form: HashMap<String, String>,
}

/// An entitlements request's authorization header and raw query.
pub type EntitlementRequest = (Option<String>, Option<String>);

#[derive(Debug, Clone, Default)]
pub struct Recorded {
    pub token_requests: Arc<Mutex<Vec<TokenRequest>>>,
    /// The Authorization header of each `/users/@me` request.
    pub me_requests: Arc<Mutex<Vec<Option<String>>>>,
    /// The guild id of each guild member request.
    pub member_requests: Arc<Mutex<Vec<String>>>,
    /// What the entitlements endpoint answers.
    pub entitlements_reply: Arc<Mutex<EntitlementsReply>>,
    /// The authorization header and raw query of each entitlements request.
    pub entitlement_requests: Arc<Mutex<Vec<EntitlementRequest>>>,
}

#[derive(Serialize)]
struct OAuthErrorBody<'a> {
    error: &'a str,
}

#[derive(Serialize)]
struct MockMember<'a> {
    nick: Option<&'a str>,
    avatar: Option<&'a str>,
    banner: Option<&'a str>,
}

#[derive(Serialize)]
struct DiscordErrorBody<'a> {
    message: &'a str,
    code: u32,
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
    banner: Option<&'a str>,
    accent_color: Option<i32>,
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
    let code = form.get("code").cloned();
    rec.token_requests.lock().unwrap().push(TokenRequest {
        authorization: header(&headers, "authorization"),
        form,
    });
    match code.as_deref() {
        Some(BAD_CODE) => (
            StatusCode::BAD_REQUEST,
            Json(OAuthErrorBody {
                error: "invalid_grant",
            }),
        )
            .into_response(),
        Some(INVALID_CLIENT_CODE) => (
            StatusCode::UNAUTHORIZED,
            Json(OAuthErrorBody {
                error: "invalid_client",
            }),
        )
            .into_response(),
        Some(DISCORD_DOWN_CODE) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
        _ => Json(MockToken {
            access_token: MOCK_ACCESS_TOKEN,
            token_type: "Bearer",
            expires_in: 604_800,
            refresh_token: MOCK_REFRESH_TOKEN,
            scope: "identify",
        })
        .into_response(),
    }
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
        banner: Some("a_banner"),
        accent_color: Some(0x11_22_33),
    })
}

async fn member(
    State(rec): State<Recorded>,
    axum::extract::Path(guild_id): axum::extract::Path<String>,
) -> Response {
    rec.member_requests.lock().unwrap().push(guild_id.clone());
    if guild_id == MOCK_GUILD_ID {
        Json(MockMember {
            nick: Some(MOCK_NICK),
            avatar: Some("guildav"),
            banner: None,
        })
        .into_response()
    } else {
        (
            StatusCode::FORBIDDEN,
            Json(DiscordErrorBody {
                message: "Missing Access",
                code: 50001,
            }),
        )
            .into_response()
    }
}

async fn entitlements(
    State(rec): State<Recorded>,
    headers: HeaderMap,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    rec.entitlement_requests
        .lock()
        .unwrap()
        .push((header(&headers, "authorization"), query));
    match rec.entitlements_reply.lock().unwrap().clone() {
        EntitlementsReply::List(list) => Json(list).into_response(),
        EntitlementsReply::Fail(status) => status.into_response(),
    }
}

/// Start the mock on an ephemeral port; returns its base URL.
pub async fn spawn_mock_discord() -> (String, Recorded) {
    let rec = Recorded::default();
    let app = Router::new()
        .route("/oauth2/token", post(token))
        .route("/users/@me", get(me))
        .route("/users/@me/guilds/{guild_id}/member", get(member))
        .route("/applications/{app_id}/entitlements", get(entitlements))
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

pub fn test_state_with_storage(api_base: &str) -> (Arc<Auth>, Arc<MemoryStorage>) {
    let storage = Arc::new(MemoryStorage::new());
    let auth = Auth::new(test_config(api_base), storage.clone()).unwrap();
    (Arc::new(auth), storage)
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

pub const PREMIUM_SKU: i64 = 777;

/// One observed login.
#[derive(Debug, Clone, PartialEq)]
pub struct Seen {
    pub flow: Flow,
    pub user_id: Option<i64>,
    pub reason: Option<&'static str>,
    pub warnings: Vec<LoginWarning>,
}

#[derive(Default)]
pub struct Recorder(pub Mutex<Vec<Seen>>);

impl AuthObserver for Recorder {
    fn on_event(&self, event: &AuthEvent<'_>) {
        if let AuthEvent::Login {
            flow,
            result,
            warnings,
            ..
        } = event
        {
            self.0.lock().unwrap().push(Seen {
                flow: *flow,
                user_id: result.as_ref().ok().copied(),
                reason: result.as_ref().err().map(|e| e.reason()),
                warnings: warnings.to_vec(),
            });
        }
    }
}

impl Recorder {
    pub fn seen(&self) -> Vec<Seen> {
        self.0.lock().unwrap().clone()
    }
}

/// What the mock's entitlements endpoint answers.
#[derive(Debug, Clone)]
pub enum EntitlementsReply {
    List(Vec<MockEntitlement>),
    Fail(StatusCode),
}

impl Default for EntitlementsReply {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct MockEntitlement {
    pub id: String,
    pub sku_id: String,
    #[serde(rename = "type")]
    pub entitlement_type: i32,
    pub deleted: bool,
    pub consumed: bool,
    pub starts_at: Option<String>,
    pub ends_at: Option<String>,
}

impl MockEntitlement {
    /// A premium entitlement with `ends_at` given as an offset from now.
    pub fn premium_ending(id: &str, ends_in: chrono::Duration) -> Self {
        Self {
            ends_at: Some((chrono::Utc::now() + ends_in).to_rfc3339()),
            ..Self::premium_forever(id)
        }
    }

    /// An active premium entitlement that never ends.
    pub fn premium_forever(id: &str) -> Self {
        Self {
            id: id.into(),
            sku_id: PREMIUM_SKU.to_string(),
            entitlement_type: 8,
            deleted: false,
            consumed: false,
            starts_at: None,
            ends_at: None,
        }
    }
}

pub struct Built {
    pub state: Arc<Auth>,
    pub storage: Arc<MemoryStorage>,
    pub events: Arc<Recorder>,
}

pub fn build(api_base: &str, premium: bool) -> Built {
    let mut config = test_config(api_base);
    if premium {
        config.discord.premium = Some(PremiumConfig {
            sku_id: PREMIUM_SKU,
            bot_token: "bot-token".into(),
        });
    }
    let storage = Arc::new(MemoryStorage::new());
    let events = Arc::new(Recorder::default());
    let state = Auth::new(config, storage.clone())
        .unwrap()
        .with_observer(events.clone());
    Built {
        state: Arc::new(state),
        storage,
        events,
    }
}
