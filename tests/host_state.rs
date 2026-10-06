#![cfg(feature = "memory-storage")]

mod common;

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, Request, StatusCode},
    routing::get,
    Router,
};
use catacombs::{auth::AuthenticatedUser, router, Auth, Flows, HasAuth, MemoryStorage};
use common::*;
use tower::ServiceExt;

/// RuneCast's shape: the router state is `Arc<HostState>`, and the host type
/// is not `Clone`. Under 0.1 this needed an impl the orphan rule forbids.
struct HostState {
    auth: Auth,
    greeting: &'static str,
}

impl HasAuth for HostState {
    fn auth(&self) -> &Auth {
        &self.auth
    }
}

async fn whoami(user: AuthenticatedUser, State(host): State<Arc<HostState>>) -> String {
    format!("{} {}", host.greeting, user.user_id)
}

fn app(api_base: &str) -> Router {
    let host = Arc::new(HostState {
        auth: Auth::new(test_config(api_base), MemoryStorage::new()).unwrap(),
        greeting: "hello",
    });
    Router::new()
        .nest("/auth", router(Flows::Activity))
        .route("/whoami", get(whoami))
        .with_state(host)
}

#[tokio::test]
async fn a_host_with_arc_state_mounts_the_router_and_uses_the_extractor() {
    let (base, _rec) = spawn_mock_discord().await;
    let app = app(&base);

    let resp = app
        .clone()
        .oneshot(post_json("/auth/exchange", r#"{"code":"good-code"}"#))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let jwt = access_token(resp).await;

    let resp = app
        .oneshot(
            Request::get("/whoami")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, format!("hello {MOCK_USER_ID}"));
}

#[tokio::test]
async fn the_extractor_refuses_a_request_without_a_token() {
    let (base, _rec) = spawn_mock_discord().await;
    let resp = app(&base)
        .oneshot(Request::get("/whoami").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// CrackTunes' shape: a plain `Clone` state, with no `Arc` around the host.
#[derive(Clone)]
struct WebHost {
    auth: Arc<Auth>,
}

impl HasAuth for WebHost {
    fn auth(&self) -> &Auth {
        &self.auth
    }
}

async fn web_whoami(user: AuthenticatedUser) -> String {
    user.user_id.to_string()
}

#[tokio::test]
async fn a_host_with_plain_clone_state_mounts_the_web_router_and_uses_the_extractor() {
    let host = WebHost {
        auth: Arc::new(Auth::new(test_config("http://127.0.0.1:1"), MemoryStorage::new()).unwrap()),
    };
    let jwt =
        catacombs::auth::generate_token(7, "someone", &host.auth.config().security.jwt_secret)
            .unwrap();
    let app = Router::new()
        .nest("/auth", router(Flows::Web))
        .route("/whoami", get(web_whoami))
        .with_state(host);

    let resp = app
        .clone()
        .oneshot(Request::get("/auth/login").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let resp = app
        .clone()
        .oneshot(Request::get("/whoami").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let resp = app
        .oneshot(
            Request::get("/whoami")
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_string(resp).await, "7");
}
