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
use catacombs::{auth::AuthenticatedUser, routes::auth_router, Auth, HasAuth, MemoryStorage};
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
        .nest("/auth", auth_router())
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
