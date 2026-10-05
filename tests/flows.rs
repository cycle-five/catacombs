#![cfg(feature = "memory-storage")]

mod common;

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    routing::get,
    Router,
};
use catacombs::{router, routes::me, Auth, Flows};
use common::*;
use tower::ServiceExt;

async fn status(app: Router, method: Method, uri: &str) -> StatusCode {
    let req = if method == Method::POST {
        post_json(uri, "{}")
    } else {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    };
    app.oneshot(req).await.unwrap().status()
}

fn app(flows: Flows) -> Router {
    router(flows).with_state(test_state("http://127.0.0.1:1"))
}

#[tokio::test]
async fn activity_mounts_no_web_routes() {
    assert_eq!(
        status(app(Flows::Activity), Method::GET, "/login").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(app(Flows::Activity), Method::GET, "/callback").await,
        StatusCode::NOT_FOUND
    );
    // Mounted: an empty body is refused for missing `code`, not 404.
    assert_eq!(
        status(app(Flows::Activity), Method::POST, "/exchange").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn web_mounts_no_activity_routes() {
    for uri in ["/exchange", "/refresh", "/revoke"] {
        assert_eq!(
            status(app(Flows::Web), Method::POST, uri).await,
            StatusCode::NOT_FOUND,
            "{uri}"
        );
    }
    assert_eq!(
        status(app(Flows::Web), Method::GET, "/login").await,
        StatusCode::SEE_OTHER
    );
}

#[tokio::test]
async fn both_mounts_everything_and_logout_once() {
    assert_eq!(
        status(app(Flows::Both), Method::GET, "/login").await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        status(app(Flows::Both), Method::POST, "/exchange").await,
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        status(app(Flows::Both), Method::POST, "/logout").await,
        StatusCode::NO_CONTENT
    );
}

#[tokio::test]
async fn me_is_mounted_only_by_the_host() {
    assert_eq!(
        status(app(Flows::Both), Method::GET, "/me").await,
        StatusCode::NOT_FOUND
    );
    let with_me = router(Flows::Both)
        .route("/me", get(me::<Arc<Auth>>))
        .with_state(test_state("http://127.0.0.1:1"));
    assert_eq!(
        status(with_me, Method::GET, "/me").await,
        StatusCode::UNAUTHORIZED
    );
}
