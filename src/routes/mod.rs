//! The routes catacombs mounts, chosen by [`Flows`].

pub mod auth;
pub mod web;

use axum::{
    routing::{get, post},
    Router,
};

pub use auth::{
    exchange_code, logout, me, refresh_token, revoke_token, CodeExchangeRequest, TokenResponse,
    UserResponse,
};
pub use web::{callback, login, safe_return_to};

use crate::state::HasAuth;

/// Which login flows to mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flows {
    /// A Discord Activity or single-page app posts a code:
    /// `/exchange`, `/refresh`, `/revoke`, `/logout`.
    Activity,
    /// A website redirects through Discord: `/login`, `/callback`, `/logout`.
    Web,
    /// Both, with `/logout` mounted once.
    Both,
}

/// catacombs' routes for `flows`, to nest under a prefix such as `/auth`.
///
/// `/me` is not included, because what a user looks like belongs to the
/// host. Mount [`me`] for catacombs' basic shape, or write your own handler
/// with [`AuthenticatedUser`](crate::auth::AuthenticatedUser).
pub fn router<S: HasAuth + Clone>(flows: Flows) -> Router<S> {
    let mut router = Router::new().route("/logout", post(logout::<S>));
    if matches!(flows, Flows::Activity | Flows::Both) {
        router = router
            .route("/exchange", post(exchange_code::<S>))
            .route("/refresh", post(refresh_token::<S>))
            .route("/revoke", post(revoke_token::<S>));
    }
    if matches!(flows, Flows::Web | Flows::Both) {
        router = router
            .route("/login", get(login::<S>))
            .route("/callback", get(callback::<S>));
    }
    router
}
