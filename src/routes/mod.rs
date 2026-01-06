//! HTTP route handlers for Discord OAuth.

pub mod auth;

pub use auth::{auth_router, exchange_code, get_current_user, logout, refresh_token, revoke_token};
