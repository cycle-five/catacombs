//! The website flow: a browser redirect to Discord and back, ending in a
//! session cookie. The SDK flow (`POST /exchange`) is untouched.

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::Redirect,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::Engine;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::{auth::SESSION_TTL_SECS, config::WebConfig, routes::auth::complete_login, HasAuth};

/// Discord's authorize page (not the REST API base).
pub const AUTHORIZE_URL: &str = "https://discord.com/oauth2/authorize";
/// Holds the OAuth `state` between `/login` and `/callback`.
pub const STATE_COOKIE: &str = "catacombs_oauth_state";
/// Holds where to send the user after `/callback`.
pub const RETURN_COOKIE: &str = "catacombs_return_to";
/// How long a login may take before its state cookie expires.
const LOGIN_TTL_SECS: i64 = 10 * 60;

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub return_to: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// Discord sets this (e.g. `access_denied`) when the user cancels.
    pub error: Option<String>,
}

#[derive(Serialize)]
struct AuthorizeParams<'a> {
    response_type: &'a str,
    client_id: &'a str,
    scope: &'a str,
    state: &'a str,
    redirect_uri: &'a str,
}

/// Where a login may send the user back to: a path on this site, or `/`.
///
/// Rejects anything a browser could read as another origin: absolute URLs,
/// protocol-relative `//host`, and backslashes (`/\host` is `//host` to
/// browsers). Rejects control characters, which could split a header.
pub fn safe_return_to(raw: Option<&str>) -> String {
    match raw {
        Some(p)
            if p.starts_with('/')
                && !p.starts_with("//")
                && !p.contains('\\')
                && !p.chars().any(char::is_control) =>
        {
            p.to_owned()
        }
        _ => "/".to_owned(),
    }
}

/// Compare without an early exit, so timing does not reveal a prefix match.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn short_cookie(web: &WebConfig, name: &'static str, value: String) -> Cookie<'static> {
    Cookie::build((name, value))
        .http_only(true)
        .secure(web.secure_cookies)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(LOGIN_TTL_SECS))
        .build()
}

/// The session cookie holding `jwt`.
pub(crate) fn session_cookie(web: &WebConfig, jwt: String) -> Cookie<'static> {
    Cookie::build((web.cookie_name.clone(), jwt))
        .http_only(true)
        .secure(web.secure_cookies)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(cookie::time::Duration::seconds(SESSION_TTL_SECS))
        .build()
}

/// A cookie that, passed to `CookieJar::remove`, deletes `name` at `/`.
///
/// It carries the same `Secure`/`HttpOnly`/`SameSite` attributes as the cookie
/// it deletes: browsers reject a `__Host-`/`__Secure-` `Set-Cookie` without
/// `Secure`, deletions included.
pub(crate) fn removal(web: &WebConfig, name: String) -> Cookie<'static> {
    Cookie::build((name, ""))
        .http_only(true)
        .secure(web.secure_cookies)
        .same_site(SameSite::Lax)
        .path("/")
        .build()
}

/// `GET /login?return_to=/path` — start a login.
pub async fn login<S: HasAuth + Clone>(
    State(state): State<S>,
    jar: CookieJar,
    Query(q): Query<LoginQuery>,
) -> (CookieJar, Redirect) {
    let auth = state.auth();
    let csrf = random_state();
    let return_to = safe_return_to(q.return_to.as_deref());
    let scope = auth.config().web.scopes.join(" ");
    let params = serde_urlencoded::to_string(AuthorizeParams {
        response_type: "code",
        client_id: &auth.config().discord.client_id,
        scope: &scope,
        state: &csrf,
        redirect_uri: &auth.config().discord.redirect_uri,
    })
    .expect("authorize params are plain strings");
    let web = &auth.config().web;
    let jar = jar
        .add(short_cookie(web, STATE_COOKIE, csrf))
        .add(short_cookie(web, RETURN_COOKIE, return_to));
    (jar, Redirect::to(&format!("{AUTHORIZE_URL}?{params}")))
}

/// `GET /callback?code&state` — finish a login.
pub async fn callback<S: HasAuth + Clone>(
    State(state): State<S>,
    jar: CookieJar,
    Query(q): Query<CallbackQuery>,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let auth = state.auth();
    let expected = jar.get(STATE_COOKIE).map(|c| c.value().to_owned());
    // Validated again here: the cookie could have been planted.
    let return_to = safe_return_to(jar.get(RETURN_COOKIE).map(Cookie::value));
    let jar = jar
        .remove(removal(&auth.config().web, STATE_COOKIE.to_owned()))
        .remove(removal(&auth.config().web, RETURN_COOKIE.to_owned()));

    if let Some(error) = q.error {
        // The user cancelled on Discord. Back where they were, logged out.
        tracing::info!("Discord login not completed: {error:?}");
        return Ok((jar, Redirect::to(&return_to)));
    }

    let (Some(code), Some(got), Some(expected)) = (q.code, q.state, expected) else {
        tracing::warn!("callback without code, state or state cookie");
        return Err(StatusCode::BAD_REQUEST);
    };
    if !constant_time_eq(got.as_bytes(), expected.as_bytes()) {
        tracing::warn!("callback state mismatch");
        return Err(StatusCode::BAD_REQUEST);
    }

    let login = complete_login(auth, &code).await?;
    let jar = jar.add(session_cookie(&auth.config().web, login.jwt));
    Ok((jar, Redirect::to(&return_to)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_same_site_paths_survive() {
        let cases: &[(Option<&str>, &str)] = &[
            (Some("/g/123"), "/g/123"),
            (Some("/g/123?x=1#y"), "/g/123?x=1#y"),
            (Some("/"), "/"),
            (None, "/"),
            (Some(""), "/"),
            (Some("g/123"), "/"),
            (Some("//evil.example"), "/"),
            (Some("/\\evil.example"), "/"),
            (Some("https://evil.example/"), "/"),
            (Some("/a\r\nSet-Cookie: x=y"), "/"),
            (Some("/a\\b"), "/"),
        ];
        for (raw, want) in cases {
            assert_eq!(safe_return_to(*raw), *want, "input {raw:?}");
        }
    }

    #[test]
    fn constant_time_eq_compares_content_and_length() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
    }
}
