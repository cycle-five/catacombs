# Catacombs

[![CI](https://github.com/cycle-five/catacombs/actions/workflows/ci.yml/badge.svg)](https://github.com/cycle-five/catacombs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<!-- Opening prose goes here. -->

## What it does

Catacombs adds "Log in with Discord" to a Rust web service built on axum. It
runs the OAuth2 exchange with Discord, remembers who has signed in, and gives
your handlers an `AuthenticatedUser` so they never touch a token themselves.
If you sell a premium tier through Discord, it can also record each user's
entitlements when they log in.

There are two ways to log in. A Discord Activity or a single-page app that
already has an authorization code posts it to `/auth/exchange` and gets a JWT
back. A normal website sends people to `/auth/login` instead. Catacombs
redirects them to Discord, checks the `state` that comes back, sets an HttpOnly
session cookie, and returns them to the page they started from. CrackTunes'
web dashboard signs in this second way.

## Using it

```toml
[dependencies]
catacombs = "0.2"
```

By default it keeps users in PostgreSQL through SQLx and uses rustls for TLS.
The `memory-storage` feature swaps the database for an in-process map, which
suits tests and small services that can afford to forget everyone on a
restart. Memory storage holds refresh tokens encrypted, like any storage; a
per-process key from `catacombs::encryption::generate_key()` is enough, since
nothing outlives the process. The database storage needs PostgreSQL 14 or
newer. The `native-tls` feature uses the system's OpenSSL in place of rustls. To use either one, turn
off the default features and name both a storage and a TLS feature, for
example `default-features = false, features = ["memory-storage", "rustls-tls"]`.

Mounting the router is most of the work:

```rust
use std::sync::Arc;
use catacombs::{router, Auth, Config, Flows, HasAuth, SqlxStorage};

struct AppState { auth: Auth /* , your own fields */ }
impl HasAuth for AppState {
    fn auth(&self) -> &Auth { &self.auth }
}

let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
let storage = SqlxStorage::new(pool);
storage.migrate().await?;
let auth = Auth::new(Config::from_env()?, storage)?;

let app = axum::Router::new()
    .nest("/auth", router(Flows::Activity))
    .with_state(Arc::new(AppState { auth }));
```

`Auth::new` checks the encryption key and returns an error if it is not 32
base64 bytes. `Flows` picks which routes are mounted: `Activity` for
`/exchange`, `/refresh` and `/revoke`, `Web` for `/login` and `/callback`, or
`Both`. `/logout` is always mounted.

`Config::from_env` reads the settings below, and `.env.example` has the full
set with comments. `DATABASE_URL` is only read by the snippet above.
`DISCORD_PREMIUM_SKU_ID` is optional, and entitlements are only fetched when it
is set. The bot token is only required with a SKU.

```bash
DISCORD_CLIENT_ID=...
DISCORD_CLIENT_SECRET=...
DISCORD_BOT_TOKEN=...
DISCORD_REDIRECT_URI=https://example.com/auth/callback
JWT_SECRET=...
ENCRYPTION_KEY=...             # openssl rand -base64 32
DISCORD_PREMIUM_SKU_ID=...     # optional
```

In a handler, ask for an `AuthenticatedUser`, and requests without a valid
session are turned away before they reach your code:

```rust
use catacombs::auth::AuthenticatedUser;

async fn hello(user: AuthenticatedUser) -> String {
    format!("Hello, {}!", user.username)
}
```

The extractor looks for the session cookie first, then an
`Authorization: Bearer` header, and finally a `?token=` query parameter. That
last one is for WebSocket clients, which can't set headers.

For the website flow, register `<your origin>/auth/callback` as a redirect in
the Discord developer portal, and set `DISCORD_REDIRECT_URI` to the same URL.
Then link people to `/auth/login?return_to=/where/next`. Only same-site paths
are accepted for `return_to`. `POST /auth/logout` signs someone out. Scopes,
the cookie's name and its `Secure` flag live in `WebConfig`.

The session cookie is `SameSite=Lax`. That keeps other sites out, but not your
own subdomains. Host the site on a domain whose subdomains you control, and
have your own state-changing endpoints check `Origin` or require a JSON body.

The rest of the router refreshes and revokes Discord tokens. It does not mount
`/me`; `catacombs::routes::me` is there if you want to route it yourself. The
rustdoc covers each route.

## Your own users table

If your application already has a users table, implement `Storage` on a
newtype around your pool instead of using `SqlxStorage`. It has five methods:
`get_user`, `upsert_user`, `set_tokens`, `set_subscription` and
`upsert_entitlement`. Tokens arrive as ciphertext in `StoredTokens`. Persist
`refresh_token.as_str()` and read it back with `EncryptedToken::from_stored`;
the storage never sees a key. `upsert_user` merges `profile.guilds` into what is
already stored and never deletes guilds.

## Metrics

`Auth::with_observer` takes an `AuthObserver`, which is called once per login
attempt with an `AuthEvent::Login`. The event carries the flow, the user or
`LoginError::reason()`, the elapsed time and any warnings.

## Guild profiles

To read a user's profile in a guild, such as their server nickname, send
`guild_id` to `/exchange` and request the `guilds.members.read` scope. Profiles
accumulate in storage across logins.

## Upgrading from 0.1

- `AppState` became `Auth`, built with `Auth::new(config, storage)?` (it checks
  the encryption key); implement `HasAuth` instead of `FromRef`.
- `auth_router()` became `router(Flows::...)`, and `/me` is no longer mounted
  (`routes::me` is still available).
- `UserStorage` and `EntitlementStorage` became `Storage`.
- `ServerConfig` was removed, and `bot_token` and `premium_sku_id` became
  `premium: Option<PremiumConfig>`.
- `SqlxStorage` uses `catacombs_*` tables; data in 0.1's `users` and
  `entitlements` tables is not migrated.
- `User.refresh_token` and `User.token_expires_at` became `User.tokens`.

## Working on it

You need Rust 1.89 or newer, and no database: the integration tests run
against memory storage and a mock Discord. CI builds and tests three feature
sets, so when you change anything feature-gated, run all three:

```bash
cargo test
cargo test --no-default-features --features "memory-storage,rustls-tls"
cargo test --no-default-features --features "sqlx-storage,native-tls"
```

Where things are going next is in [ROADMAP.md](ROADMAP.md), and what has
changed is in [CHANGELOG.md](CHANGELOG.md).

<!-- Closing prose goes here. -->

## License

MIT. See [LICENSE](LICENSE).
