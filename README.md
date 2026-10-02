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

Catacombs is not on crates.io yet, so depend on it by git tag:

```toml
[dependencies]
catacombs = { git = "https://github.com/cycle-five/catacombs", tag = "v0.1.0" }
```

By default it keeps users in PostgreSQL through SQLx and uses rustls for TLS.
The `memory-storage` feature swaps the database for an in-process map, which
suits tests and small services that can afford to forget everyone on a
restart. Be aware that memory storage keeps Discord refresh tokens in
plaintext, while the database encrypts them with AES-256-GCM. The `native-tls`
feature uses the system's OpenSSL in place of rustls. To use either one, turn
off the default features and name both a storage and a TLS feature, for
example `default-features = false, features = ["memory-storage", "rustls-tls"]`.

Mounting the router is most of the work:

```rust
use catacombs::{routes, AppState, Config, SqlxStorage};
use std::sync::Arc;

let config = Config::from_env()?;
let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
let storage = SqlxStorage::new(pool);
storage.migrate().await?;

let app = axum::Router::new()
    .nest("/auth", routes::auth_router())
    .with_state(Arc::new(AppState::new(config, storage)));
```

`Config::from_env` reads the settings below, and `.env.example` has the full
set with comments. `DATABASE_URL` is only read by the snippet above.
`DISCORD_PREMIUM_SKU_ID` is optional, and entitlements are only fetched when it
is set.

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

The rest of the router refreshes and revokes Discord tokens, and returns the
current user from `/auth/me`. The rustdoc covers each route.

## Working on it

You need Rust 1.88 or newer, and no database: the integration tests run
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
