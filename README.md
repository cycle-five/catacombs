# Catacombs

[![CI](https://github.com/cycle-five/catacombs/actions/workflows/ci.yml/badge.svg)](https://github.com/cycle-five/catacombs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Discord OAuth2 library for Rust with user management and subscription support. Built on Axum, SQLx, and Tokio with rustls by default.

## Features

- **Discord OAuth2** - Complete OAuth2 flow with code exchange, token refresh, and revocation
- **User Management** - Store and manage Discord users with subscription tiers
- **Discord Entitlements** - Integrate with Discord's monetization API for premium features
- **Feature-flagged Storage** - Choose between PostgreSQL (SQLx) or in-memory storage
- **Feature-flagged TLS** - Choose between rustls (default) or native-tls (OpenSSL)
- **Secure Token Storage** - Refresh tokens encrypted at rest with AES-256-GCM
- **Axum Integration** - Ready-to-use router and authentication extractors

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
catacombs = { git = "https://github.com/cycle-five/catacombs", tag = "v0.1.0" }
```

catacombs is not published to crates.io yet.

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `sqlx-storage` | Yes | PostgreSQL storage via SQLx |
| `memory-storage` | No | In-memory storage for testing |
| `rustls-tls` | Yes | Pure Rust TLS (no system dependencies) |
| `native-tls` | No | System OpenSSL/native TLS |

#### Examples

```toml
# Default (PostgreSQL + rustls)
catacombs = { git = "https://github.com/cycle-five/catacombs", tag = "v0.1.0" }

# Memory storage for testing
catacombs = { git = "https://github.com/cycle-five/catacombs", tag = "v0.1.0", default-features = false, features = ["memory-storage", "rustls-tls"] }

# PostgreSQL with native TLS
catacombs = { git = "https://github.com/cycle-five/catacombs", tag = "v0.1.0", default-features = false, features = ["sqlx-storage", "native-tls"] }
```

## Quick Start

```rust
use catacombs::{AppState, Config, SqlxStorage, routes};
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    // Load configuration from environment
    let config = Config::from_env()?;

    // Set up PostgreSQL storage
    let pool = sqlx::PgPool::connect(&std::env::var("DATABASE_URL")?).await?;
    let storage = SqlxStorage::new(pool);
    storage.migrate().await?;

    // Create application state
    let state = Arc::new(AppState::new(config, storage));

    // Build Axum router with auth routes
    let app = axum::Router::new()
        .nest("/auth", routes::auth_router())
        .with_state(state);

    // Start server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;

    Ok(())
}
```

## Configuration

Set the following environment variables (see `.env.example`):

```bash
# Required
DATABASE_URL=postgresql://postgres:password@localhost:5432/catacombs
DISCORD_CLIENT_ID=your_client_id
DISCORD_CLIENT_SECRET=your_client_secret
DISCORD_BOT_TOKEN=your_bot_token
DISCORD_REDIRECT_URI=http://localhost:3000/auth/callback
JWT_SECRET=your_jwt_secret
ENCRYPTION_KEY=your_base64_encoded_32_byte_key  # Generate with: openssl rand -base64 32

# Optional
DISCORD_PREMIUM_SKU_ID=your_sku_id  # For Discord monetization
HOST=0.0.0.0
PORT=3000
```

## API Endpoints

The `auth_router()` provides these endpoints:

| Method | Path | Description |
|--------|------|-------------|
| POST | `/exchange` | Exchange Discord auth code for tokens |
| POST | `/refresh` | Refresh OAuth tokens |
| POST | `/revoke` | Revoke tokens with Discord |
| POST | `/logout` | Delete the session cookie and clear local tokens (always 204) |
| GET | `/me` | Get current user info |
| GET | `/login` | Start the website flow (redirect to Discord) |
| GET | `/callback` | Finish the website flow (sets the session cookie) |

## Authentication

Use the `AuthenticatedUser` extractor in your handlers:

```rust
use catacombs::auth::AuthenticatedUser;

async fn protected_handler(user: AuthenticatedUser) -> String {
    format!("Hello, {}!", user.username)
}
```

Reads the token from, in order:
- the session cookie (set by the website flow)
- `Authorization: Bearer <token>` header
- `?token=<token>` query parameter (useful for WebSocket connections)

## Website flow

For a site (not a Discord Activity), catacombs can log users in with a browser
redirect and keep them logged in with a cookie:

- Mount `auth_router()` at `/auth`.
- Set `DISCORD_REDIRECT_URI` to `https://<site>/auth/callback` and register the
  same URL in the Discord developer portal. When the router is mounted at
  `/auth`, it must be exactly `<public origin>/auth/callback`.
- Link users to `/auth/login?return_to=/where/next`. After Discord approves,
  `/auth/callback` checks the OAuth `state`, sets the session cookie and sends
  the user to `return_to` (same-site paths only).
- Protect handlers with the `AuthenticatedUser` extractor.
- `POST /auth/logout` signs out: it deletes the cookie and clears stored tokens.
- The session is a `SameSite=Lax`, HttpOnly cookie, so state-changing endpoints
  should additionally require a JSON content type or check `Origin`.

## Development

### Prerequisites

- Rust 1.88.0 or later
- Docker and Docker Compose (for local PostgreSQL)

### Setup

```bash
# Clone the repository
git clone https://github.com/cycle-five/catacombs.git
cd catacombs

# Start PostgreSQL
docker compose up -d

# Copy environment template
cp .env.example .env
# Edit .env with your Discord credentials

# Run tests
cargo test

# Run tests with memory storage
cargo test --no-default-features --features "memory-storage,rustls-tls"
```

### Running Tests

```bash
# All tests with default features
cargo test

# With memory storage
cargo test --no-default-features --features "memory-storage,rustls-tls"

# With native TLS
cargo test --no-default-features --features "sqlx-storage,native-tls"
```

## License

MIT License - see [LICENSE](LICENSE) for details.
