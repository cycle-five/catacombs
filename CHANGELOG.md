# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - Unreleased

The host seam: catacombs now plugs into an application's own state,
storage and metrics. See "Upgrading from 0.1" in the README.

### Added

- `HasAuth`, implemented for `Arc<T>`, so a router whose state is
  `Arc<YourState>` can use catacombs' routes and extractor.
- `AuthObserver`: one `AuthEvent::Login` per attempt, with the flow, the
  user or `LoginError::reason()`, the elapsed time and warnings.
- `LoginError` and `Rejection`.
- `DiscordProfile` (with banner and accent colour) and `GuildProfile`.
  `/exchange` accepts `guild_id` and stores the user's profile in that guild.
- `router(Flows::Activity | Web | Both)`.
- `encryption::generate_key` and `encryption::validate_key`.

### Changed

- `AppState` is now `Auth`. `Auth::new` returns an error for an encryption
  key that is not 32 base64 bytes.
- One `Storage` trait replaces `UserStorage` and `EntitlementStorage`. It
  takes no encryption key: catacombs encrypts, and storage only sees
  `EncryptedToken`. `MemoryStorage` no longer holds refresh tokens in
  plaintext.
- `/me` is no longer mounted by the router. `routes::me` remains for hosts
  that want it.
- Discord unreachable, or failing on its side, is 502, not 401.
- A user without a custom avatar has `avatar_url: None`, not Discord's
  default-avatar URL.
- Premium is reconciled from entitlements on every login. Premium from
  Discord ends when its entitlement does. Manual and external premium is
  never removed, and a Discord grant does not replace one that is still active
  and lasts at least as long. A Discord grant that outlasts it does replace it.
  An entitlements outage, or an entitlement that cannot be read (a malformed
  SKU id, or a malformed id on the premium SKU), changes nothing and raises
  `LoginWarning::EntitlementsUnavailable`.
- Discord requests use a default HTTP client with a 15 second timeout (it
  had none). `Auth::with_http_client` replaces it.
- `Debug` for `Config`'s parts no longer prints secrets, and
  `encryption::encrypt` and `decrypt` are crate-private.
- An unrecognised stored subscription source reads as `Manual`, not `Discord`.
- `StorageError` is `#[non_exhaustive]`.
- `SqlxStorage` uses `catacombs_users`, `catacombs_entitlements` and
  `catacombs_guild_profiles`, from a timestamp-versioned migration, and
  `migrate()` tolerates a host's own migrations. It needs PostgreSQL 14+.
- `DISCORD_PREMIUM_SKU_ID` that is not a number is now an error.

### Fixed

- `Cargo.toml` listed the category `api`, which crates.io does not have, so
  publishing v0.1.1 was refused (400). It is now
  `web-programming::http-server`.

### Removed

- `ServerConfig` (and `HOST`/`PORT` in `from_env`). `DiscordConfig.bot_token`
  and `premium_sku_id` moved into `premium: Option<PremiumConfig>`, and the
  bot token is only required with a SKU.
- `SharedState`, `auth_router`, `UserUpsertParams`, `storage_error`.
- `error::Error` and `error::Result` (nothing used them).

## [0.1.1] - 2026-10-04

### Fixed

- CI's Clippy job failed on Rust 1.99, whose new `double_must_use` lint fires
  inside the code that `async-trait` 0.1.89 generates. The lockfile now has
  `async-trait` 0.1.92, which does not trip it.

### Changed

- MSRV is 1.89, because `uuid` 1.27 requires it.
- Published to crates.io. The package leaves out CI and local-dev files, and
  docs.rs builds the docs with every feature enabled.

## [0.1.0] - 2026-09-30

### Added

- Website flow: `GET /login?return_to=` redirects to Discord with an OAuth
  `state`; `GET /callback` checks it, completes the login and sets an HttpOnly,
  `SameSite=Lax` session cookie holding the JWT, then returns the user to
  `return_to` (same-site paths only).
- `WebConfig` (`Config.web`): scopes, session cookie name, `Secure` flag.
- `DiscordConfig.api_base` (`DISCORD_API_BASE`), so tests can use a local mock.

### Changed

- `Config.web` and `DiscordConfig.api_base` are new fields, so code building
  these structs by literal must add `web: WebConfig::default()` and
  `api_base: catacombs::config::default_api_base()`.
- The `AuthenticatedUser` extractor reads the session cookie first, then the
  `Authorization` header, then `?token=`.
- `POST /logout` always returns 204 and deletes the session cookie; it clears
  stored tokens only when the caller is authenticated (it used to 401).
- MSRV is 1.88. Unused dependencies (`oauth2`, `dotenvy`, `tower`,
  `tower-http`, `tracing-subscriber`, axum `ws`) are gone.
- A tag without a `CRATES_IO_TOKEN` secret makes a GitHub release and skips
  crates.io.

## [0.0.1] - 2025-01-07

### Added

- Initial release
- Discord OAuth2 authentication with code exchange, token refresh, and revocation
- User management with subscription support (free/premium tiers)
- Discord entitlements API integration for monetization
- Feature-flagged storage backends:
  - `sqlx-storage` (default): PostgreSQL via SQLx
  - `memory-storage`: In-memory HashMap for testing
- Feature-flagged TLS backends:
  - `rustls-tls` (default): Pure Rust TLS implementation
  - `native-tls`: System OpenSSL/native TLS
- JWT authentication with Axum extractor
- AES-256-GCM encryption for refresh token storage at rest
- Axum router with auth endpoints (`/exchange`, `/refresh`, `/revoke`, `/logout`, `/me`)

[Unreleased]: https://github.com/cycle-five/catacombs/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/cycle-five/catacombs/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/cycle-five/catacombs/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/cycle-five/catacombs/releases/tag/v0.1.0
[0.0.1]: https://github.com/cycle-five/catacombs/releases/tag/v0.0.1
