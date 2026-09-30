# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-30

### Added

- Website flow: `GET /login?return_to=` redirects to Discord with an OAuth
  `state`; `GET /callback` checks it, completes the login and sets an HttpOnly,
  `SameSite=Lax` session cookie holding the JWT, then returns the user to
  `return_to` (same-site paths only).
- `WebConfig` (`Config.web`): scopes, session cookie name, `Secure` flag.
- `DiscordConfig.api_base` (`DISCORD_API_BASE`), so tests can use a local mock.

### Changed

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

[Unreleased]: https://github.com/cycle-five/catacombs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/cycle-five/catacombs/releases/tag/v0.1.0
[0.0.1]: https://github.com/cycle-five/catacombs/releases/tag/v0.0.1
