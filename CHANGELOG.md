# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/cycle-five/catacombs/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/cycle-five/catacombs/releases/tag/v0.0.1
