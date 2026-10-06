# catacombs 0.2.0: the host seam

**Status:** design approved in conversation, 2026-10-05. This file is the
written spec for review.

## Why

catacombs began as RuneCast's `routes/auth.rs`, lifted out and cleaned up.
CrackTunes' web dashboard now signs in through it. RuneCast still carries its
own copy, about 1,650 lines, and cannot switch: parts of the seam between
catacombs and a host application cannot be bridged from the host's side.

The goal of 0.2.0 is a seam that RuneCast and CrackTunes both plug into
cleanly, with RuneCast deleting most of its auth code and CrackTunes changing
a few lines.

"General" means general across *these projects and the next ones like them*:
Discord Activities, bots with a web side, small dashboards. Strangers on
crates.io are welcome, but they come second. catacombs stays opinionated and
offers exactly the extension points these hosts need.

One rule decides what belongs where: **catacombs owns the login lifecycle;
the host owns what a user looks like.**

## What already lines up

These need no change, and the migration depends on them staying that way.

- RuneCast's auth routes have the same paths as catacombs':
  `/auth/exchange`, `/me`, `/refresh`, `/revoke`, `/logout`.
- The JWT claims are the same: `sub`, `username`, `exp`. Existing sessions
  stay valid across the switch.
- `encryption.rs` is identical in both repositories. Refresh tokens already
  in RuneCast's database stay readable.
- The entitlement logic and the shape of the `discord_entitlements` table
  are the same.
- `TokenResponse` has the same fields: `access_token` and
  `discord_access_token`.

## The gaps this release closes

1. **The extractor cannot be used in RuneCast.** catacombs' `AuthenticatedUser`
   requires `Arc<catacombs::AppState>: FromRef<S>`. RuneCast's router state is
   `Arc<AppState>`, and the orphan rule forbids RuneCast from writing that impl
   (E0117, confirmed with a compile test). CrackTunes only works because its
   router state is a local struct.
2. **Storage is shaped for catacombs' schema.** `SqlxStorage` creates its own
   `users` table, which would collide with RuneCast's. A host must implement
   the storage traits itself, and those traits pass `encryption_key: &str`
   into every call.
3. **Discord's profile is private.** catacombs parses `/users/@me` into a
   private struct and keeps a fixed set of fields. RuneCast's `banner_url`
   and `accent_color` have nowhere to go.
4. **Login failures are opaque.** RuneCast records a Prometheus failure reason
   and duration for every login, and answers 502 when Discord is unreachable.
   catacombs turns every failure into a bare `StatusCode` and a log line.
5. **`/me` is app-specific.** RuneCast's `/me` adds an admin flag, an avatar
   decoration, a sandbox gate and a premium override. catacombs' router
   bundles its own `/me`, which neither host uses.
6. **Both login flows are always mounted.** RuneCast uses only the Activity
   flow and CrackTunes only the web flow, so each exposes routes it never
   uses.
7. **`Config` asks for things catacombs never uses.** It never reads
   `ServerConfig`; it is only filled by `from_env`. `bot_token` is required
   although it is only used to fetch entitlements.

## Design

### 1. Host state: `Auth` and `HasAuth`

`AppState` is renamed to `Auth`. It is catacombs' piece of the host's state
(config, storage, HTTP client, observer), not the application's state. The
rename removes a name clash, since both hosts already have an `AppState`.

```rust
pub trait HasAuth: Send + Sync + 'static {
    fn auth(&self) -> &Auth;
}
impl HasAuth for Auth {
    fn auth(&self) -> &Auth { self }
}
impl<T: HasAuth> HasAuth for Arc<T> {
    fn auth(&self) -> &Auth { (**self).auth() }
}
```

Because catacombs provides the `Arc<T>` impl, a host implements `HasAuth` on
its own state type, which the orphan rule allows, and `Arc<HostState>` is
covered automatically.

The extractor and the router are generic over the host's state and do not
use axum's `FromRef`:

- `impl<S: HasAuth> FromRequestParts<S> for AuthenticatedUser`. It reads the
  session cookie, then `Authorization: Bearer`, then `?token=`, as it does
  today, and it reads only the JWT secret and the cookie name.
- `pub fn router<S: HasAuth + Clone>(flows: Flows) -> Router<S>`. The host
  nests it inside its own router. There is no second state type and no
  separate `with_state`.

Construction:

```rust
let auth = Auth::new(config, storage)
    .with_http_client(client)   // optional
    .with_observer(metrics);    // optional, see section 3
```

### 2. Storage

#### One trait

The current `UserStorage`, `EntitlementStorage` and blanket `Storage` become
one trait with five methods. No host implements one half without the other.

```rust
#[async_trait]
pub trait Storage: Send + Sync + 'static {
    async fn get_user(&self, user_id: i64) -> Result<Option<User>, StorageError>;
    async fn upsert_user(
        &self,
        profile: &DiscordProfile,
        tokens: Option<&StoredTokens>,
    ) -> Result<(), StorageError>;
    /// `None` clears the tokens (logout).
    async fn set_tokens(&self, user_id: i64, tokens: Option<&StoredTokens>) -> Result<(), StorageError>;
    /// `None` resets the user to the free tier.
    async fn set_subscription(&self, user_id: i64, sub: Option<&Subscription>) -> Result<(), StorageError>;
    async fn upsert_entitlement(&self, entitlement: &Entitlement) -> Result<(), StorageError>;
}
```

`Subscription` is `{ tier, source, expires_at }`. `Entitlement` holds the
fields that `EntitlementUpsertParams` holds today. `User` is catacombs'
summary of a stored user, the fields its own routes and the default `/me`
need. Its `refresh_token: Option<String>` becomes `tokens: Option<StoredTokens>`.

#### Encryption belongs to catacombs

Storage only ever sees ciphertext.

```rust
pub struct StoredTokens {
    pub refresh_token: EncryptedToken,
    pub expires_at: DateTime<Utc>,
}

/// Ciphertext of a Discord refresh token. Only catacombs can encrypt
/// plaintext into one or decrypt one. Storage persists it as a string.
pub struct EncryptedToken(String);
impl EncryptedToken {
    pub fn as_str(&self) -> &str;
    /// For storage reading a value back. No validation; decryption fails
    /// later if the value is not catacombs ciphertext.
    pub fn from_stored(s: String) -> Self;
}
```

- `encryption_key` leaves every trait method. A storage implementation cannot
  forget to encrypt.
- `MemoryStorage` stops holding plaintext refresh tokens. CrackTunes'
  dashboard runs on it in production, and the README's warning goes away.
- Identity-only logins, a roadmap item, follow for free: `tokens: None`
  stores nothing. A `WebConfig` option to choose this is out of scope here.
- The ciphertext format does not change, so tokens already stored by RuneCast
  decrypt correctly.

#### The Discord profile

```rust
#[non_exhaustive]
pub struct DiscordProfile {
    pub id: i64,
    pub username: String,
    pub global_name: Option<String>,
    pub avatar_url: Option<String>,   // CDN URL, already built
    pub banner_url: Option<String>,   // CDN URL, already built
    pub accent_color: Option<i32>,
    /// Guilds this login fetched a member profile for: usually zero or one.
    pub guilds: BTreeMap<GuildId, GuildProfile>,
}

#[non_exhaustive]
pub struct GuildProfile {
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,   // the per-guild avatar
    pub banner_url: Option<String>,   // the per-guild banner
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct GuildId(pub i64);
```

`GuildId` deserializes from a JSON string as well as a number, because
Discord and the Activity SDK send snowflakes as strings.
`#[non_exhaustive]` lets later releases add Discord fields without breaking
hosts. `user_id` stays a bare `i64`. A `UserId` newtype is out of scope.

#### Guild profiles, filled in over time

Discord has no call that returns a user's member profile in every guild.
`GET /users/@me/guilds/{guild_id}/member` returns one guild at a time, is
rate limited, and needs the `guilds.members.read` scope. So catacombs fetches
profiles only for the guilds a login names, and storage accumulates them
across logins.

- `/exchange` accepts an optional `guild_id`:
  `{ "code": "...", "guild_id": "123" }`. An Activity has it from the SDK. A
  request without it gets an empty map, so the change is wire-compatible.
- The web flow fetches no guild profiles in this release.
- A guild fetch that fails, including for a missing scope, leaves that guild
  out of the map and does not fail the login. The observer reports it as a
  warning.
- `upsert_user` **merges**. It writes the guilds in the map and leaves other
  stored guilds alone. Over time a host holds a profile for every guild the
  user has used the app in.

The full list of a user's guild IDs (`GET /users/@me/guilds`, `guilds`
scope) is not needed for this and is out of scope. It would support a future
"a server you are in plays this" feature, and can be added then.

#### Errors

`StorageError` gains `Backend(Box<dyn std::error::Error + Send + Sync>)`, so
a host's `sqlx::Error` converts without being flattened into a string.

#### `SqlxStorage`

It stays, for new projects without a users table of their own. While nothing
uses it:

- its tables are renamed `catacombs_users` and `catacombs_entitlements`, and a
  `catacombs_guild_profiles` table is added;
- `migrate()` tolerates a host's own sqlx migrations in the same database
  (`set_ignore_missing(true)`, and catacombs' migration files are renamed to
  timestamp versions such as `20261005000000_catacombs_users.sql`, so they
  cannot collide with a host's `001_…` numbering), so the two migrators do not trip over each other's
  `_sqlx_migrations` rows.

### 3. Errors and the observer

#### `LoginError`

```rust
#[non_exhaustive]
pub enum LoginError {
    DiscordRejected(Rejection), // InvalidGrant | InvalidClient | Other → 401
    DiscordUnavailable,         // network, timeout or 5xx              → 502
    BadProfile,                 // /users/@me unreadable                → 500
    Storage(StorageError),      //                                      → 500
    Session,                    // JWT signing failed                   → 500
    BadState,                   // web callback: state mismatch         → 400
}

impl LoginError {
    /// A stable, low-cardinality label for metrics.
    pub fn reason(&self) -> &'static str;
}
impl IntoResponse for LoginError { /* the status codes above */ }
```

The status codes match RuneCast's current responses, including 401 for
`invalid_client`. catacombs classifies a Discord rejection from the parsed
OAuth error body, not by searching error text.

#### `AuthObserver`

```rust
pub trait AuthObserver: Send + Sync + 'static {
    fn on_event(&self, _event: &AuthEvent<'_>) {}
}

#[non_exhaustive]
pub enum AuthEvent<'a> {
    Login {
        flow: Flow,                          // Exchange | Web
        result: Result<i64, &'a LoginError>, // Ok(user_id)
        elapsed: Duration,
        warnings: &'a [LoginWarning],
    },
}

#[non_exhaustive]
pub enum LoginWarning {
    EntitlementsUnavailable,
    GuildProfileUnavailable(GuildId),
}
```

- The method is synchronous on purpose. Metric calls are synchronous, and an
  async hook would invite network calls onto the login path.
- Login is the only event, because it is the only thing a host measures
  today. The enum is `#[non_exhaustive]`, so refresh or logout events can be
  added later without breaking hosts.
- The default observer does nothing. catacombs keeps its `tracing` logs. The
  observer exists for metrics.
- Storage timing belongs to the host, inside its `Storage` impl.

### 4. Router and `/me`

```rust
pub enum Flows { Activity, Web, Both }

pub fn router<S: HasAuth + Clone>(flows: Flows) -> Router<S>;
// Activity: /exchange  /refresh  /revoke  /logout
// Web:      /login     /callback            /logout
// Both:     all six, with /logout mounted once
```

One function, rather than two routers to merge, so `/logout` cannot be
mounted twice. Axum panics at startup on a duplicate route.

`/me` leaves the router. `catacombs::routes::me` remains a public handler
that a host can mount itself:
`.route("/me", get(catacombs::routes::me))`. A host with its own idea of a
user registers its own `/me`. A host that uses catacombs' storage can read a
user through `auth.storage().get_user(id)`.

### 5. Config

- `ServerConfig` is removed. Binding a listener is the host's job.
  `Config::from_env` stops reading `HOST` and `PORT`.
- `bot_token` and `premium_sku_id` move together into
  `premium: Option<PremiumConfig { sku_id, bot_token }>`. `from_env` builds
  it when `DISCORD_PREMIUM_SKU_ID` is set, and then requires
  `DISCORD_BOT_TOKEN`. A host without premium no longer supplies a bot
  token.

## Wire contract

For RuneCast, the switch must not change:

- route paths;
- the `TokenResponse` fields;
- the status codes for refresh and revoke;
- 204 from revoke and logout.

The switch makes these deliberate changes. RuneCast's
`tests/auth_contract/changes.rs` is the authoritative list.

- At exchange, an unreachable Discord, a 5xx, a 429, or a 200 whose body is
  not a grant gets 502 instead of 401.
- A malformed `guild_id` at exchange gets 422 instead of being ignored.
- Avatar and banner URLs gain `?size=1024`, and animated avatars are `.gif`.
- A logout without a valid token gets 204 instead of 401. catacombs adopted
  this in 0.1.0 so that logout can always clear the session cookie.
- Logout expires the `catacombs_session` cookie when the request carries it. A
  Bearer-only logout gets no `Set-Cookie`.

This section was amended on 2026-10-06, after the switch was implemented, so it
now differs from the original design.

## Migration

**Step 0, independent.** Merge catacombs #3 and publish 0.1.1 once
`CRATES_IO_TOKEN` is set.

**Step 1: catacombs 0.2.0.** One PR, with a commit per design section and the
version bump to 0.2.0. It merges but is **not tagged** until RuneCast
compiles and passes its tests against it, so the API meets a real host before
it is published.

**Step 2: RuneCast, two PRs.**

1. **Contract tests**, on their own: status codes and JSON bodies for every
   auth route, green against the current code.
2. **The switch.** It depends on catacombs by git revision until green, then
   on `catacombs = "0.2"` once 0.2.0 is tagged and published.
   - **Storage:** `impl catacombs::Storage for PgAuthStorage(PgPool)`. A
     local newtype is needed, because the orphan rule also forbids
     implementing catacombs' trait on sqlx's `PgPool`.
   - **Ciphertext writes:** a variant of the user upsert that writes
     ciphertext it is handed, and a loop over `profile.guilds` that calls the
     existing `upsert_guild_profile`.
   - **Metrics:** an `AuthObserver` that calls the existing
     `crate::metrics::oauth_exchange*` functions.
   - **Host state:** `impl HasAuth for AppState`, with an `auth: Auth` field.
   - **Extractor:** `crate::auth::AuthenticatedUser` becomes a thin wrapper.
     In debug builds it honours `X-Test-User-Id`; otherwise it delegates to
     catacombs' extractor. Its ten importers do not change.
   - **Routes:** `.nest("/auth", catacombs::router(Flows::Activity))`. RuneCast
     keeps its own `/auth/me`, `/auth/test` (debug builds) and
     `/users/decorations`.
   - **Deleted:** the duplicated handlers and Discord client code in
     `routes/auth.rs`.
   - **No database migration.** The columns, the ciphertext format and the
     `discord_entitlements` and `user_guild_profiles` tables already exist.

**Step 3: CrackTunes.** In `crack-web`:

- the `FromRef` impl becomes a `HasAuth` impl, and `Arc<catacombs::AppState>`
  becomes `Auth`;
- it mounts `router(Flows::Web)`;
- its config drops the dummy `ServerConfig` and bot token;
- the dependency moves from the git tag to `catacombs = "0.2"`.

Memory storage lives only in the process, so there is no data to migrate.

**Step 4: RuneCast frontend,** after the backend deploys: add
`guilds.members.read` to the `authorize` scopes and send `guild_id` to
`/exchange`. Users see Discord's consent screen once more, because the scopes
changed. Then the workspace submodule bump and deploy, following RuneCast's
usual process.

**Safety.** The JWT claims and secret are unchanged, so no one is logged out
in either app. RuneCast's switch changes no schema, so rollback is a redeploy
of the previous image.

## Testing

catacombs, against the existing mock Discord server (set up through
`DiscordConfig.api_base`):

- **`HasAuth`:** the extractor and the router work with host state that is a
  plain struct and with `Arc<HostState>`.
- **Encryption:** storage receives only ciphertext. A test storage asserts
  that no stored token equals the plaintext.
- **Guild profiles:**
  - a `guild_id` on `/exchange` produces a `GuildProfile`;
  - a 403 from the member endpoint leaves the map empty, the login succeeds,
    and the observer receives `GuildProfileUnavailable`;
  - `MemoryStorage` merges guilds across logins.
- **Errors:** each `LoginError` maps to its status code. Discord being
  unreachable gives 502.
- **Observer:** it receives exactly one `Login` event per attempt, with the
  right result and warnings.
- **Routes:** `Flows::Activity` does not mount `/login`, `Flows::Web` does not
  mount `/exchange`, and `Flows::Both` mounts `/logout` once.
- **Config:** `from_env` without `DISCORD_PREMIUM_SKU_ID` needs no bot token.

RuneCast: the contract tests from step 2.1, run before and after the switch.

## Out of scope

- A public toolkit layer (a Discord client and session primitives as separate
  public API). The router is built from such pieces internally, and they
  become public when a third host needs them.
- Fetching all of a user's guilds.
- A `UserId` newtype.
- Observer events for refresh and logout.
- Guild profiles in the web flow.
- The roadmap's session items (revocable sessions, configurable lifetime) and
  the website-flow rough edges. They build on this release and do not block
  it.
