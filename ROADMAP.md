# Roadmap

This is where catacombs is headed after v0.1.0, which added the website login
flow that CrackTunes' web dashboard signs in through. Nothing here is promised
to a date. Within each section, items are in rough priority order.

## Next: the rough edges of the website flow

**Skip Discord's consent screen on return visits.** Every login currently
shows the "Authorize" page, even to someone who approved the app yesterday.
Discord skips it when the authorize URL carries `prompt=none` and the user has
already granted the same scopes. This should be a `WebConfig` option, on by
default.

**Friendly error pages.** When a login fails, `/callback` answers with a bare
status code: 400 for a bad `state`, 401 when Discord rejects the code, and
500 for most other failures. Someone who clicked "Log in" sees a blank browser
error. The callback should send them back to `return_to` with a short reason,
or render a minimal page that the host application can replace.

**Two tabs logging in at once.** The OAuth `state` lives in a single cookie,
so a login started in a second tab overwrites the first tab's state, and the
first tab's callback fails with a 400. Keying the cookie by its state value,
or keeping a small set of pending states, would let both succeed.

**`Origin` checks on catacombs' own POSTs.** `/refresh`, `/revoke` and
`/logout` accept the session cookie and rely only on `SameSite=Lax`. That
stops other sites, but not a sibling subdomain. The routes should reject a
request whose `Origin` does not match the configured public origin, as the
CrackTunes dashboard already does for its own endpoints.

## Then: sessions

**Sessions that can be revoked.** A session is a stateless JWT that is valid
for 24 hours. Logging out deletes the cookie, but a copy of the token keeps
working until it expires. A per-user session generation, stored with the user
and checked by the extractor, would make logout and "sign out everywhere"
real, at the cost of one storage read per request.

**A configurable session lifetime.** `SESSION_TTL_SECS` is a constant today.
It belongs in `WebConfig`.

**Identity-only logins.** A site such as the CrackTunes dashboard only needs
to know who you are. It never calls Discord on your behalf, but catacombs
still keeps your Discord access and refresh tokens. Storage now accepts
`tokens: None`, but nothing chooses it yet. What remains is a `WebConfig`
option to skip storing tokens, which would shrink what a leak exposes.

## Maintenance

**sqlx 0.9.** catacombs is on sqlx 0.8 and CrackTunes has moved to 0.9. A
consumer that enables `sqlx-storage` alongside its own sqlx 0.9 compiles both
versions.

**The `rsa` advisory.** RUSTSEC-2023-0071 is ignored in `.cargo/audit.toml`,
because only HS256 is used and the vulnerable code never runs. That should be
revisited when `rsa` ships a fix. The alternative is jsonwebtoken's
`aws_lc_rs` backend, which drops `rsa` entirely but brings a C toolchain into
the build.

## Settled: crates.io

catacombs is published from v0.1.1. A tag that matches `Cargo.toml` publishes
it through the release workflow, using the `CRATES_IO_TOKEN` secret. Because a
0.x minor bump may break things under Cargo's rules, the session work above
ships as 0.2.0, not as a 0.1.x patch.
