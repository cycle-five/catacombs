//! Hooks for metrics: catacombs reports each login, and the host counts it.

use std::{sync::Arc, time::Duration};

use crate::{error::LoginError, models::GuildId};

/// Which login flow an event came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// `POST /exchange`: an Activity or single-page app.
    Exchange,
    /// `GET /callback`: the website flow.
    Web,
}

/// Something that did not stop a login but left data out.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoginWarning {
    /// Discord's entitlements could not be read; the subscription was left
    /// as it was.
    EntitlementsUnavailable,
    /// The user's profile in this guild could not be read (often a missing
    /// `guilds.members.read` scope).
    GuildProfileUnavailable(GuildId),
}

/// What catacombs reports.
#[derive(Debug)]
#[non_exhaustive]
pub enum AuthEvent<'a> {
    /// A login attempt finished.
    #[non_exhaustive]
    Login {
        /// The flow it came through.
        flow: Flow,
        /// The user ID on success, or why it failed.
        result: Result<i64, &'a LoginError>,
        /// How long it took, Discord calls included.
        elapsed: Duration,
        /// What was left out of a login that went ahead.
        warnings: &'a [LoginWarning],
    },
}

/// Receives catacombs' events, for metrics.
///
/// The method is synchronous on purpose: it runs on the login path, so it
/// should record and return, not make network calls.
pub trait AuthObserver: Send + Sync + 'static {
    /// Called once per event. The default does nothing.
    fn on_event(&self, _event: &AuthEvent<'_>) {}
}

impl<T: AuthObserver + ?Sized> AuthObserver for Arc<T> {
    fn on_event(&self, event: &AuthEvent<'_>) {
        (**self).on_event(event);
    }
}

/// The observer used when the host sets none.
pub(crate) struct NoObserver;

impl AuthObserver for NoObserver {}
