//! Error types.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Storage-specific errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// Database query failed.
    #[cfg(feature = "sqlx-storage")]
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// An error from a host's own storage backend.
    #[error("storage backend error: {0}")]
    Backend(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Generic storage error for non-sqlx backends.
    #[error("storage error: {0}")]
    Other(String),
}

impl StorageError {
    /// Wrap any backend error, keeping its source chain.
    pub fn backend(err: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> Self {
        Self::Backend(err.into())
    }
}

/// Why Discord refused a token request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Rejection {
    /// The code or refresh token is expired, already used, or not ours.
    InvalidGrant,
    /// Discord refused our client ID and secret: a configuration error.
    InvalidClient,
    /// Any other refusal.
    Other,
}

/// Why a login failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LoginError {
    /// Discord refused the token request.
    #[error("discord rejected the token request: {0:?}")]
    DiscordRejected(Rejection),
    /// Discord could not be reached, or failed on its side.
    #[error("discord is unreachable or failed")]
    DiscordUnavailable,
    /// Discord's `/users/@me` could not be read.
    #[error("discord's user profile could not be read")]
    BadProfile,
    /// Storage failed.
    #[error("storage failed: {0}")]
    Storage(#[from] StorageError),
    /// The session token could not be signed.
    #[error("could not sign the session token")]
    Session,
    /// The web callback's `state` did not match the login's.
    #[error("the login state did not match")]
    BadState,
}

impl LoginError {
    /// A short, stable label for metrics. The set is fixed, so it is safe as
    /// a Prometheus label. It matches the labels RuneCast records.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::DiscordRejected(Rejection::InvalidGrant) => "invalid_grant",
            Self::DiscordRejected(Rejection::InvalidClient) => "invalid_client",
            Self::DiscordRejected(Rejection::Other) => "rejected",
            Self::DiscordUnavailable => "network",
            Self::BadProfile => "discord_user_fetch",
            Self::Storage(_) => "db_upsert",
            Self::Session => "jwt_sign",
            Self::BadState => "bad_state",
        }
    }

    /// The HTTP status a login route answers with.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        match self {
            Self::DiscordRejected(_) => StatusCode::UNAUTHORIZED,
            Self::DiscordUnavailable => StatusCode::BAD_GATEWAY,
            Self::BadState => StatusCode::BAD_REQUEST,
            Self::BadProfile | Self::Storage(_) | Self::Session => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl IntoResponse for LoginError {
    fn into_response(self) -> Response {
        self.status().into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_error_display() {
        let err = StorageError::Other("test error".to_string());
        assert_eq!(err.to_string(), "storage error: test error");
    }

    #[test]
    fn a_backend_error_keeps_its_source() {
        let err = StorageError::backend(std::io::Error::other("disk"));
        assert_eq!(err.to_string(), "storage backend error: disk");
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn login_errors_map_to_statuses_and_stable_reasons() {
        let cases = [
            (
                LoginError::DiscordRejected(Rejection::InvalidGrant),
                401,
                "invalid_grant",
            ),
            (
                LoginError::DiscordRejected(Rejection::InvalidClient),
                401,
                "invalid_client",
            ),
            (
                LoginError::DiscordRejected(Rejection::Other),
                401,
                "rejected",
            ),
            (LoginError::DiscordUnavailable, 502, "network"),
            (LoginError::BadProfile, 500, "discord_user_fetch"),
            (
                LoginError::Storage(StorageError::Other("x".into())),
                500,
                "db_upsert",
            ),
            (LoginError::Session, 500, "jwt_sign"),
            (LoginError::BadState, 400, "bad_state"),
        ];
        for (err, status, reason) in cases {
            assert_eq!(err.status().as_u16(), status, "{err:?}");
            assert_eq!(err.reason(), reason, "{err:?}");
        }
    }
}
