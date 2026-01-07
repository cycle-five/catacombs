//! Error types for Discord OAuth template.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};

/// Result type alias using the library's error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Error type for Discord OAuth operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Storage operation failed.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    /// Discord API request failed.
    #[error("discord API error: {0}")]
    DiscordApi(String),

    /// JWT token operation failed.
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),

    /// Encryption/decryption failed.
    #[error("encryption error: {0}")]
    Encryption(#[from] anyhow::Error),

    /// User not found.
    #[error("user not found: {0}")]
    UserNotFound(i64),

    /// Authentication failed.
    #[error("authentication failed: {0}")]
    AuthFailed(String),

    /// Invalid request.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

/// Storage-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Database query failed.
    #[cfg(feature = "sqlx-storage")]
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Generic storage error for non-sqlx backends.
    #[error("storage error: {0}")]
    Other(String),
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Error::Storage(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            Error::DiscordApi(_) => (StatusCode::BAD_GATEWAY, self.to_string()),
            Error::Jwt(_) => (StatusCode::UNAUTHORIZED, "invalid token".to_string()),
            Error::Encryption(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "encryption error".to_string(),
            ),
            Error::UserNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            Error::AuthFailed(_) => (StatusCode::UNAUTHORIZED, self.to_string()),
            Error::InvalidRequest(_) => (StatusCode::BAD_REQUEST, self.to_string()),
        };

        (status, message).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = Error::UserNotFound(123);
        assert_eq!(err.to_string(), "user not found: 123");
    }

    #[test]
    fn test_storage_error_display() {
        let err = StorageError::Other("test error".to_string());
        assert_eq!(err.to_string(), "storage error: test error");
    }

    #[test]
    fn test_error_from_storage_error() {
        let storage_err = StorageError::Other("test".to_string());
        let err: Error = storage_err.into();
        assert!(matches!(err, Error::Storage(_)));
    }
}
