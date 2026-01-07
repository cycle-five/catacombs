//! JWT authentication and user extraction.
//!
//! This module provides JWT token generation/validation and an Axum extractor
//! for authenticated users.

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use axum::{
    extract::{FromRef, FromRequestParts},
    http::{header, request::Parts, StatusCode},
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

use crate::AppState;

/// JWT claims structure.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    /// Subject (user ID as string).
    pub sub: String,
    /// Username.
    pub username: String,
    /// Expiration timestamp (Unix epoch seconds).
    pub exp: i64,
}

/// Authenticated user extracted from JWT token.
///
/// This can be used as an Axum extractor to require authentication.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    /// Discord user ID.
    pub user_id: i64,
    /// Discord username.
    pub username: String,
}

/// Extractor for authenticated users from JWT tokens.
///
/// Supports two authentication methods:
/// 1. `Authorization: Bearer <token>` header
/// 2. `?token=<token>` query parameter (useful for WebSocket connections)
impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    Arc<AppState>: FromRef<S>,
{
    type Rejection = StatusCode;

    fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let app_state = Arc::<AppState>::from_ref(state);

        // Try to extract token from Authorization header first
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(String::from)
            // If no Authorization header, try query parameter
            .or_else(|| {
                parts
                    .uri
                    .query()
                    .and_then(|q| {
                        serde_urlencoded::from_str::<HashMap<String, String>>(q)
                            .ok()
                    })
                    .and_then(|params| params.get("token").cloned())
            });

        async move {
            let token = token.ok_or(StatusCode::UNAUTHORIZED)?;

            // Validate the JWT token
            let token_data = decode::<Claims>(
                &token,
                &DecodingKey::from_secret(app_state.config.security.jwt_secret.as_ref()),
                &Validation::default(),
            )
            .map_err(|_| StatusCode::UNAUTHORIZED)?;

            let user_id = token_data
                .claims
                .sub
                .parse::<i64>()
                .map_err(|_| StatusCode::UNAUTHORIZED)?;

            Ok(AuthenticatedUser {
                user_id,
                username: token_data.claims.username,
            })
        }
    }
}

/// Generate a JWT token for a user.
///
/// The token expires after 24 hours.
/// # Errors
///    - Returns `jsonwebtoken::errors::Error` if token generation fails.
/// # Panics
///    This function will panic if the now + 24 hours timestamp overflows.
pub fn generate_token(
    user_id: i64,
    username: &str,
    jwt_secret: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();
 
    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        exp: expiration,
    };

    jsonwebtoken::encode(
        &jsonwebtoken::Header::default(),
        &claims,
        &jsonwebtoken::EncodingKey::from_secret(jwt_secret.as_ref()),
    )
}

/// Validate a JWT token and extract claims.
pub fn validate_token(
    token: &str,
    jwt_secret: &str,
) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret.as_ref()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_JWT_SECRET: &str = "test-jwt-secret-for-unit-tests-only";

    #[test]
    fn test_generate_token_success() {
        let user_id = 123456789i64;
        let username = "test_user";

        let token = generate_token(user_id, username, TEST_JWT_SECRET);
        assert!(token.is_ok(), "Token generation should succeed");

        let token_str = token.unwrap();
        assert!(!token_str.is_empty(), "Token should not be empty");
        // JWT tokens have 3 parts separated by dots
        assert_eq!(
            token_str.split('.').count(),
            3,
            "JWT token should have 3 parts"
        );
    }

    #[test]
    fn test_generate_and_validate_token() {
        let user_id = 987654321i64;
        let username = "validated_user";

        let token = generate_token(user_id, username, TEST_JWT_SECRET).unwrap();
        let claims = validate_token(&token, TEST_JWT_SECRET).unwrap();

        assert_eq!(claims.sub, user_id.to_string(), "User ID should match");
        assert_eq!(claims.username, username, "Username should match");
        assert!(claims.exp > 0, "Expiration should be set");
    }

    #[test]
    fn test_validate_token_wrong_secret() {
        let user_id = 111111111i64;
        let username = "wrong_secret_user";

        let token = generate_token(user_id, username, TEST_JWT_SECRET).unwrap();
        let result = validate_token(&token, "wrong-secret");

        assert!(result.is_err(), "Validation with wrong secret should fail");
    }

    #[test]
    fn test_validate_invalid_token() {
        let result = validate_token("invalid.token.here", TEST_JWT_SECRET);
        assert!(result.is_err(), "Invalid token should fail validation");
    }

    #[test]
    fn test_validate_malformed_token() {
        let result = validate_token("not-a-jwt", TEST_JWT_SECRET);
        assert!(result.is_err(), "Malformed token should fail validation");
    }

    #[test]
    fn test_generate_token_with_special_characters_in_username() {
        let user_id = 222222222i64;
        let username = "user@name#special!chars";

        let token = generate_token(user_id, username, TEST_JWT_SECRET).unwrap();
        let claims = validate_token(&token, TEST_JWT_SECRET).unwrap();

        assert_eq!(
            claims.username, username,
            "Special characters in username should be preserved"
        );
    }

    #[test]
    fn test_generate_token_with_large_user_id() {
        // Test with a large Discord snowflake ID
        let user_id = 1234567890123456789i64;
        let username = "large_id_user";

        let token = generate_token(user_id, username, TEST_JWT_SECRET).unwrap();
        let claims = validate_token(&token, TEST_JWT_SECRET).unwrap();

        assert_eq!(
            claims.sub,
            user_id.to_string(),
            "Large user ID should be preserved"
        );
    }

    #[test]
    fn test_token_expiration_is_24_hours() {
        let user_id = 333333333i64;
        let username = "expiry_test_user";

        let before = chrono::Utc::now().timestamp();
        let token = generate_token(user_id, username, TEST_JWT_SECRET).unwrap();
        let claims = validate_token(&token, TEST_JWT_SECRET).unwrap();
        let after = chrono::Utc::now().timestamp();

        // Token should expire approximately 24 hours from now
        let expected_min = before + 24 * 60 * 60 - 1;
        let expected_max = after + 24 * 60 * 60 + 1;

        assert!(
            claims.exp >= expected_min,
            "Expiration should be at least 24 hours"
        );
        assert!(
            claims.exp <= expected_max,
            "Expiration should be at most 24 hours"
        );
    }

    #[test]
    fn test_claims_serialization() {
        let claims = Claims {
            sub: "12345".to_string(),
            username: "test".to_string(),
            exp: 1000000,
        };

        let json = serde_json::to_string(&claims).unwrap();
        let deserialized: Claims = serde_json::from_str(&json).unwrap();

        assert_eq!(claims.sub, deserialized.sub);
        assert_eq!(claims.username, deserialized.username);
        assert_eq!(claims.exp, deserialized.exp);
    }

    #[test]
    fn test_authenticated_user_debug() {
        let user = AuthenticatedUser {
            user_id: 123,
            username: "debug_test".to_string(),
        };

        // Test that Debug is implemented correctly
        let debug_str = format!("{user:?}");
        assert!(debug_str.contains("123"), "Debug should contain user_id");
        assert!(
            debug_str.contains("debug_test"),
            "Debug should contain username"
        );
    }

    #[test]
    fn test_authenticated_user_clone() {
        let user = AuthenticatedUser {
            user_id: 456,
            username: "clone_test".to_string(),
        };

        let cloned = user.clone();
        assert_eq!(user.user_id, cloned.user_id);
        assert_eq!(user.username, cloned.username);
    }
}
