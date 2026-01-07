//! Discord `OAuth2` authentication routes.
//!
//! This module provides HTTP handlers for:
//! - Code exchange (`OAuth2` authorization code -> access token)
//! - Token refresh
//! - Token revocation
//! - User info retrieval
//! - Logout

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{self, AuthenticatedUser},
    models::{EntitlementUpsertParams, SubscriptionSource, SubscriptionTier, UserUpsertParams},
    AppState,
};

/// Create an Axum router with all auth routes.
///
/// Routes:
/// - `POST /exchange` - Exchange authorization code for tokens
/// - `POST /refresh` - Refresh the OAuth token
/// - `POST /revoke` - Revoke tokens with Discord
/// - `POST /logout` - Clear local tokens
/// - `GET /me` - Get current user info
pub fn auth_router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/exchange", post(exchange_code))
        .route("/refresh", post(refresh_token))
        .route("/revoke", post(revoke_token))
        .route("/logout", post(logout))
        .route("/me", get(get_current_user))
}

#[derive(Debug, Deserialize)]
pub struct CodeExchangeRequest {
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    /// JWT token for backend API authentication.
    pub access_token: String,
    /// Discord OAuth access token for Discord SDK authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discord_access_token: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub user_id: i64,
    pub username: String,
    pub global_name: Option<String>,
    pub avatar_url: Option<String>,
    pub subscription_tier: SubscriptionTier,
    pub is_premium: bool,
}

/// Discord user response from /users/@me endpoint.
#[derive(Debug, Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    avatar: Option<String>,
    global_name: Option<String>,
    discriminator: Option<String>,
}

/// Discord `OAuth2` token response.
#[derive(Debug, Deserialize)]
struct DiscordTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: String,
    expires_in: i64,
    refresh_token: String,
    #[allow(dead_code)]
    scope: String,
}

/// Discord entitlement from the API.
#[derive(Debug, Deserialize)]
struct DiscordEntitlementResponse {
    id: String,
    sku_id: String,
    #[allow(dead_code)]
    user_id: Option<String>,
    #[serde(rename = "type")]
    entitlement_type: i32,
    #[serde(default)]
    deleted: bool,
    starts_at: Option<DateTime<Utc>>,
    ends_at: Option<DateTime<Utc>>,
    #[serde(default)]
    consumed: bool,
}

/// Exchange Discord authorization code for access token and create user session.
pub async fn exchange_code(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CodeExchangeRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    tracing::info!("Exchanging authorization code for access token");

    // Exchange authorization code for Discord access token
    let discord_token = exchange_code_with_discord(&state, &payload.code)
        .await
        .map_err(|e| {
            tracing::error!("Failed to exchange code with Discord: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    // Get user info from Discord API
    let discord_user = get_discord_user_info(&discord_token.access_token, &state.http_client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to get Discord user info: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Parse Discord user ID (u64 snowflake stored as i64)
    let user_id = discord_user.id.parse::<u64>().map_err(|e| {
        tracing::error!("Failed to parse Discord user ID: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? as i64;

    // Build avatar URL
    let avatar_url = build_avatar_url(&discord_user);

    // Calculate token expiration
    let token_expires_at = Utc::now() + chrono::Duration::seconds(discord_token.expires_in);

    // Create or update user in storage
    state
        .storage
        .upsert_user(
            UserUpsertParams {
                user_id,
                username: &discord_user.username,
                global_name: discord_user.global_name.as_deref(),
                avatar_url: Some(&avatar_url.clone()),
                refresh_token: Some(&discord_token.refresh_token),
                token_expires_at: Some(token_expires_at),
            },
            &state.config.security.encryption_key,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to create/update user in storage: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Fetch and process user entitlements for premium status
    if state.config.discord.premium_sku_id.is_some() {
        match fetch_user_entitlements(&state, user_id).await {
            Ok(entitlements) => {
                if let Err(e) = process_user_entitlements(&state, user_id, entitlements).await {
                    tracing::warn!("Failed to process entitlements for user {}: {}", user_id, e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to fetch entitlements for user {}: {}", user_id, e);
            }
        }
    }

    tracing::info!(
        "Successfully authenticated user: {} (ID: {})",
        discord_user.username,
        user_id
    );

    // Generate JWT token
    let jwt_token = auth::generate_token(
        user_id,
        &discord_user.username,
        &state.config.security.jwt_secret,
    )
    .map_err(|e| {
        tracing::error!("Failed to generate JWT token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(TokenResponse {
        access_token: jwt_token,
        discord_access_token: Some(discord_token.access_token),
    }))
}

/// Refresh the user's OAuth tokens and return a new JWT.
pub async fn refresh_token(
    user: AuthenticatedUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<TokenResponse>, StatusCode> {
    tracing::info!(
        "Refreshing token for user: {} ({})",
        user.username,
        user.user_id
    );

    // Get user with refresh token from storage
    let db_user = state
        .storage
        .get_user(user.user_id, &state.config.security.encryption_key)
        .await
        .map_err(|e| {
            tracing::error!("Storage error fetching user for refresh: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("User not found for token refresh: {}", user.user_id);
            StatusCode::NOT_FOUND
        })?;

    let current_refresh_token = db_user.refresh_token.ok_or_else(|| {
        tracing::warn!("No refresh token stored for user: {}", user.user_id);
        StatusCode::UNAUTHORIZED
    })?;

    // Refresh with Discord
    let discord_token = refresh_discord_token(&state, &current_refresh_token)
        .await
        .map_err(|e| {
            tracing::error!("Failed to refresh Discord token: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    let token_expires_at = Utc::now() + chrono::Duration::seconds(discord_token.expires_in);

    // Store new refresh token
    state
        .storage
        .update_refresh_token(
            user.user_id,
            &discord_token.refresh_token,
            token_expires_at,
            &state.config.security.encryption_key,
        )
        .await
        .map_err(|e| {
            tracing::error!("Failed to update refresh token in storage: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!(
        "Successfully refreshed token for user: {} ({})",
        user.username,
        user.user_id
    );

    // Generate new JWT
    let jwt_token = auth::generate_token(
        user.user_id,
        &user.username,
        &state.config.security.jwt_secret,
    )
    .map_err(|e| {
        tracing::error!("Failed to generate JWT token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(TokenResponse {
        access_token: jwt_token,
        discord_access_token: Some(discord_token.access_token),
    }))
}

/// Revoke the user's Discord OAuth tokens and clear from storage.
pub async fn revoke_token(
    user: AuthenticatedUser,
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, StatusCode> {
    tracing::info!(
        "Revoking tokens for user: {} ({})",
        user.username,
        user.user_id
    );

    // Get user with refresh token
    let db_user = state
        .storage
        .get_user(user.user_id, &state.config.security.encryption_key)
        .await
        .map_err(|e| {
            tracing::error!("Storage error fetching user for revoke: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Revoke with Discord if we have a refresh token
    if let Some(user_data) = db_user {
        if let Some(refresh_token) = user_data.refresh_token {
            if let Err(e) = revoke_discord_token(&state, &refresh_token).await {
                tracing::warn!(
                    "Failed to revoke token with Discord (continuing anyway): {}",
                    e
                );
            }
        }
    }

    // Clear tokens from storage
    state
        .storage
        .clear_user_tokens(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to clear tokens from storage: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!(
        "Successfully revoked tokens for user: {} ({})",
        user.username,
        user.user_id
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Log out the user by clearing their stored tokens.
pub async fn logout(
    user: AuthenticatedUser,
    State(state): State<Arc<AppState>>,
) -> Result<StatusCode, StatusCode> {
    tracing::info!("Logging out user: {} ({})", user.username, user.user_id);

    state
        .storage
        .clear_user_tokens(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Failed to clear tokens for logout: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tracing::info!(
        "Successfully logged out user: {} ({})",
        user.username,
        user.user_id
    );
    Ok(StatusCode::NO_CONTENT)
}

/// Get current user info from storage.
pub async fn get_current_user(
    user: AuthenticatedUser,
    State(state): State<Arc<AppState>>,
) -> Result<Json<UserResponse>, StatusCode> {
    tracing::debug!(
        "Getting user info for authenticated user: {} ({})",
        user.username,
        user.user_id
    );

    let db_user = state
        .storage
        .get_user(user.user_id, &state.config.security.encryption_key)
        .await
        .map_err(|e| {
            tracing::error!("Storage error fetching user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("User not found in storage: {}", user.user_id);
            StatusCode::NOT_FOUND
        })?;

    let is_premium = db_user.is_premium();
    Ok(Json(UserResponse {
        user_id: db_user.user_id,
        username: db_user.username,
        global_name: db_user.global_name,
        avatar_url: db_user.avatar_url,
        subscription_tier: db_user.subscription_tier,
        is_premium,
    }))
}

// ============================================================================
// Discord API helpers
// ============================================================================

/// Build a CDN URL for a Discord user's avatar (or the default embed avatar).
fn build_avatar_url(user: &DiscordUser) -> String {
    if let Some(avatar_hash) = user.avatar.as_ref() {
        let ext = if avatar_hash.starts_with("a_") {
            "gif"
        } else {
            "png"
        };
        format!(
            "https://cdn.discordapp.com/avatars/{}/{}.{}?size=1024",
            user.id, avatar_hash, ext
        )
    } else {
        let index = user
            .discriminator
            .as_deref()
            .and_then(|d| d.parse::<u32>().ok())
            .map_or(0, |n| n % 5);
        format!("https://cdn.discordapp.com/embed/avatars/{index}.png")
    }
}

async fn exchange_code_with_discord(
    state: &AppState,
    code: &str,
) -> anyhow::Result<DiscordTokenResponse> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", state.config.discord.redirect_uri.as_str()),
    ];

    let response = state
        .http_client
        .post("https://discord.com/api/v10/oauth2/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(
            &state.config.discord.client_id,
            Some(&state.config.discord.client_secret),
        )
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        tracing::error!("Discord token exchange failed: {} - {}", status, error_text);
        anyhow::bail!("Discord token exchange failed with status {status}");
    }

    Ok(response.json::<DiscordTokenResponse>().await?)
}

async fn get_discord_user_info(
    access_token: &str,
    http_client: &reqwest::Client,
) -> anyhow::Result<DiscordUser> {
    let response = http_client
        .get("https://discord.com/api/v10/users/@me")
        .header("Authorization", format!("Bearer {access_token}"))
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        tracing::error!(
            "Discord user info fetch failed: {} - {}",
            status,
            error_text
        );
        anyhow::bail!("Failed to fetch Discord user info with status {status}");
    }

    Ok(response.json::<DiscordUser>().await?)
}

async fn refresh_discord_token(
    state: &AppState,
    refresh_token: &str,
) -> anyhow::Result<DiscordTokenResponse> {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];

    let response = state
        .http_client
        .post("https://discord.com/api/v10/oauth2/token")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(
            &state.config.discord.client_id,
            Some(&state.config.discord.client_secret),
        )
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        tracing::error!("Discord token refresh failed: {} - {}", status, error_text);
        anyhow::bail!("Discord token refresh failed with status {status}");
    }

    Ok(response.json::<DiscordTokenResponse>().await?)
}

async fn revoke_discord_token(state: &AppState, token: &str) -> anyhow::Result<()> {
    let params = [("token", token)];

    let response = state
        .http_client
        .post("https://discord.com/api/v10/oauth2/token/revoke")
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(
            &state.config.discord.client_id,
            Some(&state.config.discord.client_secret),
        )
        .form(&params)
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        tracing::warn!(
            "Discord token revocation returned non-success: {} - {}",
            status,
            error_text
        );
    }

    Ok(())
}

async fn fetch_user_entitlements(
    state: &AppState,
    user_id: i64,
) -> anyhow::Result<Vec<DiscordEntitlementResponse>> {
    let user_id_str = user_id.to_string();
    let url = format!(
        "https://discord.com/api/v10/applications/{}/entitlements?user_id={}&exclude_ended=false",
        state.config.discord.client_id, user_id_str
    );

    let response = state
        .http_client
        .get(&url)
        .header(
            "Authorization",
            format!("Bot {}", state.config.discord.bot_token),
        )
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await?;
        tracing::warn!(
            "Discord entitlements fetch failed: {} - {}",
            status,
            error_text
        );
        return Ok(vec![]);
    }

    Ok(response.json::<Vec<DiscordEntitlementResponse>>().await?)
}

async fn process_user_entitlements(
    state: &AppState,
    user_id: i64,
    entitlements: Vec<DiscordEntitlementResponse>,
) -> anyhow::Result<SubscriptionTier> {
    let premium_sku_id = state.config.discord.premium_sku_id;

    let mut highest_tier = SubscriptionTier::Free;
    let mut subscription_expires: Option<DateTime<Utc>> = None;

    for entitlement in entitlements {
        if entitlement.deleted {
            continue;
        }

        let ent_id: i64 = match entitlement.id.parse() {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!("Failed to parse entitlement.id '{}': {}", entitlement.id, e);
                continue;
            }
        };
        let sku_id: i64 = match entitlement.sku_id.parse() {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    "Failed to parse entitlement.sku_id '{}': {}",
                    entitlement.sku_id,
                    e
                );
                continue;
            }
        };

        // Store entitlement
        if let Err(e) = state
            .storage
            .upsert_entitlement(EntitlementUpsertParams {
                entitlement_id: ent_id,
                user_id,
                sku_id,
                entitlement_type: entitlement.entitlement_type,
                is_test: false,
                consumed: entitlement.consumed,
                starts_at: entitlement.starts_at,
                ends_at: entitlement.ends_at,
            })
            .await
        {
            tracing::warn!("Failed to upsert entitlement {}: {}", ent_id, e);
            continue;
        }

        // Check if this entitlement grants premium
        if let Some(premium_sku) = premium_sku_id {
            if sku_id == premium_sku {
                let is_active = match entitlement.ends_at {
                    Some(ends) => ends > Utc::now(),
                    None => true,
                };

                if is_active {
                    highest_tier = SubscriptionTier::Premium;
                    match (subscription_expires, entitlement.ends_at) {
                        (None, ends) => subscription_expires = ends,
                        (Some(current), Some(ends)) if ends > current => {
                            subscription_expires = Some(ends);
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    // Update user's subscription tier
    if highest_tier != SubscriptionTier::Free {
        state
            .storage
            .update_subscription(
                user_id,
                highest_tier,
                SubscriptionSource::Discord,
                subscription_expires,
            )
            .await?;
        tracing::info!(
            "Updated user {} subscription to {:?} (expires: {:?})",
            user_id,
            highest_tier,
            subscription_expires
        );
    }

    Ok(highest_tier)
}

#[cfg(test)]
mod tests {
    use super::{
        build_avatar_url, CodeExchangeRequest, DiscordUser, SubscriptionTier, TokenResponse,
        UserResponse,
    };

    /// Helper function to create a `DiscordUser` for testing.
    /// This reduces redundancy in test cases.
    /// Parameters:
    ///     - id: &str - Discord user ID
    ///     - username: &str - Discord username
    ///     - avatar: Option<&str> - Discord avatar hash
    /// Returns:
    ///     - `DiscordUser` - Constructed `DiscordUser` instance
    fn make_discord_user(id: &str, username: &str, avatar: Option<&str>) -> DiscordUser {
        DiscordUser {
            id: id.to_string(),
            username: username.to_string(),
            avatar: avatar.map(std::string::ToString::to_string),
            global_name: None,
            discriminator: None,
        }
    }

    /// Helper function to create a default `DiscordUser` for testing.
    /// Returns:
    ///     - `DiscordUser` - Constructed `DiscordUser` instance with default values
    fn make_default_discord_user() -> DiscordUser {
        let id = "987654321";
        let username = "default_user";
        let avatar = None;
        make_discord_user(id, username, avatar)
    }

    #[test]
    fn test_code_exchange_request_deserialization() {
        let json = r#"{"code": "test_auth_code_12345"}"#;
        let request: CodeExchangeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(request.code, "test_auth_code_12345");
    }

    #[test]
    fn test_token_response_serialization() {
        let response = TokenResponse {
            access_token: "jwt_token_here".to_string(),
            discord_access_token: Some("discord_token_here".to_string()),
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("access_token"));
        assert!(json.contains("discord_access_token"));
    }

    #[test]
    fn test_token_response_serialization_without_discord_token() {
        let response = TokenResponse {
            access_token: "jwt_token_here".to_string(),
            discord_access_token: None,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("access_token"));
        assert!(!json.contains("discord_access_token"));
    }

    #[test]
    fn test_user_response_serialization() {
        let response = UserResponse {
            user_id: 123456789,
            username: "test_user".to_string(),
            global_name: Some("Test User".to_string()),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            subscription_tier: SubscriptionTier::Premium,
            is_premium: true,
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("123456789"));
        assert!(json.contains("test_user"));
        assert!(json.contains("premium"));
    }

    #[test]
    fn test_avatar_url_generation() {
        let user_id = "123456789";
        let avatar_hash = "abc123def456";
        let avatar_url = format!("https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png");
        assert_eq!(
            avatar_url,
            "https://cdn.discordapp.com/avatars/123456789/abc123def456.png"
        );
    }

    #[test]
    fn test_avatar_url_generation_with_discriminator() {
        let user = make_default_discord_user();
        let avatar_url = build_avatar_url(&user);

        assert_eq!(avatar_url, "https://cdn.discordapp.com/embed/avatars/0.png");
    }
}
