//! Discord `OAuth2` authentication routes.
//!
//! This module provides HTTP handlers for:
//! - Code exchange (`OAuth2` authorization code -> access token)
//! - Token refresh
//! - Token revocation
//! - User info retrieval
//! - Logout

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use axum_extra::extract::cookie::CookieJar;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{self, AuthenticatedUser},
    models::{
        DiscordProfile, EncryptedToken, Entitlement, StoredTokens, Subscription,
        SubscriptionSource, SubscriptionTier,
    },
    Auth, HasAuth,
};

/// Create an Axum router with all auth routes.
///
/// Routes:
/// - `POST /exchange` - Exchange authorization code for tokens
/// - `POST /refresh` - Refresh the OAuth token
/// - `POST /revoke` - Revoke tokens with Discord
/// - `POST /logout` - Delete the session cookie and clear local tokens
/// - `GET /me` - Get current user info
/// - `GET /login` - Start the website flow (redirect to Discord)
/// - `GET /callback` - Finish the website flow (sets the session cookie)
pub fn auth_router<S: HasAuth + Clone>() -> Router<S> {
    Router::new()
        .route("/exchange", post(exchange_code::<S>))
        .route("/refresh", post(refresh_token::<S>))
        .route("/revoke", post(revoke_token::<S>))
        .route("/logout", post(logout::<S>))
        .route("/me", get(get_current_user::<S>))
        .route("/login", get(super::web::login::<S>))
        .route("/callback", get(super::web::callback::<S>))
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

/// A completed Discord login: our JWT and Discord's own access token.
pub(crate) struct Login {
    pub jwt: String,
    pub discord_access_token: String,
}

/// Exchange `code` with Discord, upsert the user, refresh entitlements, and
/// mint our JWT. Shared by the SDK flow (`POST /exchange`) and the website
/// flow (`GET /callback`), so the two cannot drift.
pub(crate) async fn complete_login(auth: &Auth, code: &str) -> Result<Login, StatusCode> {
    // Exchange authorization code for Discord access token
    let discord_token = exchange_code_with_discord(auth, code).await.map_err(|e| {
        tracing::error!("Failed to exchange code with Discord: {}", e);
        StatusCode::UNAUTHORIZED
    })?;

    // Get user info from Discord API
    let discord_user = get_discord_user_info(
        &auth.config().discord.api_base,
        &discord_token.access_token,
        auth.http_client(),
    )
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

    // Calculate token expiration
    let token_expires_at = Utc::now() + chrono::Duration::seconds(discord_token.expires_in);

    // Create or update user in storage
    let mut profile = DiscordProfile::new(user_id, discord_user.username.clone());
    profile.global_name = discord_user.global_name.clone();
    profile.avatar_url = Some(build_avatar_url(&discord_user));
    let tokens = StoredTokens {
        refresh_token: EncryptedToken::encrypt(
            &discord_token.refresh_token,
            &auth.config().security.encryption_key,
        )
        .map_err(|e| {
            tracing::error!("Failed to encrypt refresh token: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
        expires_at: token_expires_at,
    };
    auth.storage()
        .upsert_user(&profile, Some(&tokens))
        .await
        .map_err(|e| {
            tracing::error!("Failed to create/update user in storage: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Fetch and process user entitlements for premium status
    if let Some(premium) = &auth.config().discord.premium {
        match fetch_user_entitlements(auth, premium, user_id).await {
            Ok(entitlements) => {
                if let Err(e) = process_user_entitlements(auth, user_id, entitlements).await {
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
        &auth.config().security.jwt_secret,
    )
    .map_err(|e| {
        tracing::error!("Failed to generate JWT token: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Login {
        jwt: jwt_token,
        discord_access_token: discord_token.access_token,
    })
}

/// Exchange Discord authorization code for access token and create user session.
pub async fn exchange_code<S: HasAuth + Clone>(
    State(state): State<S>,
    Json(payload): Json<CodeExchangeRequest>,
) -> Result<Json<TokenResponse>, StatusCode> {
    let auth = state.auth();
    tracing::info!("Exchanging authorization code for access token");
    let login = complete_login(auth, &payload.code).await?;
    Ok(Json(TokenResponse {
        access_token: login.jwt,
        discord_access_token: Some(login.discord_access_token),
    }))
}

/// Refresh the user's OAuth tokens and return a new JWT.
pub async fn refresh_token<S: HasAuth + Clone>(
    user: AuthenticatedUser,
    State(state): State<S>,
) -> Result<Json<TokenResponse>, StatusCode> {
    let auth = state.auth();
    tracing::info!(
        "Refreshing token for user: {} ({})",
        user.username,
        user.user_id
    );

    // Get user with refresh token from storage
    let db_user = auth
        .storage()
        .get_user(user.user_id)
        .await
        .map_err(|e| {
            tracing::error!("Storage error fetching user for refresh: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .ok_or_else(|| {
            tracing::warn!("User not found for token refresh: {}", user.user_id);
            StatusCode::NOT_FOUND
        })?;
    let stored = db_user.tokens.ok_or_else(|| {
        tracing::warn!("No refresh token stored for user: {}", user.user_id);
        StatusCode::UNAUTHORIZED
    })?;
    let key = &auth.config().security.encryption_key;
    let current_refresh_token = stored.refresh_token.decrypt(key).map_err(|e| {
        tracing::error!("Failed to decrypt the stored refresh token: {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Refresh with Discord
    let discord_token = refresh_discord_token(auth, &current_refresh_token)
        .await
        .map_err(|e| {
            tracing::error!("Failed to refresh Discord token: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    // Store new refresh token
    let new_tokens = StoredTokens {
        refresh_token: EncryptedToken::encrypt(&discord_token.refresh_token, key).map_err(|e| {
            tracing::error!("Failed to encrypt refresh token: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
        expires_at: Utc::now() + chrono::Duration::seconds(discord_token.expires_in),
    };
    auth.storage()
        .set_tokens(user.user_id, Some(&new_tokens))
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
        &auth.config().security.jwt_secret,
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
pub async fn revoke_token<S: HasAuth + Clone>(
    user: AuthenticatedUser,
    State(state): State<S>,
) -> Result<StatusCode, StatusCode> {
    let auth = state.auth();
    tracing::info!(
        "Revoking tokens for user: {} ({})",
        user.username,
        user.user_id
    );

    // Get user with refresh token
    let db_user = auth.storage().get_user(user.user_id).await.map_err(|e| {
        tracing::error!("Storage error fetching user for revoke: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Revoke with Discord if we have a refresh token
    if let Some(stored) = db_user.and_then(|u| u.tokens) {
        match stored
            .refresh_token
            .decrypt(&auth.config().security.encryption_key)
        {
            Ok(refresh_token) => {
                if let Err(e) = revoke_discord_token(auth, &refresh_token).await {
                    tracing::warn!(
                        "Failed to revoke token with Discord (continuing anyway): {}",
                        e
                    );
                }
            }
            Err(e) => tracing::warn!("Stored refresh token unreadable, not revoked: {e}"),
        }
    }

    // Clear tokens from storage
    auth.storage()
        .set_tokens(user.user_id, None)
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

/// Log out: always delete the session cookie; if the caller is
/// authenticated, also clear their stored Discord tokens.
///
/// A missing or expired session is not an error here -- the cookie still has
/// to go, or the browser keeps sending a dead token.
pub async fn logout<S: HasAuth + Clone>(
    user: Result<AuthenticatedUser, StatusCode>,
    State(state): State<S>,
    jar: CookieJar,
) -> (CookieJar, StatusCode) {
    let auth = state.auth();
    if let Ok(user) = user {
        tracing::info!("Logging out user: {} ({})", user.username, user.user_id);
        if let Err(e) = auth.storage().set_tokens(user.user_id, None).await {
            tracing::error!("Failed to clear tokens for logout: {}", e);
        }
    }
    let jar = jar.remove(super::web::removal(
        &auth.config().web,
        auth.config().web.cookie_name.clone(),
    ));
    (jar, StatusCode::NO_CONTENT)
}

/// Get current user info from storage.
pub async fn get_current_user<S: HasAuth + Clone>(
    user: AuthenticatedUser,
    State(state): State<S>,
) -> Result<Json<UserResponse>, StatusCode> {
    let auth = state.auth();
    tracing::debug!(
        "Getting user info for authenticated user: {} ({})",
        user.username,
        user.user_id
    );

    let db_user = auth
        .storage()
        .get_user(user.user_id)
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
    auth: &Auth,
    code: &str,
) -> anyhow::Result<DiscordTokenResponse> {
    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", auth.config().discord.redirect_uri.as_str()),
    ];

    let response = auth
        .http_client()
        .post(format!("{}/oauth2/token", auth.config().discord.api_base))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(
            &auth.config().discord.client_id,
            Some(&auth.config().discord.client_secret),
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
    api_base: &str,
    access_token: &str,
    http_client: &reqwest::Client,
) -> anyhow::Result<DiscordUser> {
    let response = http_client
        .get(format!("{api_base}/users/@me"))
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
    auth: &Auth,
    refresh_token: &str,
) -> anyhow::Result<DiscordTokenResponse> {
    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
    ];

    let response = auth
        .http_client()
        .post(format!("{}/oauth2/token", auth.config().discord.api_base))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(
            &auth.config().discord.client_id,
            Some(&auth.config().discord.client_secret),
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

async fn revoke_discord_token(auth: &Auth, token: &str) -> anyhow::Result<()> {
    let params = [("token", token)];

    let response = auth
        .http_client()
        .post(format!(
            "{}/oauth2/token/revoke",
            auth.config().discord.api_base
        ))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .basic_auth(
            &auth.config().discord.client_id,
            Some(&auth.config().discord.client_secret),
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
    auth: &Auth,
    premium: &crate::config::PremiumConfig,
    user_id: i64,
) -> anyhow::Result<Vec<DiscordEntitlementResponse>> {
    let user_id_str = user_id.to_string();
    let url = format!(
        "{}/applications/{}/entitlements?user_id={}&exclude_ended=false",
        auth.config().discord.api_base,
        auth.config().discord.client_id,
        user_id_str
    );

    let response = auth
        .http_client()
        .get(&url)
        .header("Authorization", format!("Bot {}", premium.bot_token))
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
    auth: &Auth,
    user_id: i64,
    entitlements: Vec<DiscordEntitlementResponse>,
) -> anyhow::Result<SubscriptionTier> {
    let premium_sku_id = auth.config().discord.premium.as_ref().map(|p| p.sku_id);

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
        if let Err(e) = auth
            .storage()
            .upsert_entitlement(&Entitlement {
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
        auth.storage()
            .set_subscription(
                user_id,
                Some(&Subscription {
                    tier: highest_tier,
                    source: SubscriptionSource::Discord,
                    expires_at: subscription_expires,
                }),
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
