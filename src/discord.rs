//! Discord's REST API, as catacombs uses it. Crate-private: hosts see the
//! results (profiles, errors), not the calls.

use chrono::{DateTime, Utc};
use reqwest::{header::AUTHORIZATION, Client, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    config::{DiscordConfig, PremiumConfig},
    error::{LoginError, Rejection},
    models::{DiscordProfile, GuildId, GuildProfile},
};

const CDN: &str = "https://cdn.discordapp.com";

/// Tokens from `/oauth2/token`.
#[derive(Debug, Deserialize)]
pub(crate) struct TokenGrant {
    pub access_token: String,
    pub expires_in: i64,
    pub refresh_token: String,
}

/// One entitlement from the application's entitlements list.
#[derive(Debug, Deserialize)]
pub(crate) struct DiscordEntitlement {
    pub id: String,
    pub sku_id: String,
    #[serde(rename = "type")]
    pub entitlement_type: i32,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub consumed: bool,
    pub starts_at: Option<DateTime<Utc>>,
    pub ends_at: Option<DateTime<Utc>>,
}

/// An OAuth error body (RFC 6749, section 5.2).
#[derive(Deserialize)]
struct OAuthError {
    error: String,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    global_name: Option<String>,
    avatar: Option<String>,
    banner: Option<String>,
    accent_color: Option<i32>,
}

#[derive(Deserialize)]
struct GuildMember {
    nick: Option<String>,
    avatar: Option<String>,
    banner: Option<String>,
}

#[derive(Serialize)]
struct CodeGrant<'a> {
    grant_type: &'static str,
    code: &'a str,
    redirect_uri: &'a str,
}

#[derive(Serialize)]
struct RefreshGrant<'a> {
    grant_type: &'static str,
    refresh_token: &'a str,
}

#[derive(Serialize)]
struct RevokeForm<'a> {
    token: &'a str,
}

#[derive(Serialize)]
struct EntitlementQuery {
    user_id: u64,
    exclude_ended: bool,
}

/// A snowflake as Discord writes it, wrapped into `i64` like every stored ID.
pub(crate) fn snowflake(s: &str) -> Option<i64> {
    s.parse::<u64>().ok().map(|n| n as i64)
}

/// `{CDN}/{path}/{hash}.{gif|png}?size=1024`. A hash starting `a_` is animated.
fn cdn_image(path: &str, hash: &str) -> String {
    let ext = if hash.starts_with("a_") { "gif" } else { "png" };
    format!("{CDN}/{path}/{hash}.{ext}?size=1024")
}

/// Map a failed token response to a [`LoginError`].
pub(crate) fn classify(status: StatusCode, body: &str) -> LoginError {
    if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
        return LoginError::DiscordUnavailable;
    }
    let kind = serde_json::from_str::<OAuthError>(body)
        .map(|e| e.error)
        .unwrap_or_default();
    LoginError::DiscordRejected(match kind.as_str() {
        "invalid_grant" => Rejection::InvalidGrant,
        "invalid_client" => Rejection::InvalidClient,
        _ => Rejection::Other,
    })
}

impl DiscordUser {
    fn into_profile(self) -> Option<DiscordProfile> {
        let id = snowflake(&self.id)?;
        let mut profile = DiscordProfile::new(id, self.username);
        profile.global_name = self.global_name;
        profile.avatar_url = self
            .avatar
            .map(|h| cdn_image(&format!("avatars/{}", self.id), &h));
        profile.banner_url = self
            .banner
            .map(|h| cdn_image(&format!("banners/{}", self.id), &h));
        profile.accent_color = self.accent_color;
        Some(profile)
    }
}

impl GuildMember {
    fn into_profile(self, user_id: i64, guild: GuildId) -> GuildProfile {
        let base = format!("guilds/{guild}/users/{}", user_id as u64);
        GuildProfile {
            nickname: self.nick,
            avatar_url: self
                .avatar
                .map(|h| cdn_image(&format!("{base}/avatars"), &h)),
            banner_url: self
                .banner
                .map(|h| cdn_image(&format!("{base}/banners"), &h)),
        }
    }
}

/// The calls catacombs makes, bound to one client and configuration.
pub(crate) struct Discord<'a> {
    http: &'a Client,
    config: &'a DiscordConfig,
}

impl<'a> Discord<'a> {
    pub(crate) fn new(http: &'a Client, config: &'a DiscordConfig) -> Self {
        Self { http, config }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.api_base)
    }

    fn as_app(&self, req: RequestBuilder) -> RequestBuilder {
        req.basic_auth(&self.config.client_id, Some(&self.config.client_secret))
    }

    /// Trade an authorization code for tokens.
    pub(crate) async fn exchange_code(&self, code: &str) -> Result<TokenGrant, LoginError> {
        self.token(&CodeGrant {
            grant_type: "authorization_code",
            code,
            redirect_uri: &self.config.redirect_uri,
        })
        .await
    }

    /// Trade a refresh token for new tokens.
    pub(crate) async fn refresh(&self, refresh_token: &str) -> Result<TokenGrant, LoginError> {
        self.token(&RefreshGrant {
            grant_type: "refresh_token",
            refresh_token,
        })
        .await
    }

    async fn token(&self, form: &impl Serialize) -> Result<TokenGrant, LoginError> {
        let resp = self
            .as_app(self.http.post(self.url("/oauth2/token")))
            .form(form)
            .send()
            .await
            .map_err(|e| {
                tracing::error!("discord token request failed: {e}");
                LoginError::DiscordUnavailable
            })?;
        let status = resp.status();
        if status.is_success() {
            return resp.json().await.map_err(|e| {
                tracing::error!("unreadable discord token response: {e}");
                LoginError::DiscordUnavailable
            });
        }
        let body = resp.text().await.unwrap_or_default();
        tracing::error!("discord token request refused: {status} {body}");
        Err(classify(status, &body))
    }

    /// The user behind `access_token`.
    pub(crate) async fn profile(&self, access_token: &str) -> Result<DiscordProfile, LoginError> {
        let user: DiscordUser = async {
            self.http
                .get(self.url("/users/@me"))
                .bearer_auth(access_token)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await
        }
        .await
        .map_err(|e: reqwest::Error| {
            tracing::error!("discord /users/@me failed: {e}");
            LoginError::BadProfile
        })?;
        user.into_profile().ok_or(LoginError::BadProfile)
    }

    /// The user's profile in `guild`. Needs the `guilds.members.read` scope.
    // Called by the login flow in a later change.
    #[allow(dead_code)]
    pub(crate) async fn guild_profile(
        &self,
        access_token: &str,
        user_id: i64,
        guild: GuildId,
    ) -> anyhow::Result<GuildProfile> {
        let member: GuildMember = self
            .http
            .get(self.url(&format!("/users/@me/guilds/{guild}/member")))
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(member.into_profile(user_id, guild))
    }

    /// Revoke a token with Discord.
    pub(crate) async fn revoke(&self, token: &str) -> anyhow::Result<()> {
        self.as_app(self.http.post(self.url("/oauth2/token/revoke")))
            .form(&RevokeForm { token })
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// The user's entitlements in this application.
    ///
    /// Errors when Discord does not answer with a list. A caller must not
    /// read an error as "no entitlements": that would downgrade a paying
    /// user during an outage.
    pub(crate) async fn entitlements(
        &self,
        premium: &PremiumConfig,
        user_id: i64,
    ) -> anyhow::Result<Vec<DiscordEntitlement>> {
        Ok(self
            .http
            .get(self.url(&format!(
                "/applications/{}/entitlements",
                self.config.client_id
            )))
            .query(&EntitlementQuery {
                user_id: user_id as u64,
                exclude_ended: false,
            })
            .header(AUTHORIZATION, format!("Bot {}", premium.bot_token))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(id: &str, avatar: Option<&str>, banner: Option<&str>) -> DiscordUser {
        DiscordUser {
            id: id.into(),
            username: "u".into(),
            global_name: Some("U".into()),
            avatar: avatar.map(Into::into),
            banner: banner.map(Into::into),
            accent_color: Some(0x11_22_33),
        }
    }

    #[test]
    fn oauth_errors_are_classified_from_the_body() {
        let rejected =
            |status: u16, body: &str| classify(StatusCode::from_u16(status).unwrap(), body);
        assert!(matches!(
            rejected(
                400,
                r#"{"error":"invalid_grant","error_description":"bad"}"#
            ),
            LoginError::DiscordRejected(Rejection::InvalidGrant)
        ));
        assert!(matches!(
            rejected(401, r#"{"error":"invalid_client"}"#),
            LoginError::DiscordRejected(Rejection::InvalidClient)
        ));
        assert!(matches!(
            rejected(400, "not json"),
            LoginError::DiscordRejected(Rejection::Other)
        ));
        assert!(matches!(rejected(503, ""), LoginError::DiscordUnavailable));
        assert!(matches!(rejected(429, ""), LoginError::DiscordUnavailable));
    }

    #[test]
    fn a_user_without_an_avatar_has_none_not_a_default_url() {
        let profile = user("1", None, None).into_profile().unwrap();
        assert_eq!(profile.avatar_url, None);
        assert_eq!(profile.banner_url, None);
        assert_eq!(profile.accent_color, Some(0x11_22_33));
        assert_eq!(profile.global_name.as_deref(), Some("U"));
    }

    #[test]
    fn animated_images_are_gifs_and_still_ones_pngs() {
        let profile = user("1", Some("a_anim"), Some("still"))
            .into_profile()
            .unwrap();
        assert_eq!(
            profile.avatar_url.as_deref(),
            Some("https://cdn.discordapp.com/avatars/1/a_anim.gif?size=1024")
        );
        assert_eq!(
            profile.banner_url.as_deref(),
            Some("https://cdn.discordapp.com/banners/1/still.png?size=1024")
        );
    }

    #[test]
    fn user_ids_above_i64_max_wrap_and_garbage_is_refused() {
        let profile = user("18446744073709551615", None, None)
            .into_profile()
            .unwrap();
        assert_eq!(profile.id, -1);
        assert!(user("abc", None, None).into_profile().is_none());
    }

    #[test]
    fn guild_member_images_use_the_guild_paths() {
        let member = GuildMember {
            nick: Some("n".into()),
            avatar: Some("gav".into()),
            banner: Some("a_gban".into()),
        };
        let profile = member.into_profile(7, GuildId(9));
        assert_eq!(profile.nickname.as_deref(), Some("n"));
        assert_eq!(
            profile.avatar_url.as_deref(),
            Some("https://cdn.discordapp.com/guilds/9/users/7/avatars/gav.png?size=1024")
        );
        assert_eq!(
            profile.banner_url.as_deref(),
            Some("https://cdn.discordapp.com/guilds/9/users/7/banners/a_gban.gif?size=1024")
        );
    }
}
