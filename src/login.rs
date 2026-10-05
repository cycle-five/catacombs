//! One login from start to finish: the code exchange, the profile, storage,
//! premium and the session token. Both flows run it, and it reports each
//! attempt to the observer.

use std::time::Instant;

use chrono::Utc;

use crate::{
    auth,
    config::PremiumConfig,
    discord::{snowflake, Discord},
    error::{LoginError, StorageError},
    models::{
        EncryptedToken, Entitlement, GuildId, StoredTokens, Subscription, SubscriptionSource,
        SubscriptionTier,
    },
    observer::{AuthEvent, Flow, LoginWarning},
    state::Auth,
};

/// What a successful login hands back to the route.
pub(crate) struct Login {
    pub jwt: String,
    pub discord_access_token: String,
}

/// Log a user in with `code`, fetching their profile in `guild` if given.
pub(crate) async fn login(
    auth: &Auth,
    flow: Flow,
    code: &str,
    guild: Option<GuildId>,
) -> Result<Login, LoginError> {
    let started = Instant::now();
    let mut warnings = Vec::new();
    let result = run(auth, code, guild, &mut warnings).await;
    auth.observer().on_event(&AuthEvent::Login {
        flow,
        result: match &result {
            Ok((user_id, _)) => Ok(*user_id),
            Err(e) => Err(e),
        },
        elapsed: started.elapsed(),
        warnings: &warnings,
    });
    match &result {
        Ok((user_id, _)) => tracing::info!(user_id, ?flow, "login succeeded"),
        Err(e) => tracing::warn!(reason = e.reason(), ?flow, "login failed: {e}"),
    }
    result.map(|(_, login)| login)
}

async fn run(
    auth: &Auth,
    code: &str,
    guild: Option<GuildId>,
    warnings: &mut Vec<LoginWarning>,
) -> Result<(i64, Login), LoginError> {
    let config = auth.config();
    let discord = Discord::new(auth.http_client(), &config.discord);
    let grant = discord.exchange_code(code).await?;
    let mut profile = discord.profile(&grant.access_token).await?;

    if let Some(guild) = guild {
        match discord
            .guild_profile(&grant.access_token, profile.id, guild)
            .await
        {
            Ok(guild_profile) => {
                profile.guilds.insert(guild, guild_profile);
            }
            Err(e) => {
                tracing::warn!("no profile for user {} in guild {guild}: {e}", profile.id);
                warnings.push(LoginWarning::GuildProfileUnavailable(guild));
            }
        }
    }

    let tokens = StoredTokens {
        refresh_token: EncryptedToken::encrypt(
            &grant.refresh_token,
            &config.security.encryption_key,
        )
        .map_err(|e| StorageError::Other(format!("encrypting the refresh token: {e}")))?,
        expires_at: Utc::now() + chrono::Duration::seconds(grant.expires_in),
    };
    auth.storage().upsert_user(&profile, Some(&tokens)).await?;

    if let Some(premium) = &config.discord.premium {
        if let Err(e) = reconcile_premium(auth, &discord, premium, profile.id).await {
            tracing::warn!("premium not reconciled for user {}: {e}", profile.id);
            warnings.push(LoginWarning::EntitlementsUnavailable);
        }
    }

    let jwt = auth::generate_token(profile.id, &profile.username, &config.security.jwt_secret)
        .map_err(|e| {
            tracing::error!("signing the session token failed: {e}");
            LoginError::Session
        })?;
    Ok((
        profile.id,
        Login {
            jwt,
            discord_access_token: grant.access_token,
        },
    ))
}

/// Bring the user's subscription in line with their Discord entitlements.
///
/// Errors when Discord cannot be asked. The stored subscription is then left
/// alone, so an outage never downgrades a paying user. Only a subscription
/// that came from Discord is ever taken away; manual and external grants stay.
async fn reconcile_premium(
    auth: &Auth,
    discord: &Discord<'_>,
    premium: &PremiumConfig,
    user_id: i64,
) -> anyhow::Result<()> {
    let storage = auth.storage();
    let entitlements = discord.entitlements(premium, user_id).await?;
    let now = Utc::now();
    let mut active = false;
    let mut lifetime = false;
    let mut latest_end = None;

    for e in entitlements.iter().filter(|e| !e.deleted) {
        let (Some(entitlement_id), Some(sku_id)) = (snowflake(&e.id), snowflake(&e.sku_id)) else {
            tracing::warn!("skipping an entitlement with a malformed id: {e:?}");
            continue;
        };
        let record = Entitlement {
            entitlement_id,
            user_id,
            sku_id,
            entitlement_type: e.entitlement_type,
            is_test: false,
            consumed: e.consumed,
            starts_at: e.starts_at,
            ends_at: e.ends_at,
        };
        if let Err(err) = storage.upsert_entitlement(&record).await {
            tracing::warn!("entitlement {entitlement_id} not stored: {err}");
        }
        if sku_id != premium.sku_id {
            continue;
        }
        match e.ends_at {
            None => {
                active = true;
                lifetime = true;
            }
            Some(ends) if ends > now => {
                active = true;
                latest_end = latest_end.max(Some(ends));
            }
            Some(_) => {}
        }
    }

    if active {
        let subscription = Subscription {
            tier: SubscriptionTier::Premium,
            source: SubscriptionSource::Discord,
            expires_at: if lifetime { None } else { latest_end },
        };
        storage
            .set_subscription(user_id, Some(&subscription))
            .await?;
    } else {
        let from_discord = storage
            .get_user(user_id)
            .await?
            .is_some_and(|u| u.subscription_source == Some(SubscriptionSource::Discord));
        if from_discord {
            storage.set_subscription(user_id, None).await?;
        }
    }
    Ok(())
}
