-- catacombs' own tables, used by SqlxStorage. The prefix keeps them clear of
-- a host application's tables in the same database, and the timestamp
-- version keeps this migration clear of a host's 001_... numbering.
-- Needs PostgreSQL 14 or newer (CREATE OR REPLACE TRIGGER).

CREATE TABLE IF NOT EXISTS catacombs_users (
    user_id BIGINT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    global_name VARCHAR(255),
    avatar_url VARCHAR(512),
    banner_url VARCHAR(512),
    accent_color INTEGER,
    -- catacombs ciphertext of the Discord refresh token
    refresh_token TEXT,
    token_expires_at TIMESTAMPTZ,
    subscription_tier VARCHAR(20) NOT NULL DEFAULT 'free'
        CHECK (subscription_tier IN ('free', 'premium')),
    subscription_source VARCHAR(20)
        CHECK (subscription_source IN ('discord', 'manual', 'external')),
    subscription_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS catacombs_guild_profiles (
    user_id BIGINT NOT NULL REFERENCES catacombs_users(user_id) ON DELETE CASCADE,
    guild_id BIGINT NOT NULL,
    nickname VARCHAR(255),
    avatar_url VARCHAR(512),
    banner_url VARCHAR(512),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, guild_id)
);

CREATE TABLE IF NOT EXISTS catacombs_entitlements (
    entitlement_id BIGINT PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES catacombs_users(user_id) ON DELETE CASCADE,
    sku_id BIGINT NOT NULL,
    entitlement_type INTEGER NOT NULL,
    is_test BOOLEAN NOT NULL DEFAULT FALSE,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    starts_at TIMESTAMPTZ,
    ends_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS catacombs_users_subscription_tier_idx
    ON catacombs_users (subscription_tier);
CREATE INDEX IF NOT EXISTS catacombs_guild_profiles_guild_idx
    ON catacombs_guild_profiles (guild_id);
CREATE INDEX IF NOT EXISTS catacombs_entitlements_user_idx
    ON catacombs_entitlements (user_id);
CREATE INDEX IF NOT EXISTS catacombs_entitlements_sku_idx
    ON catacombs_entitlements (sku_id);

CREATE OR REPLACE FUNCTION catacombs_set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER catacombs_users_updated_at
    BEFORE UPDATE ON catacombs_users
    FOR EACH ROW EXECUTE FUNCTION catacombs_set_updated_at();
CREATE OR REPLACE TRIGGER catacombs_guild_profiles_updated_at
    BEFORE UPDATE ON catacombs_guild_profiles
    FOR EACH ROW EXECUTE FUNCTION catacombs_set_updated_at();
CREATE OR REPLACE TRIGGER catacombs_entitlements_updated_at
    BEFORE UPDATE ON catacombs_entitlements
    FOR EACH ROW EXECUTE FUNCTION catacombs_set_updated_at();
