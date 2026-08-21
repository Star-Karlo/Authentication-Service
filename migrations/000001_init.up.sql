-- Authentication service schema.
--
-- The legacy system had one `users` collection carrying three separate
-- concerns: the company (a "mainAccount"), the person (a "subAccount"), and the
-- session. Those are split into three tables here, because conflating them is
-- what made the legacy permission logic so hard to reason about.

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "citext";

-- ---------------------------------------------------------------------------
-- Companies
-- ---------------------------------------------------------------------------

CREATE TABLE companies (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- legacy_id preserves the Mongo ObjectId so a later data migration can map
    -- references that still live in other systems.
    legacy_id               VARCHAR(24) UNIQUE,
    name                    VARCHAR(255) NOT NULL,
    -- role is the company's function: shipper, transporter, or both.
    role                    VARCHAR(32)  NOT NULL,
    npwp                    VARCHAR(32),
    no_siup                 VARCHAR(64),
    no_tdp                  VARCHAR(64),
    address                 TEXT,
    city_id                 VARCHAR(64),
    province_id             VARCHAR(64),
    company_profile         TEXT,
    logo_url                TEXT,
    banner_url              TEXT,
    -- settings holds the per-company business toggles. JSONB rather than
    -- columns because business rules add toggles frequently and each one is
    -- read as a whole object.
    settings                JSONB NOT NULL DEFAULT '{
        "cancelWithValidate": false,
        "finishWithGeofencing": false,
        "activeAgreementVerifiedOnly": false,
        "ppnPercentage": 0.02,
        "pph23Percentage": 0.11,
        "useStrictAgreement": false,
        "maxDriverAvailableAfterOrderDone": 0,
        "accessTolls": false
    }'::jsonb,
    bank_account            JSONB,
    email_recipients        TEXT[] NOT NULL DEFAULT '{}',
    is_verified             BOOLEAN NOT NULL DEFAULT FALSE,
    is_suspended            BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_companies_role       ON companies (role) WHERE deleted_at IS NULL;
CREATE INDEX idx_companies_legacy_id  ON companies (legacy_id);

-- ---------------------------------------------------------------------------
-- Users
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legacy_id               VARCHAR(24) UNIQUE,
    company_id              UUID REFERENCES companies (id) ON DELETE RESTRICT,
    -- parent_id is the user who created this account. NULL means a root
    -- account, which the permission model treats as unrestricted.
    parent_id               UUID REFERENCES users (id) ON DELETE SET NULL,

    username                CITEXT,
    email                   CITEXT,
    phone                   VARCHAR(32),
    -- password_hash is bcrypt. It is never selected by the default query scope;
    -- see the repository.
    password_hash           VARCHAR(255) NOT NULL,
    full_name               VARCHAR(255),

    role                    VARCHAR(32) NOT NULL,
    account_type            VARCHAR(32) NOT NULL DEFAULT 'subAccount',

    -- permission is module -> action -> bool, applied only to non-root accounts.
    permission              JSONB NOT NULL DEFAULT '{}'::jsonb,

    birth_date              DATE,
    address                 TEXT,
    city_id                 VARCHAR(64),
    photo_url               TEXT,
    language                VARCHAR(8) NOT NULL DEFAULT 'id',

    emergency_contact_name  VARCHAR(255),
    emergency_contact_phone VARCHAR(32),
    alternative_phones      JSONB NOT NULL DEFAULT '[]'::jsonb,

    is_email_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    is_phone_verified       BOOLEAN NOT NULL DEFAULT FALSE,
    is_verified             BOOLEAN NOT NULL DEFAULT FALSE,
    is_suspended            BOOLEAN NOT NULL DEFAULT FALSE,
    accepted_tnc_at         TIMESTAMPTZ,

    average_rating          NUMERIC(3,2),
    rating_count            INTEGER NOT NULL DEFAULT 0,

    last_login_at           TIMESTAMPTZ,
    deleted_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Partial unique indexes: identifiers must be unique among live accounts, but a
-- soft-deleted user must not block reuse of their email or phone.
CREATE UNIQUE INDEX uq_users_email    ON users (email)    WHERE deleted_at IS NULL AND email IS NOT NULL;
CREATE UNIQUE INDEX uq_users_username ON users (username) WHERE deleted_at IS NULL AND username IS NOT NULL;
CREATE UNIQUE INDEX uq_users_phone    ON users (phone)    WHERE deleted_at IS NULL AND phone IS NOT NULL;

CREATE INDEX idx_users_company    ON users (company_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_parent     ON users (parent_id)  WHERE deleted_at IS NULL;
CREATE INDEX idx_users_role       ON users (role)       WHERE deleted_at IS NULL;
CREATE INDEX idx_users_legacy_id  ON users (legacy_id);

-- ---------------------------------------------------------------------------
-- Sessions
-- ---------------------------------------------------------------------------

-- Sessions exist so a token can be revoked. The legacy design stored a single
-- token string on the user row, which meant logging in on a second device
-- silently invalidated the first and there was no way to list active sessions.
CREATE TABLE sessions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- token_id matches the jti claim of the issued JWT.
    token_id                UUID NOT NULL UNIQUE,
    -- refresh_token_hash is a SHA-256 of the refresh token. The token itself is
    -- never stored, so a database leak does not yield usable sessions.
    refresh_token_hash      VARCHAR(64) UNIQUE,
    -- single_device marks sessions under the legacy tokenKapps rule, where a
    -- new login must evict the previous one.
    single_device           BOOLEAN NOT NULL DEFAULT FALSE,
    device_id               VARCHAR(255),
    platform                VARCHAR(32),
    user_agent              TEXT,
    ip_address             INET,
    expires_at              TIMESTAMPTZ NOT NULL,
    revoked_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_sessions_user    ON sessions (user_id) WHERE revoked_at IS NULL;
CREATE INDEX idx_sessions_expires ON sessions (expires_at) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Device push tokens
-- ---------------------------------------------------------------------------

-- One row per device rather than one token per user. The legacy schema kept a
-- single tokenfcm on the user, so a driver with a phone and a tablet only ever
-- received notifications on whichever had logged in last.
CREATE TABLE device_tokens (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    push_token              TEXT NOT NULL,
    platform                VARCHAR(32),
    device_id               VARCHAR(255),
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    -- failed_at records the last delivery rejection, so dead tokens can be
    -- pruned instead of retried forever.
    failed_at               TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (user_id, push_token)
);

CREATE INDEX idx_device_tokens_user ON device_tokens (user_id) WHERE is_active;

-- ---------------------------------------------------------------------------
-- API keys
-- ---------------------------------------------------------------------------

-- Replaces the ten hardcoded 32-character tokens that were compiled into the
-- monolith's constants file. Keys are stored hashed, scoped, and expirable.
CREATE TABLE api_keys (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                    VARCHAR(255) NOT NULL,
    -- key_hash is SHA-256 of the key. The plaintext is shown once at creation.
    key_hash                VARCHAR(64) NOT NULL UNIQUE,
    -- key_prefix is the first 8 characters, kept in clear so an operator can
    -- identify a key in a list without being able to use it.
    key_prefix              VARCHAR(8) NOT NULL,
    user_id                 UUID REFERENCES users (id) ON DELETE CASCADE,
    company_id              UUID REFERENCES companies (id) ON DELETE CASCADE,
    scopes                  TEXT[] NOT NULL DEFAULT '{}',
    is_active               BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at            TIMESTAMPTZ,
    expires_at              TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at              TIMESTAMPTZ
);

CREATE INDEX idx_api_keys_active ON api_keys (key_hash) WHERE is_active AND revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Document verification
-- ---------------------------------------------------------------------------

-- The legacy user row carried ~16 paired columns (fotoKtp / isKtpVerified,
-- fotoSiup / isSiupVerified, ...). One row per document instead, so adding a
-- document type is data rather than a migration.
CREATE TABLE user_documents (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID REFERENCES users (id) ON DELETE CASCADE,
    company_id              UUID REFERENCES companies (id) ON DELETE CASCADE,
    doc_type                VARCHAR(32) NOT NULL,
    doc_number              VARCHAR(64),
    file_url                TEXT,
    status                  VARCHAR(16) NOT NULL DEFAULT 'pending',
    rejection_reason        TEXT,
    verified_by             UUID REFERENCES users (id) ON DELETE SET NULL,
    verified_at             TIMESTAMPTZ,
    expires_at              DATE,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_user_documents_owner CHECK (user_id IS NOT NULL OR company_id IS NOT NULL),
    CONSTRAINT chk_user_documents_status CHECK (status IN ('pending', 'verified', 'rejected'))
);

CREATE INDEX idx_user_documents_user    ON user_documents (user_id);
CREATE INDEX idx_user_documents_company ON user_documents (company_id);
CREATE INDEX idx_user_documents_status  ON user_documents (status);

-- ---------------------------------------------------------------------------
-- Collaboration invitations
-- ---------------------------------------------------------------------------

CREATE TABLE collaboration_invites (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inviter_user_id         UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    inviter_company_id      UUID NOT NULL REFERENCES companies (id) ON DELETE CASCADE,
    invitee_company_id      UUID REFERENCES companies (id) ON DELETE CASCADE,
    invitee_email           CITEXT,
    invitee_phone           VARCHAR(32),
    role                    VARCHAR(32) NOT NULL,
    permission              JSONB NOT NULL DEFAULT '{}'::jsonb,
    -- token_hash secures the accept link; the plaintext goes only to the invitee.
    token_hash              VARCHAR(64) UNIQUE,
    status                  VARCHAR(16) NOT NULL DEFAULT 'pending',
    expires_at              TIMESTAMPTZ NOT NULL,
    responded_at            TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_collab_status CHECK (status IN ('pending', 'accepted', 'rejected', 'expired', 'revoked'))
);

CREATE INDEX idx_collab_inviter ON collaboration_invites (inviter_company_id);
CREATE INDEX idx_collab_status  ON collaboration_invites (status, expires_at);

-- ---------------------------------------------------------------------------
-- Auth audit log
-- ---------------------------------------------------------------------------

-- The legacy system had no record of authentication events, which made
-- "who changed this account" unanswerable. Written on login, logout, password
-- change, permission change and suspension.
CREATE TABLE auth_audit_log (
    id                      BIGSERIAL PRIMARY KEY,
    user_id                 UUID REFERENCES users (id) ON DELETE SET NULL,
    actor_user_id           UUID REFERENCES users (id) ON DELETE SET NULL,
    event                   VARCHAR(64) NOT NULL,
    succeeded               BOOLEAN NOT NULL DEFAULT TRUE,
    ip_address              INET,
    user_agent              TEXT,
    detail                  JSONB,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user  ON auth_audit_log (user_id, created_at DESC);
CREATE INDEX idx_audit_event ON auth_audit_log (event, created_at DESC);

-- ---------------------------------------------------------------------------
-- updated_at maintenance
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_companies_updated_at     BEFORE UPDATE ON companies      FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_users_updated_at         BEFORE UPDATE ON users          FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_device_tokens_updated_at BEFORE UPDATE ON device_tokens  FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER trg_user_documents_updated_at BEFORE UPDATE ON user_documents FOR EACH ROW EXECUTE FUNCTION set_updated_at();
