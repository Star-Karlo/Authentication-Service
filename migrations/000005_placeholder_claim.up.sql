-- Placeholder companies and the links that claim them.
--
-- A transporter can place orders for a shipper who has no Karlo account yet.
-- Orders require a non-null shipper company, so a real companies row has to
-- exist — but it must not be a working tenant until a real person adopts it.
--
-- The claim link is a BEARER CREDENTIAL: whoever holds it can take ownership of
-- a company and everything already recorded against it. It is treated with the
-- same care as a refresh token, which is why the token itself is never stored.

BEGIN;

-- ---------------------------------------------------------------------------
-- Placeholder companies
-- ---------------------------------------------------------------------------
-- claimed_at NULL marks a company nobody has adopted yet. Deliberately a
-- timestamp rather than a boolean: "when did this become real" is the question
-- support actually asks, and a boolean cannot answer it.
--
-- An unclaimed company has no users, so nothing can authenticate as it, and no
-- entitlement, so it consumes no seat. It exists only to be named as the
-- shipper on an order.

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS is_placeholder BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ,
    -- Who stood it up. A placeholder is created BY another company on someone
    -- else's behalf, and only that company may re-issue or revoke its link.
    ADD COLUMN IF NOT EXISTS created_by_company_id UUID REFERENCES companies(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_companies_placeholder
    ON companies (created_by_company_id) WHERE is_placeholder;

COMMENT ON COLUMN companies.is_placeholder IS
    'Stood up by another company on behalf of a shipper with no account. No users, no entitlement, may be named as a shipper on orders and nothing else.';

COMMENT ON COLUMN companies.claimed_at IS
    'When a real person adopted this company. NULL means unclaimed.';

-- ---------------------------------------------------------------------------
-- Claim tokens
-- ---------------------------------------------------------------------------
-- Only the SHA-256 of the token is stored. A database leak then exposes no
-- usable links — the same reason refresh tokens are hashed, and it matters more
-- here because a claim link has no expiry short enough to limit the damage on
-- its own.

CREATE TABLE IF NOT EXISTS company_claim_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id  UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,

    -- SHA-256 hex of the token. Unique so a collision is refused by the
    -- database rather than silently overwriting a live link.
    token_hash  CHAR(64) NOT NULL UNIQUE,

    -- Who issued it, for the audit trail and for the re-issue permission check.
    issued_by_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    issued_by_company_id UUID REFERENCES companies(id) ON DELETE SET NULL,

    expires_at  TIMESTAMPTZ NOT NULL,

    -- Set when the link is used. Single-use: claiming consumes it atomically,
    -- so two people opening the same link cannot both succeed.
    claimed_at         TIMESTAMPTZ,
    claimed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    -- Set when re-issued or withdrawn. A revoked row is kept rather than
    -- deleted so "who cancelled that invitation" has an answer.
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(32),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- At most ONE live link per company. Re-issuing must replace rather than add:
-- two valid links to the same company doubles the exposure for no benefit, and
-- makes revocation something you can do incompletely.
CREATE UNIQUE INDEX IF NOT EXISTS idx_claim_tokens_one_live
    ON company_claim_tokens (company_id)
    WHERE claimed_at IS NULL AND revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_claim_tokens_company
    ON company_claim_tokens (company_id);

COMMENT ON TABLE company_claim_tokens IS
    'Bearer credentials that transfer ownership of a placeholder company. Only the hash is stored; the token is shown once, at issue.';

COMMIT;
