-- Reverse 000009.
--
-- NOT lossless. is_placeholder and claimed_at are reconstructed from whether a
-- company has users, which is what they meant; invited_by_user_id cannot be
-- reconstructed at all and comes back empty, because the information only ever
-- existed in this column.
BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS invited_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS is_placeholder BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ;

UPDATE companies c SET is_placeholder = TRUE
WHERE NOT EXISTS (SELECT 1 FROM users u WHERE u.company_id = c.id AND u.deleted_at IS NULL);

UPDATE companies c SET claimed_at = sub.first_user
FROM (SELECT company_id, MIN(created_at) AS first_user FROM users
      WHERE company_id IS NOT NULL GROUP BY company_id) sub
WHERE sub.company_id = c.id;

CREATE INDEX IF NOT EXISTS idx_companies_placeholder
    ON companies (created_by_company_id) WHERE is_placeholder;

CREATE TABLE IF NOT EXISTS company_claim_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id  UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    token_hash  CHAR(64) NOT NULL UNIQUE,
    issued_by_user_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    issued_by_company_id UUID REFERENCES companies(id) ON DELETE SET NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    claimed_at         TIMESTAMPTZ,
    claimed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO company_claim_tokens (company_id, token_hash, issued_by_user_id, expires_at)
SELECT id, claim_token_hash, claim_issued_by_user_id, claim_expires_at
FROM companies WHERE claim_token_hash IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_claim_tokens_one_live
    ON company_claim_tokens (company_id) WHERE claimed_at IS NULL AND revoked_at IS NULL;

DROP INDEX IF EXISTS idx_companies_claim_hash;
DROP INDEX IF EXISTS idx_companies_created_by;
ALTER TABLE companies
    DROP COLUMN IF EXISTS claim_token_hash,
    DROP COLUMN IF EXISTS claim_expires_at,
    DROP COLUMN IF EXISTS claim_issued_by_user_id;

COMMIT;
