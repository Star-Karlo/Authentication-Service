-- Remove state that can be derived, and fold the claim link into the company.
--
-- Three simplifications, all the same idea: a fact stored twice can disagree
-- with itself, and a fact that can be derived should be.
--
--   users.invited_by_user_id  — written everywhere, read for nothing. The
--                               audit log already records who created an
--                               account, with an actor and a timestamp, which
--                               is a better record than a bare column.
--
--   companies.is_placeholder  — a placeholder IS a company with no users. The
--   companies.claimed_at        flag was a second copy of that, and the schema
--                               allowed it to be TRUE on a company with three
--                               users, which is a contradiction nothing
--                               prevented. claimed_at is likewise just when
--                               the first user appeared.
--
--   company_claim_tokens      — one link per company, single-use, re-issuing
--                               overrides the old one. That is one row at most,
--                               ever, which is a column rather than a table.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. The claim link moves onto the company
-- ---------------------------------------------------------------------------
-- Only the SHA-256 is stored, never the link. A database leak then exposes
-- nothing usable: a hash cannot be turned back into a claimable URL. That is
-- what makes it safe to keep on a row that is serialised to API clients, and
-- the Go field is tagged json:"-" so it is never sent anyway.

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS claim_token_hash CHAR(64),
    ADD COLUMN IF NOT EXISTS claim_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS claim_issued_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- Carry across any live token before the table goes.
UPDATE companies c
SET claim_token_hash        = t.token_hash,
    claim_expires_at        = t.expires_at,
    claim_issued_by_user_id = t.issued_by_user_id
FROM company_claim_tokens t
WHERE t.company_id = c.id
  AND t.claimed_at IS NULL
  AND t.revoked_at IS NULL;

-- Finding a company by the link someone opened. Partial, because the vast
-- majority of companies have no live link and indexing their NULLs would be
-- most of the table for nothing.
CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_claim_hash
    ON companies (claim_token_hash) WHERE claim_token_hash IS NOT NULL;

COMMENT ON COLUMN companies.claim_token_hash IS
    'SHA-256 of the live claim link, or NULL. Single-use: cleared when claimed. Re-issuing overwrites, so a company has at most one live link by construction. Never serialised.';

DROP TABLE IF EXISTS company_claim_tokens;

-- ---------------------------------------------------------------------------
-- 2. Derived state removed
-- ---------------------------------------------------------------------------
-- created_by_company_id STAYS. It is the one fact here that cannot be derived:
-- which transporter stood this company up. It is also the permission check for
-- who may re-issue or revoke the link — without it, any company could issue a
-- claim link for any other.

DROP INDEX IF EXISTS idx_companies_placeholder;

CREATE INDEX IF NOT EXISTS idx_companies_created_by
    ON companies (created_by_company_id) WHERE created_by_company_id IS NOT NULL;

ALTER TABLE companies
    DROP COLUMN IF EXISTS is_placeholder,
    DROP COLUMN IF EXISTS claimed_at;

-- A placeholder is now a question, not a column:
--
--   SELECT c.* FROM companies c
--   WHERE NOT EXISTS (SELECT 1 FROM users u
--                     WHERE u.company_id = c.id AND u.deleted_at IS NULL);
--
-- and when it was claimed is MIN(users.created_at) for that company.

-- ---------------------------------------------------------------------------
-- 3. invited_by_user_id
-- ---------------------------------------------------------------------------

ALTER TABLE users DROP COLUMN IF EXISTS invited_by_user_id;

COMMIT;
