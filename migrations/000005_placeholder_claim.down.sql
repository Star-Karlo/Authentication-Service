-- Reverse 000005. Any placeholder company that has NOT been claimed becomes an
-- ordinary company row with no users, which is why this must not run while
-- placeholders are outstanding.
BEGIN;

DROP INDEX IF EXISTS idx_claim_tokens_one_live;
DROP INDEX IF EXISTS idx_claim_tokens_company;
DROP TABLE IF EXISTS company_claim_tokens;

DROP INDEX IF EXISTS idx_companies_placeholder;
ALTER TABLE companies
    DROP COLUMN IF EXISTS created_by_company_id,
    DROP COLUMN IF EXISTS claimed_at,
    DROP COLUMN IF EXISTS is_placeholder;

COMMIT;
