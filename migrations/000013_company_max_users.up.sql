-- A seat limit per company.
--
-- Karlo grants a company its features and how many people may hold accounts.
-- Without this, entitlement controls WHAT a company can do but not HOW MANY
-- people can do it, so a two-seat customer and a two-hundred-seat customer are
-- indistinguishable to the system.
--
-- Counted as ACTIVE users: soft-deleted accounts do not occupy a seat. That is
-- the behaviour anyone would expect — removing someone should free their seat —
-- and it is why the count is a query rather than a stored tally, which would
-- drift every time an account was deleted, restored or suspended.
--
-- Suspended accounts DO occupy a seat. A suspension is temporary and the person
-- is expected back; freeing the seat would mean their return could fail because
-- somebody else took it.

BEGIN;

ALTER TABLE companies
    -- 0 means unlimited, matching default_max_devices. Existing companies are
    -- unlimited, so nothing is restricted until Karlo sets a number.
    ADD COLUMN IF NOT EXISTS max_users INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN companies.max_users IS
    'How many active accounts this company may hold. 0 is unlimited. Soft-deleted accounts do not count; suspended ones do.';

-- The seat check counts users in one company, which is what this index serves.
-- idx_users_company already covers (company_id) WHERE deleted_at IS NULL, so
-- there is nothing to add — noted here so the next reader does not add a
-- duplicate.

COMMIT;
