-- Reverse 000010.
--
-- NOT lossless, and the columns come back EMPTY. Their contents were frozen at
-- 000003 and could not be reconstructed from the role model even in principle:
-- a role is shared by many people, so there is no way to know which of its keys
-- any individual once held directly.
--
-- role is NOT NULL, so it is backfilled with a placeholder rather than a real
-- value. Nothing should read it; that is why it was dropped.
BEGIN;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role VARCHAR(32) NOT NULL DEFAULT 'unknown',
    ADD COLUMN IF NOT EXISTS permission JSONB NOT NULL DEFAULT '{}';

CREATE INDEX IF NOT EXISTS idx_users_role ON users (role) WHERE deleted_at IS NULL;

COMMIT;
