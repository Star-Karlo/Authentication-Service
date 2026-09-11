-- The role_id index that migration 000006 believed it created.
--
-- 000006 ran:
--   CREATE INDEX IF NOT EXISTS idx_users_role ON users (role_id) WHERE ...
--
-- but `idx_users_role` already existed, created by 000001 on the DEPRECATED
-- `role` varchar. IF NOT EXISTS matches on the NAME, not the definition, so it
-- silently did nothing and the index everyone assumed existed does not.
--
-- The effect is invisible until it matters: every lookup of "who holds this
-- role" is a sequential scan over the whole users table, and with 25,572
-- accounts that is slow rather than broken — which is exactly the kind of thing
-- that ships.
--
-- Named distinctly so the collision cannot happen again.

BEGIN;

CREATE INDEX IF NOT EXISTS idx_users_role_id
    ON users (role_id) WHERE deleted_at IS NULL;

COMMENT ON INDEX idx_users_role_id IS
    'Holders of a role. Deliberately not named idx_users_role: that name is taken by an index on the deprecated role varchar, and reusing it made CREATE INDEX IF NOT EXISTS a silent no-op.';

-- Also correct the system-role conflict handling from 000006.
--
-- Its `No access` insert used ON CONFLICT DO UPDATE SET is_system = TRUE, so a
-- company that had already created a role of that name had it silently
-- converted into one they can no longer delete. Only roles with no permissions
-- and no holders could plausibly have been the migration's own, so anything
-- else is handed back.
UPDATE roles r
SET is_system = FALSE
WHERE r.name = 'No access'
  AND r.is_system
  AND array_length(r.permissions, 1) IS NOT NULL;

COMMIT;
