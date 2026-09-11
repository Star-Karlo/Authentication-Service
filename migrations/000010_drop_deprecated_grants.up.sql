-- Remove the last two columns of the pre-role access model.
--
-- users.role and users.permission were the whole of access before 000003.
-- They were kept afterwards so a reverted deploy would still find its data —
-- a reasonable precaution for one release, and six migrations of dead weight
-- since.
--
-- Keeping them was not free. Both were still being READ for live decisions
-- while carrying values nothing had maintained since 000003:
--
--   * CheckPermission — a gRPC method other services call — ended in
--     `user.Permission.Allows(module, action)`. Every caller was told "no" for
--     permissions the person genuinely held through their role. Administrators
--     were unaffected, because a grants_all check returned first, which is
--     precisely why it went unnoticed: the accounts most likely to be tested
--     were the ones it did not break.
--
--   * The single-device rule read `users.role` through a hardcoded map of
--     legacy role names. It happened to work, because the importer and seed
--     still wrote that column — a live decision resting on a column nobody
--     maintained.
--
-- Both now resolve the same way a request does. Dropping the columns is what
-- stops a third reader appearing.

BEGIN;

-- The index on the deprecated column goes with it. This is the name that made
-- 000006's CREATE INDEX IF NOT EXISTS a silent no-op, so removing it also
-- removes the trap.
DROP INDEX IF EXISTS idx_users_role;

ALTER TABLE users
    DROP COLUMN IF EXISTS role,
    DROP COLUMN IF EXISTS permission;

COMMIT;
