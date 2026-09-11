-- Reverse of 000018_fms_identity.
--
-- WARNING, stated rather than left to be discovered: rolling this back after
-- the FMS import has run DESTROYS the only mapping between an auth UUID and the
-- bigint identity every row in fms_app is keyed by. There is no way to
-- reconstruct it from either side — FMS's own users table matches on email at
-- best, and companies match on nothing at all.
--
-- Before rolling back, dump the mapping:
--
--   \copy (SELECT id, fms_tenant_id FROM companies WHERE fms_tenant_id IS NOT NULL) TO 'companies_fms_map.csv' CSV HEADER
--   \copy (SELECT id, fms_user_id   FROM users     WHERE fms_user_id   IS NOT NULL) TO 'users_fms_map.csv'     CSV HEADER
--   \copy (SELECT id, fms_role_id   FROM roles     WHERE fms_role_id   IS NOT NULL) TO 'roles_fms_map.csv'     CSV HEADER

BEGIN;

DROP INDEX IF EXISTS idx_companies_fms_tenant_id;
DROP INDEX IF EXISTS idx_users_fms_user_id;
DROP INDEX IF EXISTS idx_roles_fms_role_id;

ALTER TABLE companies DROP COLUMN IF EXISTS fms_tenant_id;
ALTER TABLE users     DROP COLUMN IF EXISTS fms_user_id;
ALTER TABLE roles     DROP COLUMN IF EXISTS fms_role_id;

-- Truncates any prefix longer than 8; identification only, nothing joins on it.
UPDATE api_keys SET key_prefix = LEFT(key_prefix, 8);
ALTER TABLE api_keys ALTER COLUMN key_prefix TYPE VARCHAR(8);

COMMIT;
