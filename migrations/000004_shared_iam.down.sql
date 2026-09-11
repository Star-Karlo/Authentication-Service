-- Reverse 000004. The aliases and the entitlement mode are dropped, so any FMS
-- tenant migrated onto this schema must be moved off it BEFORE running this.
BEGIN;

DROP INDEX IF EXISTS idx_sessions_replaced_by;
ALTER TABLE sessions
    DROP COLUMN IF EXISTS replaced_by_session_id,
    DROP COLUMN IF EXISTS revoked_reason;

DROP TABLE IF EXISTS company_product_settings;
DROP TYPE IF EXISTS entitlement_mode;

DROP INDEX IF EXISTS idx_user_product_access_role;
ALTER TABLE user_product_access DROP COLUMN IF EXISTS role_id;

DROP INDEX IF EXISTS idx_product_roles_company;
DROP INDEX IF EXISTS idx_product_roles_fms_role_id;
DROP TABLE IF EXISTS product_roles;

-- last_login_at is deliberately NOT dropped: migration 000001 created it, and
-- dropping it here would destroy a column this migration never added, taking
-- every account's last-seen timestamp with it.
DROP INDEX IF EXISTS idx_companies_slug;
ALTER TABLE companies DROP COLUMN IF EXISTS slug;
DROP INDEX IF EXISTS idx_users_fms_user_id;
ALTER TABLE users DROP COLUMN IF EXISTS fms_user_id;

COMMIT;
