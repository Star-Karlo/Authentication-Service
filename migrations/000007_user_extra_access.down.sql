-- Reverse 000007. Any per-person exception to a role is lost; the roles
-- themselves are untouched, so everyone keeps their base access.
BEGIN;
DROP INDEX IF EXISTS idx_user_extra_access_user;
DROP TABLE IF EXISTS user_product_access;
COMMIT;
