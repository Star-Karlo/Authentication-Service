-- Reverse 000011. Any edited label is lost; the keys themselves are unaffected,
-- because the code has always been their source.
BEGIN;
DROP INDEX IF EXISTS idx_permission_catalog_active;
DROP INDEX IF EXISTS idx_permission_catalog_feature;
DROP TABLE IF EXISTS permission_catalog;
COMMIT;
