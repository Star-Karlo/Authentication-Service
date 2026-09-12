-- Reverse of 000019. Ids already allocated stay on their companies; only
-- the ability to allocate new ones goes.
BEGIN;
DROP SEQUENCE IF EXISTS companies_fms_tenant_id_seq;
COMMIT;
