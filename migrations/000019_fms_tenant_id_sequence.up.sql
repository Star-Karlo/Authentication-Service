-- Who allocates fms_tenant_id for a company that never was an FMS tenant.
--
-- FMS keys every row and every row-level-security policy on a bigint tenant
-- id. A company created here — by a Karlo admin onboarding a new fleet
-- customer — has no such id, so to FMS it does not exist: no vehicles, no
-- telemetry, no scope, and nothing saying why.
--
-- So auth allocates one, from this sequence, the first time a company is
-- granted an FMS entitlement. Tying the alias to the entitlement that needs
-- it means a TMS-only company never gets one and a fleet customer cannot be
-- sold FMS without one. The values carry no meaning; they only have to be
-- unique and stable.
--
-- Imported tenants keep their FMS ids. The import's last step must therefore
-- move the sequence past them:
--
--   SELECT setval('companies_fms_tenant_id_seq', (SELECT max(id) FROM fms_app.tenants));
--
-- The start value is a floor for a deployment that never imports anything.

BEGIN;

CREATE SEQUENCE IF NOT EXISTS companies_fms_tenant_id_seq
    AS BIGINT START WITH 1000;

COMMENT ON SEQUENCE companies_fms_tenant_id_seq IS
    'Allocates companies.fms_tenant_id for companies first sold FMS here. Must be set past max(fms_app.tenants.id) after an import.';

COMMIT;
