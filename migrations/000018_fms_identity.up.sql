-- FMS identity aliases, restored.
--
-- Migration 000006 dropped companies.fms_tenant_id, users.fms_user_id and
-- product_roles.fms_role_id, on the reasoning that "FMS authenticates HERE now,
-- so there is no second identity to alias."
--
-- That holds for the login and for nothing else. FMS is bigint-keyed end to
-- end: every table in fms_app carries `tenant_id bigint`, and row-level
-- security enforces isolation with
--
--     USING (tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::bigint)
--
-- on roughly thirty tables, plus the telemetry service's readings and every
-- historical row behind them. Re-keying that to UUID is a rewrite of the data
-- plane, not a migration, and it would have to happen atomically with the
-- cutover of the login.
--
-- So the alias returns, for the reason 000004 gave when it first added it: one
-- concept, one primary key, one recorded alias, and neither product translating
-- identifiers at runtime. The token carries fms_tenant_id as
-- Principal.FMSTenantID, and FMS sets app.current_tenant from it directly.
--
-- Cost when FMS is not involved: three nullable columns and three partial
-- indexes over the rows that have a value, which for a TMS-only deployment is
-- none of them.
--
-- fms_role_id goes on `roles`, not `product_roles` — 000006 renamed the table
-- and dropped the product column, so a role now spans products. The alias is
-- still one-to-one, because an FMS role only ever named FMS keys.

BEGIN;

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS fms_tenant_id BIGINT;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS fms_user_id BIGINT;

ALTER TABLE roles
    ADD COLUMN IF NOT EXISTS fms_role_id BIGINT;

-- Partial, because the overwhelming majority of rows have no FMS identity and
-- indexing their NULLs would be most of the table for nothing. UNIQUE because
-- two auth rows claiming one FMS identity is the failure this column exists to
-- make impossible: it would silently split one tenant's data in two.
CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_fms_tenant_id
    ON companies (fms_tenant_id) WHERE fms_tenant_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_fms_user_id
    ON users (fms_user_id) WHERE fms_user_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_roles_fms_role_id
    ON roles (fms_role_id) WHERE fms_role_id IS NOT NULL;

COMMENT ON COLUMN companies.fms_tenant_id IS
    'fms_app.tenants.id. The value FMS sets app.current_tenant to; its row-level security compares against this on every query. Carried in the access token as Principal.FMSTenantID so no service translates at runtime.';

COMMENT ON COLUMN users.fms_user_id IS
    'fms_app.users.id. Recorded so FMS rows that reference a user (dashboard_layouts, api_tokens.created_by, alert check_by) still resolve after identity moved here.';

COMMENT ON COLUMN roles.fms_role_id IS
    'fms_app.roles.id, for roles imported from FMS. NULL for every role created here.';

-- FMS api_tokens carry a longer clear-text prefix than the 8 characters the
-- column was sized for. It is identification only, but a customer's key list
-- showing a shorter prefix than the one they were handed is a support ticket.
ALTER TABLE api_keys
    ALTER COLUMN key_prefix TYPE VARCHAR(16);

COMMIT;
