-- Reverse 000006.
--
-- This is NOT lossless and must not be run casually. Roles carry access that
-- per-user grants cannot express — a company that has defined its own roles
-- loses that structure, and everyone reverts to whatever their reconstructed
-- account_type implies. Restore from a backup instead if any real role exists.
BEGIN;

ALTER TABLE companies RENAME COLUMN derived_from_legacy_user_id TO legacy_id;
ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS fms_tenant_id BIGINT,
    DROP COLUMN IF EXISTS default_max_devices;

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS account_type VARCHAR(32) NOT NULL DEFAULT 'subAccount',
    ADD COLUMN IF NOT EXISTS parent_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS average_rating NUMERIC(3,2),
    ADD COLUMN IF NOT EXISTS rating_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS fms_user_id BIGINT;

-- Reconstruct what can be reconstructed: an administrator was a root account.
UPDATE users u SET account_type = 'mainAccount'
FROM roles r WHERE r.id = u.role_id AND r.grants_all;
UPDATE users SET parent_id = invited_by_user_id WHERE invited_by_user_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS user_product_access (
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product     VARCHAR(16) NOT NULL REFERENCES products(key),
    role        VARCHAR(32) NOT NULL,
    permissions TEXT[] NOT NULL DEFAULT '{}',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    granted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, product)
);

DROP INDEX IF EXISTS idx_api_keys_role;
ALTER TABLE api_keys
    DROP COLUMN IF EXISTS role_id,
    DROP COLUMN IF EXISTS company_id,
    DROP COLUMN IF EXISTS created_by_user_id;

DROP INDEX IF EXISTS idx_users_role;
ALTER TABLE users
    DROP COLUMN IF EXISTS role_id,
    DROP COLUMN IF EXISTS invited_by_user_id,
    DROP COLUMN IF EXISTS max_devices;

-- Before the flag columns go, remove the roles this migration created.
DELETE FROM roles WHERE is_system;

DROP INDEX IF EXISTS idx_roles_company;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS roles_name_unique;
ALTER TABLE roles
    DROP COLUMN IF EXISTS grants_all,
    DROP COLUMN IF EXISTS is_system,
    ADD COLUMN IF NOT EXISTS product VARCHAR(16) REFERENCES products(key),
    ADD COLUMN IF NOT EXISTS fms_role_id BIGINT;
UPDATE roles SET product = 'tms' WHERE product IS NULL;
ALTER TABLE roles ALTER COLUMN product SET NOT NULL;
ALTER TABLE roles RENAME TO product_roles;
ALTER TABLE product_roles ADD CONSTRAINT product_roles_name_unique UNIQUE (company_id, product, name);

COMMIT;
