-- Multi-product identity.
--
-- One person, one company, one login — used by two products (TMS and FMS) that
-- have almost nothing in common at the access-control level. FMS is already in
-- production with its own equivalent model; this is the shared shape both
-- converge on.
--
-- Access is decided by three things, deliberately separated because they answer
-- three different questions and change for three different reasons:
--
--   is_platform_staff              Is this a Karlo employee?      product-neutral
--   company_modules(product)       Is the company sold it?        per product
--   user_product_access(product)   May this person use it?        per product
--
-- The earlier design collapsed the first into the third — Karlo staff were
-- identified by a tenant role called "admin". That breaks with two products: a
-- Karlo employee is staff across both, not an administrator of one.

-- ---------------------------------------------------------------------------
-- Products
-- ---------------------------------------------------------------------------

CREATE TABLE products (
    key         VARCHAR(16) PRIMARY KEY,
    name        VARCHAR(64) NOT NULL,
    -- A product-neutral entry owns entitlements that belong to neither product:
    -- accounting and telemetry are separate services both products consume, so
    -- duplicating their entitlement per product would let the two disagree.
    is_shared   BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO products (key, name, is_shared) VALUES
    ('tms',    'Transport Management System', FALSE),
    ('fms',    'Fleet Management System',     FALSE),
    ('shared', 'Shared services',             TRUE);

-- ---------------------------------------------------------------------------
-- Platform staff
-- ---------------------------------------------------------------------------

-- Karlo employees, who administer across tenants and bypass company
-- entitlement entirely. FMS calls this platform_admin; TMS called it superadmin
-- and admin. It is one concept and it is not a tenant role, so it does not
-- belong in a per-product table.
ALTER TABLE users
    ADD COLUMN is_platform_staff BOOLEAN NOT NULL DEFAULT FALSE;

-- Carry over the existing platform roles before they stop meaning this.
UPDATE users SET is_platform_staff = TRUE WHERE role IN ('superadmin', 'admin');

CREATE INDEX idx_users_platform_staff ON users (id) WHERE is_platform_staff;

-- ---------------------------------------------------------------------------
-- Entitlement gains a product
-- ---------------------------------------------------------------------------

-- Module names are product-qualified everywhere they are compared, because both
-- products have a module called dashboard, notifications, reports, masterData
-- and customer meaning entirely different things. Unqualified, one product's
-- entitlement would silently grant the other's.
ALTER TABLE company_modules
    ADD COLUMN product VARCHAR(16) NOT NULL DEFAULT 'tms'
        REFERENCES products (key);

-- The existing rows were all TMS; the default above has already labelled them.
-- Drop it so future inserts must state the product rather than inheriting an
-- assumption that only held during this migration.
ALTER TABLE company_modules
    ALTER COLUMN product DROP DEFAULT;

ALTER TABLE company_modules DROP CONSTRAINT company_modules_pkey;
ALTER TABLE company_modules ADD PRIMARY KEY (company_id, product, module);

DROP INDEX IF EXISTS idx_company_modules_active;
CREATE INDEX idx_company_modules_active
    ON company_modules (company_id, product)
    WHERE enabled;

ALTER TABLE company_module_history
    ADD COLUMN product VARCHAR(16) NOT NULL DEFAULT 'tms'
        REFERENCES products (key);
ALTER TABLE company_module_history ALTER COLUMN product DROP DEFAULT;

-- ---------------------------------------------------------------------------
-- Per-product access
-- ---------------------------------------------------------------------------

-- Role and permission move off the user and become per-product.
--
-- The vocabularies do not overlap. TMS roles are job personas — shipper,
-- transporter, driver, warehousePic. FMS roles are privilege tiers —
-- operator ⊂ manager ⊂ admin. Forcing one column to carry both would mean
-- every consumer interpreting a value it cannot validate.
--
-- NO ROW MEANS NO ACCESS. That is the natural way to express the common case:
-- a TMS driver has a tms row and no fms row, and an FMS-only customer has the
-- reverse. It also means granting someone a second product is an insert rather
-- than an edit to a field that already had a value.
CREATE TABLE user_product_access (
    user_id     UUID        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    product     VARCHAR(16) NOT NULL REFERENCES products (key),

    -- The tenant role, in that product's own vocabulary.
    role        VARCHAR(32) NOT NULL,

    -- Granted permissions. Stored as a flat array of `module.action` keys
    -- rather than a nested map: it is the shape FMS already uses in
    -- production, it is trivially indexable, and the nested form carried no
    -- information the flat one does not.
    permissions TEXT[]      NOT NULL DEFAULT '{}',

    enabled     BOOLEAN     NOT NULL DEFAULT TRUE,

    -- Who granted this person access to this product, and when.
    granted_by_user_id UUID REFERENCES users (id) ON DELETE SET NULL,

    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, product)
);

CREATE INDEX idx_user_product_access_user
    ON user_product_access (user_id)
    WHERE enabled;

-- Answering "who has access to FMS", for seat counting and licence review.
CREATE INDEX idx_user_product_access_product
    ON user_product_access (product, role)
    WHERE enabled;

CREATE TRIGGER trg_user_product_access_updated_at
    BEFORE UPDATE ON user_product_access
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Migrate the existing single-product data. Every current user is a TMS user;
-- their role and permission map move into a tms row.
--
-- The permission map is flattened from {module: {action: bool}} into
-- module.action keys, keeping only the granted ones — a false entry never meant
-- anything different from an absent one.
INSERT INTO user_product_access (user_id, product, role, permissions, enabled)
SELECT
    u.id,
    'tms',
    u.role,
    COALESCE(
        (
            SELECT array_agg(module_key || '.' || action_key ORDER BY module_key, action_key)
            FROM jsonb_each(u.permission) AS modules(module_key, actions)
            CROSS JOIN LATERAL jsonb_each(actions) AS acts(action_key, granted)
            WHERE granted = 'true'::jsonb
        ),
        '{}'
    ),
    NOT u.is_suspended
FROM users u
WHERE u.deleted_at IS NULL
ON CONFLICT (user_id, product) DO NOTHING;

-- users.role and users.permission are deliberately left in place for now.
--
-- Dropping them in the same migration that introduces their replacement would
-- make rollback impossible: a deploy that has to be reverted would find the
-- data gone. They become read-only at this point and are removed in a later
-- migration, once the application no longer reads them.
COMMENT ON COLUMN users.role IS
    'DEPRECATED: superseded by user_product_access.role. Retained for rollback; do not read.';
COMMENT ON COLUMN users.permission IS
    'DEPRECATED: superseded by user_product_access.permissions. Retained for rollback; do not read.';

-- ---------------------------------------------------------------------------
-- FMS company alias
-- ---------------------------------------------------------------------------

-- FMS identifies a tenant by a bigint, and its row-level security compares
-- against it on every query across live customer data. Rather than change that,
-- a company records its FMS-facing alias here and the token carries both.
--
-- One concept, one primary key, one recorded alias for a system that predates
-- the shared IAM — the same shape as the legacy_id columns already carried for
-- the Mongo migration. Neither product translates at runtime: FMS reads the
-- bigint, TMS reads the UUID.
--
-- Nullable because a company that has never used FMS has no alias.
ALTER TABLE companies
    ADD COLUMN fms_tenant_id BIGINT UNIQUE;

COMMENT ON COLUMN companies.fms_tenant_id IS
    'FMS-facing alias, seeded from the FMS tenants table. Read into app.current_tenant by FMS; never used as a TMS identifier.';
