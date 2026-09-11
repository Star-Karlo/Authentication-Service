-- Shared IAM: hold both products as they actually are.
--
-- TMS and FMS were built independently and disagree in five ways that matter.
-- This migration makes the schema able to represent BOTH, so FMS can migrate
-- onto it without changing its behaviour on the day it moves. Nothing here
-- changes how TMS behaves.
--
-- The disagreements, and how each is resolved:
--
--   1. Identifiers. TMS keys everything by UUID; FMS by bigint, and FMS's live
--      row-level security compares against those bigints across all its data.
--      Neither can be rewritten cheaply, so both are carried: the UUID stays
--      primary, the bigint becomes a recorded alias.
--
--   2. Roles. A TMS role is a job persona (shipper, driver); an FMS role is a
--      rank (operator < manager < admin). Already per-product, so both fit.
--
--   3. Permission bundles. FMS lets a company define named roles holding a set
--      of permission keys, and assigns users to one. TMS has no such concept
--      and grants keys per user. Modelled as an optional named role a user MAY
--      point at, so TMS simply never sets it.
--
--   4. Entitlement default. This is the hard one. TMS is opt-in: no row means
--      denied. FMS is opt-out: no row means ENABLED. They fail in opposite
--      directions, and flipping FMS to opt-in in one step would take every
--      tenant with sparse rows dark at once. So the default becomes a per
--      company, per product PROPERTY rather than an assumption in code, and a
--      tenant can be moved from one to the other individually, with the ability
--      to move it back.
--
--   5. Sessions. FMS rotates refresh tokens and detects reuse of a revoked one
--      as evidence of theft. TMS stores a refresh hash but has no rotation
--      chain. The chain is added here.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Identifiers
-- ---------------------------------------------------------------------------
-- companies.fms_tenant_id already exists (migration 000003). Users need the
-- same treatment: FMS references a user by bigint throughout its own data, so
-- without a recorded alias the migration would have to rewrite every FMS table
-- that names a user.
--
-- Nullable and unique: only accounts that exist in FMS carry one, and no two
-- accounts may claim the same FMS identity.

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS fms_user_id BIGINT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_fms_user_id
    ON users (fms_user_id) WHERE fms_user_id IS NOT NULL;

COMMENT ON COLUMN users.fms_user_id IS
    'The same person''s FMS-facing bigint id. Null for accounts FMS has never seen.';

-- FMS identifies a tenant in URLs by a slug and requires it to be unique.
-- Carried so an FMS-facing route can resolve a company the way FMS always has.
ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS slug VARCHAR(64);

CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_slug
    ON companies (slug) WHERE slug IS NOT NULL AND deleted_at IS NULL;

-- users.last_login_at is NOT added here: migration 000001 already declares it.
-- It is mentioned because FMS carries the same column and the merge relies on
-- it existing — but adding it again would imply this migration owns it, and
-- the down migration would then drop a column it never created.

-- ---------------------------------------------------------------------------
-- 3. Named permission bundles
-- ---------------------------------------------------------------------------
-- FMS's `roles` table: a company defines a role by name, gives it a set of
-- permission keys, and points users at it. Editing the role changes what every
-- user holding it can do, which is the whole reason it exists — TMS's per-user
-- grants cannot express "everyone in dispatch gets this" without editing every
-- account.
--
-- Scoped to (company, product) because a name means different things in each:
-- an FMS "Supervisor" and a TMS "Supervisor" would share nothing but a word.

CREATE TABLE IF NOT EXISTS product_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id  UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    product     VARCHAR(16) NOT NULL REFERENCES products(key),

    name        VARCHAR(64) NOT NULL,
    description TEXT,

    -- Flat catalogue keys, the same shape user_product_access.permissions uses.
    permissions TEXT[] NOT NULL DEFAULT '{}',

    -- The FMS-facing alias, for the same reason as users.fms_user_id.
    fms_role_id BIGINT,

    created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT product_roles_name_unique UNIQUE (company_id, product, name)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_product_roles_fms_role_id
    ON product_roles (fms_role_id) WHERE fms_role_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_product_roles_company
    ON product_roles (company_id, product);

COMMENT ON TABLE product_roles IS
    'Named permission bundles a company defines. Optional: TMS grants keys per user and leaves this empty.';

-- A user may point at one bundle per product, IN ADDITION to their own keys.
--
-- ON DELETE SET NULL rather than RESTRICT: deleting a role must not be blocked
-- by the people holding it, and it must not delete them either. They fall back
-- to their own keys, which is the safe direction — they lose access rather than
-- keeping a bundle nobody can see any more.
ALTER TABLE user_product_access
    ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES product_roles(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_user_product_access_role
    ON user_product_access (role_id) WHERE role_id IS NOT NULL;

COMMENT ON COLUMN user_product_access.role_id IS
    'Optional named bundle. Effective permissions are this bundle UNION the row''s own permissions.';

-- ---------------------------------------------------------------------------
-- 4. Entitlement default, per company and product
-- ---------------------------------------------------------------------------
-- The inversion, made into data.
--
--   'grant'  — opt-in. A module is held only if an enabled row says so.
--              What TMS has always done, and the safer default: a company
--              cannot reach something nobody decided to sell them.
--
--   'revoke' — opt-out. A module is held UNLESS a row disables it.
--              What FMS does today. Every FMS tenant migrates as 'revoke' and
--              keeps working; nobody goes dark on the day of the move.
--
-- Making it per (company, product) rather than per product is what makes the
-- eventual convergence safe: tenants move one at a time, each move is
-- reversible, and a mistake affects one customer instead of all of them.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'entitlement_mode') THEN
        CREATE TYPE entitlement_mode AS ENUM ('grant', 'revoke');
    END IF;
END$$;

CREATE TABLE IF NOT EXISTS company_product_settings (
    company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    product    VARCHAR(16) NOT NULL REFERENCES products(key),

    -- Defaults to 'grant' so anything created without thinking about it fails
    -- closed. A row is only ever 'revoke' because somebody deliberately said so.
    entitlement_mode entitlement_mode NOT NULL DEFAULT 'grant',

    -- Set when a tenant is moved from opt-out to opt-in, so the convergence can
    -- be audited: who was moved, when, and who is left.
    converted_at       TIMESTAMPTZ,
    converted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (company_id, product)
);

COMMENT ON TABLE company_product_settings IS
    'How to read an ABSENT company_modules row for this company and product: grant = denied, revoke = enabled.';

-- Every existing company is opt-in, which is what TMS already does. Stating it
-- explicitly rather than relying on the column default means a later reader can
-- tell "nobody has decided" from "decided to be opt-in".
INSERT INTO company_product_settings (company_id, product, entitlement_mode)
SELECT c.id, 'tms', 'grant'
FROM companies c
ON CONFLICT (company_id, product) DO NOTHING;

-- ---------------------------------------------------------------------------
-- 5. Refresh token rotation
-- ---------------------------------------------------------------------------
-- FMS rotates a refresh token on every use and treats the replay of a revoked
-- one as evidence that it was stolen, revoking the whole chain. That is a real
-- protection TMS lacks, and it needs the chain recorded to work at all: without
-- knowing which token replaced which, a replay is indistinguishable from a
-- client that retried.

ALTER TABLE sessions
    ADD COLUMN IF NOT EXISTS replaced_by_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS revoked_reason VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_sessions_replaced_by
    ON sessions (replaced_by_session_id) WHERE replaced_by_session_id IS NOT NULL;

COMMENT ON COLUMN sessions.replaced_by_session_id IS
    'The session that superseded this one when its refresh token was rotated. Replaying a revoked token whose successor exists is theft, not a retry.';

COMMENT ON COLUMN sessions.revoked_reason IS
    'Why the session ended: logout, rotated, reuse_detected, password_change, access_change, suspended.';

COMMIT;
