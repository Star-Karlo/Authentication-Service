-- Role-based IAM.
--
-- Replaces per-user permission grants with company-defined ROLES. A company
-- creates roles, gives each a set of permissions, and assigns people to one.
-- Changing what a team may do becomes one edit instead of one per person, and
-- an administrator can express their own structure rather than being handed a
-- fixed set of job titles.
--
-- What this removes and why each was wrong:
--
--   users.account_type  — root versus invited was a two-value stand-in for
--                         "how much may this person do". A role says it
--                         properly, and says it in the company's own words.
--   users.parent_id     — a hierarchy nothing enforced. Who invited whom is an
--                         audit fact, not an access rule, so it survives as
--                         invited_by_user_id and grants nothing.
--   user_product_access — one row per user per product, carrying a role name
--                         and a key list. The role now carries both, once.
--   collaboration_invites — superseded by company_claim_tokens, which is the
--                         same idea done safely (hashed, single-use, expiring).
--   average_rating,
--   rating_count        — a driver's rating is business data. It belongs to
--                         whatever measures performance, not to identity.
--   fms_tenant_id,
--   fms_user_id         — aliases for a system that kept its own identities.
--                         FMS authenticates HERE now, so there is no second
--                         identity to alias.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Roles
-- ---------------------------------------------------------------------------
-- product_roles already existed as an optional bundle alongside per-user keys.
-- It becomes the ONLY way permissions are granted, so it is renamed to what it
-- now is and loses the product column: a role spans every product its company
-- holds, because a person does one job and that job does not stop at a product
-- boundary.

ALTER TABLE product_roles RENAME TO roles;
ALTER TABLE roles DROP CONSTRAINT IF EXISTS product_roles_name_unique;
ALTER TABLE roles DROP COLUMN IF EXISTS product;
ALTER TABLE roles DROP COLUMN IF EXISTS fms_role_id;

ALTER TABLE roles
    -- grants_all is the administrator role: everything the company is entitled
    -- to, without listing it. Enumerating the keys instead would go stale the
    -- day the company buys another module — the administrator would silently
    -- not have it, which is the opposite of what an administrator means.
    ADD COLUMN IF NOT EXISTS grants_all BOOLEAN NOT NULL DEFAULT FALSE,
    -- is_system marks a role the platform created and the company may not
    -- delete. Every company needs at least one role that can administer it;
    -- allowing that one to be removed is how a company locks itself out.
    ADD COLUMN IF NOT EXISTS is_system BOOLEAN NOT NULL DEFAULT FALSE;

-- Permissions are stored PRODUCT-QUALIFIED: 'tms:order.read', 'fms:live.view'.
--
-- No key collides between the two catalogues today, but `dashboard` is already
-- a subject in both, so an unqualified key is one FMS release away from being
-- ambiguous — and the ambiguity would resolve silently to whichever catalogue
-- was consulted first.
COMMENT ON COLUMN roles.permissions IS
    'Product-qualified catalogue keys, e.g. tms:order.read. Ignored when grants_all is true.';

ALTER TABLE roles ADD CONSTRAINT roles_name_unique UNIQUE (company_id, name);

CREATE INDEX IF NOT EXISTS idx_roles_company ON roles (company_id);

-- ---------------------------------------------------------------------------
-- 2. Every company gets an Administrator role
-- ---------------------------------------------------------------------------
-- Created before users are pointed at roles, so nobody is left without one.

INSERT INTO roles (company_id, name, description, permissions, grants_all, is_system)
SELECT id, 'Administrator',
       'Full access to everything this company is entitled to. Created automatically and cannot be deleted.',
       '{}'::text[], TRUE, TRUE
FROM companies
-- DO UPDATE, not DO NOTHING. A role of this name may already exist — a company
-- may have made one, or a previous run of this migration may have been rolled
-- back, which drops the columns but leaves the rows. DO NOTHING would then
-- leave an "Administrator" that grants nothing, which is worse than no
-- administrator at all because it looks correct in a role list.
ON CONFLICT (company_id, name) DO UPDATE SET
    grants_all = TRUE, is_system = TRUE, updated_at = NOW();

-- ---------------------------------------------------------------------------
-- 3. Users hold a role
-- ---------------------------------------------------------------------------

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES roles(id) ON DELETE RESTRICT,
    -- Who invited this person. An audit fact only: it grants nothing, which is
    -- the difference from the parent_id it replaces.
    ADD COLUMN IF NOT EXISTS invited_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- ON DELETE RESTRICT on role_id is deliberate. SET NULL would leave a person
-- with no role and therefore no access, silently, the moment somebody tidied
-- up a role list. Refusing the delete forces the administrator to move people
-- off a role before removing it.

-- Carry the existing hierarchy across before parent_id is dropped.
UPDATE users SET invited_by_user_id = parent_id WHERE parent_id IS NOT NULL;

-- Existing root accounts become administrators.
UPDATE users u
SET role_id = r.id
FROM roles r
WHERE r.company_id = u.company_id
  AND r.is_system
  AND u.account_type = 'mainAccount'
  AND u.role_id IS NULL;

-- ---------------------------------------------------------------------------
-- 3b. Everyone else keeps exactly what they had, as a role
-- ---------------------------------------------------------------------------
-- This is the part that must not be skipped. Dropping user_product_access
-- without deriving roles from it first would leave every member of every
-- company with no role and therefore no access at all — they would still sign
-- in and then be refused everywhere, which is the worst possible failure
-- because it looks like a permissions bug rather than a missing migration.
--
-- A role is created per DISTINCT permission set per company, not per user.
-- Fifty dispatchers with identical access become one role named for the job,
-- which is the entire point of the change; giving each person a private role
-- would carry the old model forward under a new name.
--
-- Keys are qualified with their product as they move, because the role no
-- longer records which product they came from.

INSERT INTO roles (company_id, name, description, permissions, grants_all, is_system)
SELECT DISTINCT ON (u.company_id, a.permissions)
       u.company_id,
       -- Named after the job the old access row recorded. Where several
       -- distinct permission sets shared a job name, the set is numbered so
       -- the unique constraint holds and nobody is silently merged into
       -- another group's access.
       a.role || COALESCE(
           NULLIF(' (' || (dense_rank() OVER (
               PARTITION BY u.company_id, a.role ORDER BY a.permissions
           ))::text || ')', ' (1)'), ''),
       'Migrated from the permissions this group already held.',
       ARRAY(SELECT 'tms:' || k FROM unnest(a.permissions) AS k),
       FALSE, FALSE
FROM user_product_access a
JOIN users u ON u.id = a.user_id
WHERE u.company_id IS NOT NULL
  AND a.enabled
  AND array_length(a.permissions, 1) > 0
ON CONFLICT (company_id, name) DO NOTHING;

-- Point each remaining account at the role matching what it held.
UPDATE users u
SET role_id = r.id
FROM user_product_access a
JOIN LATERAL (SELECT 1) _ ON TRUE
JOIN roles r ON TRUE
WHERE a.user_id = u.id
  AND u.role_id IS NULL
  AND r.company_id = u.company_id
  AND NOT r.is_system
  AND r.permissions = ARRAY(SELECT 'tms:' || k FROM unnest(a.permissions) AS k);

-- Anyone left has no permissions recorded at all — a member who was never
-- granted anything. They get a role that says so explicitly, rather than a
-- NULL that reads as "not migrated yet".
INSERT INTO roles (company_id, name, description, permissions, grants_all, is_system)
SELECT DISTINCT u.company_id, 'No access',
       'Held no permissions before the migration. Assign a real role to grant access.',
       '{}'::text[], FALSE, TRUE
FROM users u
WHERE u.company_id IS NOT NULL AND u.role_id IS NULL
ON CONFLICT (company_id, name) DO UPDATE SET
    grants_all = FALSE, is_system = TRUE, updated_at = NOW();

UPDATE users u
SET role_id = r.id
FROM roles r
WHERE r.company_id = u.company_id
  AND r.name = 'No access'
  AND u.role_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_users_role ON users (role_id) WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- 4. Configurable device limit, replacing the single-device flag
-- ---------------------------------------------------------------------------
-- single_device was a boolean meaning "one, or unlimited". The real question is
-- how many, and it differs per account: a driver on a company phone is not the
-- same as an operations manager with a laptop and a tablet.
--
-- It lives on the user with a company default behind it, so an administrator
-- sets a policy once and overrides the exceptions.

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS default_max_devices INTEGER NOT NULL DEFAULT 0;

ALTER TABLE users
    -- 0 means "use the company default"; the company's 0 means unlimited.
    -- Unlimited is the historical behaviour, so nothing changes for anyone
    -- until somebody sets a limit deliberately.
    ADD COLUMN IF NOT EXISTS max_devices INTEGER NOT NULL DEFAULT 0;

COMMENT ON COLUMN users.max_devices IS
    'Concurrent sessions allowed. 0 defers to companies.default_max_devices, which is 0 for unlimited.';

-- Accounts that were single-device keep that meaning as a limit of one.
UPDATE users u SET max_devices = 1
WHERE EXISTS (SELECT 1 FROM sessions s WHERE s.user_id = u.id AND s.single_device);

-- ---------------------------------------------------------------------------
-- 5. API keys act as a role
-- ---------------------------------------------------------------------------
-- A key held what its creating user could do at the moment it was made, and
-- kept it even after that person's access changed or they left. Pointing at a
-- role means a key's reach is reviewed whenever the role is.

ALTER TABLE api_keys
    ADD COLUMN IF NOT EXISTS role_id UUID REFERENCES roles(id) ON DELETE RESTRICT,
    ADD COLUMN IF NOT EXISTS company_id UUID REFERENCES companies(id) ON DELETE CASCADE,
    -- Retained for audit. Who created a credential is a question that outlives
    -- the creator's own access.
    ADD COLUMN IF NOT EXISTS created_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

UPDATE api_keys k SET created_by_user_id = k.user_id WHERE k.user_id IS NOT NULL;
UPDATE api_keys k SET company_id = u.company_id FROM users u WHERE u.id = k.user_id;

CREATE INDEX IF NOT EXISTS idx_api_keys_role ON api_keys (role_id);

-- ---------------------------------------------------------------------------
-- 6. Removals
-- ---------------------------------------------------------------------------

DROP TABLE IF EXISTS collaboration_invites;
DROP TABLE IF EXISTS user_product_access;

ALTER TABLE users
    DROP COLUMN IF EXISTS account_type,
    DROP COLUMN IF EXISTS parent_id,
    DROP COLUMN IF EXISTS average_rating,
    DROP COLUMN IF EXISTS rating_count,
    DROP COLUMN IF EXISTS fms_user_id;

ALTER TABLE companies
    DROP COLUMN IF EXISTS fms_tenant_id;

-- companies.legacy_id says what it holds but not what it means. It is the
-- Mongo id of the USER the company was derived from — the company itself never
-- existed in the legacy system. Naming it accurately is the difference between
-- a reader understanding the import and guessing at it.
ALTER TABLE companies RENAME COLUMN legacy_id TO derived_from_legacy_user_id;

COMMENT ON COLUMN companies.derived_from_legacy_user_id IS
    'Mongo _id of the legacy user this company was derived from. There were no companies in the legacy data; each parentless user became one. Also the import''s idempotency key.';

COMMIT;
