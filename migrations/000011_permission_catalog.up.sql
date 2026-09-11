-- The permission catalogue, as data.
--
-- Which keys exist was previously only in code — 54 for TMS, 31 for FMS — with
-- no endpoint exposing them. So the role editor had nothing to populate itself
-- from, and renaming "View orders" needed a deploy.
--
-- This makes the catalogue queryable WITHOUT letting a database row invent a
-- permission. The direction matters:
--
--   code  --declares-->  this table  --reads-->  UI
--
-- The service upserts every key it declares into this table at startup. A row
-- for a key the code does not declare is marked inactive, never honoured, and
-- never offered in a role editor. So inserting a row grants nothing: a key
-- means something only because a handler checks it, and a key that exists only
-- here would appear in every role editor as though it worked, be ticked, and do
-- nothing — with no error anywhere to find.
--
-- What IS editable here is presentation: the label, the grouping, the order.
-- Those are not enforcement, and changing them should never need a deploy.

BEGIN;

CREATE TABLE IF NOT EXISTS permission_catalog (
    -- The catalogue key: 'order.read'. Unqualified — `product` below says
    -- which catalogue it belongs to.
    key VARCHAR(64) NOT NULL,

    -- Which product declares it. This is the "which service" marker: a key is
    -- only meaningful inside its own product, and the same subject can appear
    -- in both (`dashboard` already does).
    product VARCHAR(16) NOT NULL REFERENCES products(key),

    -- The entitlement that gates it. NOT derivable from the key: `order.read`
    -- happens to be gated by `order`, but the mapping is declared so a key can
    -- be gated by something its name does not mention.
    feature VARCHAR(32) NOT NULL,

    -- Presentation, supplied by the code as a default.
    group_name VARCHAR(64) NOT NULL,
    label      VARCHAR(128) NOT NULL,

    -- Presentation, edited HERE and preserved across restarts.
    --
    -- Separate from `label` rather than overwriting it, so a startup sync can
    -- refresh the code's default without discarding somebody's wording — and
    -- so clearing the override falls back to the default rather than to empty.
    label_override VARCHAR(128),
    sort_order     INTEGER NOT NULL DEFAULT 0,

    -- FALSE once the code stops declaring the key.
    --
    -- Marked rather than deleted, deliberately. Roles may still list a retired
    -- key; deleting the catalogue row would hide that instead of surfacing it,
    -- and "which roles still reference something that no longer exists" is a
    -- question worth being able to ask.
    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    synced_at  TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (product, key)
);

CREATE INDEX IF NOT EXISTS idx_permission_catalog_active
    ON permission_catalog (product, group_name, sort_order) WHERE is_active;

CREATE INDEX IF NOT EXISTS idx_permission_catalog_feature
    ON permission_catalog (product, feature) WHERE is_active;

COMMENT ON TABLE permission_catalog IS
    'Queryable copy of the permission keys the CODE declares, synced at startup. Editing a label changes presentation; inserting a row grants nothing, because a key is honoured only if the code declares it too.';

COMMIT;
