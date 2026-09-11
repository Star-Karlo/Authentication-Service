-- Per-user access, on top of a role.
--
-- The role says what a job does. This says what ONE person may do beyond it —
-- the dispatcher who also reconciles invoices, the driver trusted to close a
-- shipment. Without it an administrator has two bad options: give the whole
-- role an ability only one person needs, or create a role for one person and
-- lose the point of roles.
--
-- The two combine by UNION. Extras only ever ADD. That direction is deliberate:
-- a grant that could also subtract would mean reading two places to know what
-- somebody can do, and a role change would silently do nothing for the people
-- carrying a subtraction.

BEGIN;

CREATE TABLE IF NOT EXISTS user_product_access (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- Which product these extras belong to. The keys below are UNQUALIFIED —
    -- `order.read`, not `tms:order.read` — because the product is this column.
    -- Roles store qualified keys instead, since a role spans products and has
    -- no column to carry it.
    product VARCHAR(16) NOT NULL REFERENCES products(key),

    permissions TEXT[] NOT NULL DEFAULT '{}',

    -- Disabling keeps the row, so "what did this person used to have" survives
    -- a temporary withdrawal. Deleting it loses the fact the grant was ever
    -- made, which is the question a support ticket usually asks.
    enabled BOOLEAN NOT NULL DEFAULT TRUE,

    -- Who granted it. An exception to a role is a decision somebody made, and
    -- it should be answerable later.
    granted_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    note TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, product)
);

CREATE INDEX IF NOT EXISTS idx_user_extra_access_user
    ON user_product_access (user_id) WHERE enabled;

COMMENT ON TABLE user_product_access IS
    'Extra permissions for ONE person, on top of their role. Additive only: effective access is the role UNION these.';

COMMENT ON COLUMN user_product_access.permissions IS
    'Unqualified catalogue keys for this product, e.g. order.read. The product column qualifies them.';

COMMIT;
