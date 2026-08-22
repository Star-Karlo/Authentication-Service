-- Company module entitlement.
--
-- The first of the two tiers that govern access. Until now the only tier was
-- the per-user permission map, and a root account bypassed it entirely — so a
-- company could use any module the code knew about, including ones it had never
-- been sold. This table is what a company is *allowed*; users.permission stays
-- what a person is *permitted* within that.
--
-- Effective access is the intersection, and the grantable list an administrator
-- sees when assigning rights to a colleague is exactly this table's contents.

CREATE TABLE company_modules (
    company_id      UUID        NOT NULL REFERENCES companies (id) ON DELETE CASCADE,
    module          VARCHAR(64) NOT NULL,

    -- A row that exists but is disabled is not the same as no row. Disabling
    -- records that the company once had the module, which matters for
    -- reinstating it and for understanding a support ticket about access that
    -- used to work.
    enabled         BOOLEAN     NOT NULL DEFAULT TRUE,

    -- Trials and fixed-term contracts. NULL means no limit in that direction.
    valid_from      DATE,
    valid_until     DATE,

    -- Per-module quotas: seats, monthly order volume, and so on. JSONB because
    -- each module limits different things.
    limits          JSONB       NOT NULL DEFAULT '{}'::jsonb,

    granted_by_user_id UUID     REFERENCES users (id) ON DELETE SET NULL,
    note            TEXT,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (company_id, module),

    CONSTRAINT chk_company_module_validity
        CHECK (valid_until IS NULL OR valid_from IS NULL OR valid_until >= valid_from)
);

-- The hot query is "which modules does this company hold right now", run when
-- a token is minted.
CREATE INDEX idx_company_modules_active
    ON company_modules (company_id)
    WHERE enabled;

-- Answering "who has accounting" for billing and renewals.
CREATE INDEX idx_company_modules_module
    ON company_modules (module)
    WHERE enabled;

CREATE TRIGGER trg_company_modules_updated_at
    BEFORE UPDATE ON company_modules
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- A change to entitlement is a commercial event. It decides what a customer can
-- do and, indirectly, what they are billed, so it is recorded rather than
-- inferred from the current state.
CREATE TABLE company_module_history (
    id              BIGSERIAL   PRIMARY KEY,
    company_id      UUID        NOT NULL REFERENCES companies (id) ON DELETE CASCADE,
    module          VARCHAR(64) NOT NULL,
    action          VARCHAR(16) NOT NULL,
    actor_user_id   UUID        REFERENCES users (id) ON DELETE SET NULL,
    detail          JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_company_module_history_action
        CHECK (action IN ('granted', 'revoked', 'updated'))
);

CREATE INDEX idx_company_module_history
    ON company_module_history (company_id, created_at DESC);

-- Give every existing company the default set, so applying this migration does
-- not lock anyone out of what they were already using. Accounting and telemetry
-- are excluded: those are the separately sold modules, and a company gets them
-- when someone decides they should.
INSERT INTO company_modules (company_id, module)
SELECT c.id, m.module
FROM companies c
CROSS JOIN (VALUES
    ('order'), ('agreement'), ('invoice'), ('shipment'),
    ('truck'), ('warehouse'), ('customer'), ('dashboard'),
    ('collaboration'), ('notification'), ('masterData')
) AS m(module)
ON CONFLICT (company_id, module) DO NOTHING;
