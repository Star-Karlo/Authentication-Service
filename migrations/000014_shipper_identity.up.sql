-- Shipper identity, sharing and merging.
--
-- Three connected changes, all driven by one fact: a shipper is a real business
-- that several transporters may deal with, so it must be ONE row that they
-- share rather than one row each.
--
--   1. entity_type   — a shipper may be a person or a company. Both are named
--                      as the shipper on an order, so both are a companies row.
--   2. npwp unique   — the tax number is what says "this is the same business".
--                      Optional, because a transporter creating a placeholder
--                      usually does not know it; unique when present, so the
--                      moment anyone supplies it the duplicate is refused
--                      rather than silently created.
--   3. merging       — duplicates will still happen, because two transporters
--                      can both create a shipper without an NPWP. Requiring the
--                      NPWP at CLAIM time is what surfaces them.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Person or company
-- ---------------------------------------------------------------------------
-- Not a boolean. `is_personal` stops being enough the moment a third kind
-- appears — a cooperative, a foundation, a government body — and renaming a
-- column in use is worse than choosing the right shape now.

DO $$ BEGIN
    CREATE TYPE entity_kind AS ENUM ('company', 'personal');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS entity_type entity_kind NOT NULL DEFAULT 'company',

    -- Nomor Induk Berusaha. Replaced SIUP and TDP when OSS launched in 2018;
    -- this schema carried the obsolete pair and lacked the current one.
    -- Company-only: a personal shipper has no NIB, which is exactly why NIB
    -- cannot be the identity key and NPWP is.
    ADD COLUMN IF NOT EXISTS nib VARCHAR(32);

COMMENT ON COLUMN companies.entity_type IS
    'Whether this shipper is a registered business or an individual. Personal shippers have an NPWP and a bank account but no NIB.';

COMMENT ON COLUMN companies.no_siup IS
    'LEGACY. Superseded by NIB in 2018; present on imported records, not collected for new ones.';
COMMENT ON COLUMN companies.no_tdp IS
    'LEGACY. Superseded by NIB in 2018; present on imported records, not collected for new ones.';

-- ---------------------------------------------------------------------------
-- 2. The tax number identifies the business
-- ---------------------------------------------------------------------------
-- Partial, the same pattern as users.email: optional, but unique when present.
-- That is what makes the placeholder flow work at all — a transporter can
-- create a shipper knowing only a name and a phone number — while guaranteeing
-- that two transporters who DO know the tax number reach the same row.
--
-- Normalised before comparison, so 01.234.567.8-901.000 and 012345678901000
-- are the same business. Without this, formatting alone would defeat the
-- uniqueness and the duplicate would be created anyway.

CREATE OR REPLACE FUNCTION normalise_tax_id(value TEXT) RETURNS TEXT
    LANGUAGE sql IMMUTABLE AS
$$ SELECT NULLIF(regexp_replace(COALESCE(value, ''), '[^0-9]', '', 'g'), '') $$;

CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_npwp
    ON companies (normalise_tax_id(npwp))
    WHERE npwp IS NOT NULL AND deleted_at IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_nib
    ON companies (normalise_tax_id(nib))
    WHERE nib IS NOT NULL AND deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- 3. Which transporters deal with which shipper
-- ---------------------------------------------------------------------------
-- A placeholder is SHARED, not owned. When a second transporter supplies an
-- NPWP that already exists they are linked to the existing shipper rather than
-- creating a second one — so both see the same company, and an order from
-- either names the same row.
--
-- created_by_company_id records who created it first and stays as provenance.
-- This table records everyone who deals with it, which is the question that
-- actually gets asked: "which shippers may I name on an order".

CREATE TABLE IF NOT EXISTS company_links (
    transporter_company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    shipper_company_id     UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,

    -- Who first connected the two, for the audit trail.
    linked_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (transporter_company_id, shipper_company_id)
);

CREATE INDEX IF NOT EXISTS idx_company_links_shipper
    ON company_links (shipper_company_id);

COMMENT ON TABLE company_links IS
    'Which transporters deal with which shippers. A shipper created by one transporter is shared with any other that supplies the same tax number.';

-- Every placeholder created so far belongs to whoever created it.
INSERT INTO company_links (transporter_company_id, shipper_company_id)
SELECT created_by_company_id, id FROM companies
WHERE created_by_company_id IS NOT NULL
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- 4. Merging duplicates
-- ---------------------------------------------------------------------------
-- Two transporters can both create a shipper without a tax number, so
-- duplicates are unavoidable. They surface when the shipper CLAIMS the company
-- and supplies an NPWP that already exists elsewhere.
--
-- The losing row is kept and points at the winner rather than being deleted.
-- That matters because orders, agreements and invoices live in ANOTHER service
-- and reference this id: deleting the row would break them, and a cross-service
-- transaction to move them all is not something this service can offer. A
-- forwarding pointer lets every service resolve the old id correctly and
-- migrate its own rows in its own time.

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS merged_into_company_id UUID REFERENCES companies(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS merged_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_companies_merged_into
    ON companies (merged_into_company_id) WHERE merged_into_company_id IS NOT NULL;

COMMENT ON COLUMN companies.merged_into_company_id IS
    'This company was found to be a duplicate and its records now belong to the company named here. The row is kept, not deleted, because other services reference this id.';

COMMIT;
