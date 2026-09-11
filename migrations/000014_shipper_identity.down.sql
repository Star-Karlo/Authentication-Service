-- Reverse 000014.
--
-- NOT lossless. The link table is dropped, so which transporters shared a
-- shipper is lost; merges are unwound as pointers but the two rows stay
-- separate, which is the state that existed before the merge anyway.
BEGIN;

DROP INDEX IF EXISTS idx_companies_merged_into;
ALTER TABLE companies
    DROP COLUMN IF EXISTS merged_into_company_id,
    DROP COLUMN IF EXISTS merged_at;

DROP INDEX IF EXISTS idx_company_links_shipper;
DROP TABLE IF EXISTS company_links;

DROP INDEX IF EXISTS idx_companies_npwp;
DROP INDEX IF EXISTS idx_companies_nib;
DROP FUNCTION IF EXISTS normalise_tax_id(TEXT);

ALTER TABLE companies
    DROP COLUMN IF EXISTS entity_type,
    DROP COLUMN IF EXISTS nib;

DROP TYPE IF EXISTS entity_kind;

COMMIT;
