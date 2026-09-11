BEGIN;
DROP INDEX IF EXISTS idx_companies_abbreviation;
ALTER TABLE companies DROP COLUMN IF EXISTS abbreviation;
COMMIT;
