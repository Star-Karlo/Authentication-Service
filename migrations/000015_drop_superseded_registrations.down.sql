-- Reverse 000015. The columns come back EMPTY: their contents were obsolete
-- registration numbers and are not reconstructible from anything else.
BEGIN;
ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS no_siup VARCHAR(64),
    ADD COLUMN IF NOT EXISTS no_tdp VARCHAR(64);
COMMIT;
