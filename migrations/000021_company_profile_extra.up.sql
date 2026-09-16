-- The rest of the company profile: what the console's Profil Perusahaan
-- shows and no document prints.
--
-- Founded year, service types, operating regions, the PIC's name and
-- position, NIB, the registered KPP. None of them is queried, joined or
-- printed — they are read back as one block onto one screen — so unlike
-- migration 000020 they go in a JSONB column rather than eight nullable
-- ones. A field that later turns out to be worth querying moves to its own
-- column then, with the data already in hand.

BEGIN;

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS profile JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN companies.profile IS
    'Free-form profile fields the console shows and nothing queries: foundedYear, serviceTypes, operatingRegions, picName, picPosition, picPhone, nib, kppLocation.';

COMMIT;
