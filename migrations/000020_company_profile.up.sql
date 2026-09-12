-- The company profile: what goes on a document.
--
-- A company was a name, a tax number and an address. That is enough to
-- identify one and not enough to print one: a delivery note, an invoice or
-- an FMS report carries the legal name, a phone number, an email, a postal
-- code, and the logo. FMS kept all of that on its own tenants row; with
-- identity moving here it needs a home here, and TMS wants the same fields
-- the day it prints an invoice.
--
-- Plain columns, not settings JSONB: these are queried and printed, and a
-- JSON blob is where a field goes to become unqueryable.
--
-- city / province are NAMES. city_id and province_id are legacy identifiers
-- carried from the monolith that nothing resolves any more; the names are
-- what a document prints.
--
-- logo_key is an object key in the uploads bucket, deliberately not a URL: a
-- signed URL expires, and a stored one rots. logo_url stays for the legacy
-- rows that hold a public URL.

BEGIN;

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS legal_name  VARCHAR(255),
    ADD COLUMN IF NOT EXISTS phone       VARCHAR(32),
    ADD COLUMN IF NOT EXISTS email       VARCHAR(255),
    ADD COLUMN IF NOT EXISTS website     VARCHAR(255),
    ADD COLUMN IF NOT EXISTS city        VARCHAR(128),
    ADD COLUMN IF NOT EXISTS province    VARCHAR(128),
    ADD COLUMN IF NOT EXISTS postal_code VARCHAR(16),
    ADD COLUMN IF NOT EXISTS country     CHAR(2) NOT NULL DEFAULT 'ID',
    ADD COLUMN IF NOT EXISTS logo_key    VARCHAR(512);

COMMENT ON COLUMN companies.name IS
    'Display name, what the console shows — "Karlo". legal_name is what a document prints.';
COMMENT ON COLUMN companies.legal_name IS
    'Registered name as printed on documents — "PT Karlo Logistik Indonesia". NULL falls back to name.';
COMMENT ON COLUMN companies.country IS
    'ISO 3166-1 alpha-2.';
COMMENT ON COLUMN companies.logo_key IS
    'Object key in the uploads bucket. Never a URL: signed URLs expire.';

COMMIT;
