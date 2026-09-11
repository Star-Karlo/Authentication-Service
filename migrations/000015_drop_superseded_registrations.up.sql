-- Remove the pre-2018 business registration numbers.
--
-- SIUP (Surat Izin Usaha Perdagangan) and TDP (Tanda Daftar Perusahaan) were
-- both replaced by NIB when the OSS system launched in 2018. Existing ones
-- stayed valid until they expired; by now none has. A SIUP number recorded
-- today identifies a licence that no longer exists as a legal instrument.
--
-- The schema already carries what replaced them: `nib` for a business and
-- `npwp` for the tax number, which is the identity key and the one an
-- individual has too.
--
-- What the legacy export actually holds, which is what makes this safe:
--
--   6,156 companies
--     526 have an NPWP
--     390 have a SIUP
--     389 have a TDP
--       6 have a SIUP or TDP and NO NPWP
--
-- So six companies lose their only recorded registration number, and they keep
-- their name, address and contact details. Against that, keeping two obsolete
-- columns means every form, every import and every reader has to decide what
-- they are for — and the answer is nothing.

BEGIN;

ALTER TABLE companies
    DROP COLUMN IF EXISTS no_siup,
    DROP COLUMN IF EXISTS no_tdp;

COMMENT ON COLUMN companies.nib IS
    'Nomor Induk Berusaha, the single business registration number since 2018. Replaced SIUP and TDP, which this schema carried until 000015. Company-only: a personal shipper has none, which is why NPWP and not NIB is the identity key.';

COMMIT;
