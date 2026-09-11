-- Grant dispatch and form configuration to every existing company.
--
-- These two are part of the base product, but entitlement is stored one row per
-- company per feature and is read literally — an absent row is a denial. So a
-- feature added to DefaultTMSFeatures reaches NEW companies only; every company
-- that already existed holds nothing for it.
--
-- The consequence is worth stating because it is invisible: RequireModule calls
-- HasPermission, which refuses any permission whose gating feature the company
-- does not hold. Without these rows every dispatch.* and config.fields.*
-- endpoint answers 403 for everybody, including administrators — grants_all
-- means "everything the company is entitled to", and the company is entitled to
-- nothing here. Nothing errors and no test fails; the endpoints are simply dark.
--
-- This is the same fix migration 000012 made for collaboration and masterData,
-- for the same reason. Both are base-product entitlements that can still be
-- withdrawn deliberately, which is why they are rows rather than an exemption
-- in the checking code.

BEGIN;

-- product is part of the primary key, added when the platform became
-- multi-product. Both features belong to TMS.
INSERT INTO company_modules (company_id, product, module, enabled, note)
SELECT c.id, 'tms', m.module, TRUE,
       'Base product entitlement, granted by migration 000016.'
FROM companies c
CROSS JOIN (VALUES ('dispatch'), ('configuration')) AS m(module)
WHERE c.deleted_at IS NULL
ON CONFLICT (company_id, product, module) DO UPDATE
    -- DO UPDATE rather than DO NOTHING: a company that holds a DISABLED row
    -- from an earlier experiment would otherwise keep it and stay denied, and
    -- the conflict would hide that rather than fix it.
    SET enabled = TRUE;

COMMIT;
