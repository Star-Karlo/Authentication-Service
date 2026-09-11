-- Grant the administration and reference-data features to every company.
--
-- Every permission is now gated: an ungated one skipped the entitlement check
-- entirely, which made a forgotten Feature field silently grant access to
-- everyone. Fourteen keys were in that state, including managing your own
-- members and reading master data.
--
-- Gating them without granting the features would REVOKE those abilities from
-- every existing company — including the ability to invite the member who would
-- fix it. So the features are granted here, and the net effect for an existing
-- company is nothing at all: the check is uniform, and the answer is unchanged.
--
-- 000002's backfill already granted `collaboration` and `masterData` as module
-- names; they were simply never declared as features, so nothing consulted
-- them. This makes the two lists agree.

BEGIN;

INSERT INTO company_modules (company_id, product, module, enabled)
SELECT c.id, 'tms', m.module, TRUE
FROM companies c
CROSS JOIN (VALUES ('collaboration'), ('masterData')) AS m(module)
ON CONFLICT (company_id, product, module) DO UPDATE SET enabled = TRUE;

COMMIT;
