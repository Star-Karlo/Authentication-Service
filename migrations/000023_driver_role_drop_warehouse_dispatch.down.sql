-- Put them back, as 000022 did.
UPDATE roles
SET permissions = array_cat(
        permissions,
        ARRAY(SELECT k FROM unnest(ARRAY['tms:warehouse.read', 'tms:dispatch.read']) AS k
              WHERE NOT (permissions @> ARRAY[k]))
    ),
    updated_at = now()
WHERE name = 'Driver' AND is_system;
