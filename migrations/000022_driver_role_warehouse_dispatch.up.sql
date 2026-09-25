-- The Driver system role gains warehouse.read and dispatch.read.
--
-- The K-Trip app reads the two warehouses of a trip (address, pin, geofence
-- radius, PIC) and the planned road between them; both routes sit behind
-- these keys and a driver's token did not carry them, so the app showed
-- warehouse names only. New Driver roles get the keys from code; this tops
-- up the ones that already exist. Drivers pick it up on their next login.
UPDATE roles
SET permissions = array_cat(
        permissions,
        ARRAY(SELECT k FROM unnest(ARRAY['tms:warehouse.read', 'tms:dispatch.read']) AS k
              WHERE NOT (permissions @> ARRAY[k]))
    ),
    updated_at = now()
WHERE name = 'Driver' AND is_system;
