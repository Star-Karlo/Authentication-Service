-- The Driver system role gives back warehouse.read and dispatch.read.
--
-- 000022 granted them so K-Trip could show a warehouse address and draw the
-- planned road. Both are module keys and carried far more than that:
-- warehouse.read lists every site the company owns, dispatch.read opens the
-- planner's live fleet map, per-driver activity and the candidate trucks for
-- any order. A driver's phone held all of it to render one card and one line.
--
-- The business service now carries the trip's two warehouses on the shipment
-- read and serves the driver's own legs at GET /shipments/{id}/route, gated on
-- being the assigned driver rather than on a module key, so the app needs
-- neither. K-Trip build 120 and later use those; older builds lose the address
-- until they update, which is why this is a separate migration from 000022 and
-- not a revert of it.
UPDATE roles
SET permissions = ARRAY(
        SELECT p FROM unnest(permissions) AS p
        WHERE p NOT IN ('tms:warehouse.read', 'tms:dispatch.read')
    ),
    updated_at = now()
WHERE name = 'Driver' AND is_system;
