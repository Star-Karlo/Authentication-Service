-- Reverse 000012.
--
-- Leaves the rows in place rather than deleting them. Removing them would take
-- administration away from every company, and the code at the version this
-- reverts to did not consult these features anyway — so deleting would cause
-- harm to undo something that was doing none.
BEGIN;
SELECT 1;
COMMIT;
