-- Reverse 000013. Every company becomes unlimited again.
BEGIN;
ALTER TABLE companies DROP COLUMN IF EXISTS max_users;
COMMIT;
