BEGIN;
DELETE FROM company_modules WHERE product = 'tms' AND module IN ('dispatch', 'configuration');
COMMIT;
