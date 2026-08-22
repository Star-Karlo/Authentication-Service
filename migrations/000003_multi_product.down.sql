ALTER TABLE companies DROP COLUMN IF EXISTS fms_tenant_id;

DROP TRIGGER IF EXISTS trg_user_product_access_updated_at ON user_product_access;
DROP TABLE IF EXISTS user_product_access;

ALTER TABLE company_module_history DROP COLUMN IF EXISTS product;

ALTER TABLE company_modules DROP CONSTRAINT IF EXISTS company_modules_pkey;
ALTER TABLE company_modules ADD PRIMARY KEY (company_id, module);
ALTER TABLE company_modules DROP COLUMN IF EXISTS product;

DROP INDEX IF EXISTS idx_users_platform_staff;
ALTER TABLE users DROP COLUMN IF EXISTS is_platform_staff;

DROP TABLE IF EXISTS products;
