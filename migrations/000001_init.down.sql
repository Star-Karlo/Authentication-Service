DROP TRIGGER IF EXISTS trg_user_documents_updated_at ON user_documents;
DROP TRIGGER IF EXISTS trg_device_tokens_updated_at  ON device_tokens;
DROP TRIGGER IF EXISTS trg_users_updated_at          ON users;
DROP TRIGGER IF EXISTS trg_companies_updated_at      ON companies;
DROP FUNCTION IF EXISTS set_updated_at();

DROP TABLE IF EXISTS auth_audit_log;
DROP TABLE IF EXISTS collaboration_invites;
DROP TABLE IF EXISTS user_documents;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS device_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS companies;
