-- Down migration: remove provider_status column and restore previous defaults.

DROP INDEX IF EXISTS idx_users_provider_active;

ALTER TABLE users DROP CONSTRAINT IF EXISTS chk_provider_status;

ALTER TABLE users DROP COLUMN IF EXISTS provider_status;

-- Restore merchant_available default to true (pre-#371 behavior).
ALTER TABLE users ALTER COLUMN merchant_available SET DEFAULT true;
