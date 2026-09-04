-- Micopay MVP — Schema base
-- Aplicado por el migration runner (src/db/migrate.ts) ANTES de las migraciones.
-- Reparado 2026-06-28: la tabla `users` tenía columnas duplicadas (no parseaba) y `audit_log`
-- estaba definido dos veces. Nullabilidad de users alineada con el borrado de cuenta
-- (account.service.ts pone username/stellar_address/phone_hash en NULL al anonimizar).

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ================================================
-- USERS
-- (username/stellar_address/phone_hash son NULLABLE: se ponen en NULL al borrar la cuenta,
--  preservando el valor anonimizado en las columnas deleted_*.)
-- ================================================
CREATE TABLE users (
  id                       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  stellar_address          VARCHAR(56) UNIQUE,
  username                 VARCHAR(30) UNIQUE,
  phone_hash               VARCHAR(64) UNIQUE,
  -- #371: merchant_available defaults to false; only active providers should
  -- be discoverable. Kept as a compatibility boolean alongside availability.
  merchant_available       BOOLEAN NOT NULL DEFAULT false,
  -- #371: explicit provider enrollment status. New users are not enrolled.
  provider_status          VARCHAR(20) NOT NULL DEFAULT 'not_enrolled'
                           CHECK (provider_status IN ('not_enrolled', 'pending_verification', 'active', 'suspended')),
  deleted_at               TIMESTAMPTZ,
  deleted_username         VARCHAR(30),
  deleted_stellar_address  VARCHAR(56),
  deleted_phone_hash       VARCHAR(64),
  created_at               TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_users_stellar ON users (stellar_address);

-- #371: idx_users_provider_active is created by migration
-- 20260828000000_provider_enrollment.up.sql AFTER availability exists.

-- ================================================
-- WALLETS
-- ================================================
CREATE TABLE wallets (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID UNIQUE NOT NULL REFERENCES users(id),
  stellar_address VARCHAR(56) NOT NULL,
  wallet_type     VARCHAR(15) DEFAULT 'self_custodial',
  created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ================================================
-- TRADES
-- ================================================
CREATE TABLE trades (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),

  seller_id       UUID NOT NULL REFERENCES users(id),
  buyer_id        UUID NOT NULL REFERENCES users(id),

  amount_mxn      INTEGER NOT NULL,
  amount_stroops  BIGINT NOT NULL,
  seller_fee_mxn  INTEGER NOT NULL DEFAULT 0,
  platform_fee_mxn INTEGER NOT NULL DEFAULT 0,

  -- HTLC
  secret_hash     VARCHAR(64) NOT NULL,
  secret_enc      BYTEA,
  secret_nonce    BYTEA,

  -- Estado
  status          VARCHAR(12) DEFAULT 'pending'
                  CHECK (status IN (
                    'pending', 'locked', 'revealing',
                    'completed', 'cancelled', 'expired', 'refunded'
                  )),

  -- Stellar
  stellar_trade_id VARCHAR(64),
  lock_tx_hash    VARCHAR(64),
  release_tx_hash VARCHAR(64),

  -- Timestamps
  locked_at       TIMESTAMPTZ,
  reveal_requested_at TIMESTAMPTZ,
  completed_at    TIMESTAMPTZ,
  expires_at      TIMESTAMPTZ,

  created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_trades_seller ON trades (seller_id, status);
CREATE INDEX idx_trades_buyer ON trades (buyer_id, status);
CREATE INDEX idx_trades_status ON trades (status, expires_at)
  WHERE status IN ('locked', 'revealing');

-- ================================================
-- TRADE AUDIT LOG
-- (versión canónica usada por src/db/audit-log.model.ts; la columna request_id la agrega
--  la migración 20260529120000_audit_log_request_id.up.sql)
-- ================================================
CREATE TABLE audit_log (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  trade_id        UUID NOT NULL REFERENCES trades(id) ON DELETE CASCADE,
  from_state      VARCHAR(12) NOT NULL,
  to_state        VARCHAR(12) NOT NULL,
  actor           TEXT NOT NULL,
  metadata        JSONB NOT NULL DEFAULT '{}'::jsonb,
  occurred_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_trade_time ON audit_log (trade_id, occurred_at ASC);
CREATE INDEX idx_audit_log_trade_to_state ON audit_log (trade_id, to_state);

-- ================================================
-- SECRET ACCESS LOG
-- ================================================
CREATE TABLE secret_access_log (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  trade_id        UUID NOT NULL REFERENCES trades(id),
  user_id         UUID NOT NULL REFERENCES users(id),
  ip_address      INET NOT NULL,
  user_agent      TEXT,
  accessed_at     TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_secret_access_trade ON secret_access_log (trade_id);

-- ================================================
-- PROCESSED TX (replay protection)
-- Append-only: every confirmed Stellar tx hash acted on. The PRIMARY KEY makes
-- INSERT … ON CONFLICT DO NOTHING atomic so duplicates are rejected under concurrency.
-- ================================================
CREATE TABLE processed_tx (
  tx_hash       VARCHAR(64) PRIMARY KEY,
  source_route  VARCHAR(64) NOT NULL,
  user_id       UUID        NOT NULL,
  processed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_processed_tx_user
  ON processed_tx (user_id, processed_at DESC);
