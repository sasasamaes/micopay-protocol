-- Migration 20260828000000: Add explicit provider enrollment status.
-- Issue #371 — RED-1: Account creation, Red MicoPay membership, verification
-- and current availability are different facts. This migration adds an
-- explicit enrollment state so that a normal user cannot accidentally appear
-- as a cash provider.

-- ── provider_status enum ──────────────────────────────────────────────────
-- not_enrolled        – default for all new and existing users
-- pending_verification – user started enrollment, awaiting KYC/config review
-- active              – approved provider, discoverable if also available
-- suspended           – temporarily removed from discovery by admin or auto-pause

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS provider_status VARCHAR(20) NOT NULL DEFAULT 'not_enrolled';

-- Set default for existing databases where the column was created before #371.
ALTER TABLE users ALTER COLUMN merchant_available SET DEFAULT false;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'chk_provider_status'
  ) THEN
    ALTER TABLE users
      ADD CONSTRAINT chk_provider_status
      CHECK (provider_status IN ('not_enrolled', 'pending_verification', 'active', 'suspended'));
  END IF;
END $$;

-- ── Backfill existing users ───────────────────────────────────────────────
-- Production was confirmed to hold no real users on 2026-08-27, so this is
-- a safe default rather than a data-interpretation problem. Every existing
-- row becomes not_enrolled and unavailable.

UPDATE users
SET provider_status = 'not_enrolled',
    merchant_available = false,
    availability = 'offline'
WHERE provider_status = 'not_enrolled'
   OR merchant_available = true
   OR availability != 'offline';

-- ── Index for discovery eligibility ───────────────────────────────────────
-- Partial index: only active providers are eligible for discovery filtering.
-- The query in merchant.service.ts filters on provider_status = 'active' +
-- availability = 'online' + merchant_available = true.

CREATE INDEX IF NOT EXISTS idx_users_provider_active
  ON users (provider_status, availability, merchant_available)
  WHERE provider_status = 'active';
