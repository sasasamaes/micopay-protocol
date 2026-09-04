import type { FastifyInstance } from 'fastify';
import { authMiddleware } from '../middleware/auth.middleware.js';
import db from '../db/schema.js';
import { getOrCreateMerchantConfig } from '../services/merchant.service.js';
import { getEffectiveKycLevel } from '../services/kyc-gate.service.js';

/**
 * #371 — RED-1: Provider enrollment and readiness endpoints.
 *
 * POST /providers/enroll    — start or confirm enrollment (idempotent)
 * POST /providers/activate  — activate after readiness checks pass
 * GET  /providers/readiness — report profile/location/limits/KYC completeness
 *
 * These are self-service, authenticated endpoints. They never create a second
 * user or wallet — enrollment is a status change on the existing user row.
 */
export async function providerRoutes(app: FastifyInstance) {
  /**
   * POST /providers/enroll
   *
   * Idempotent. Transitions the user from not_enrolled → pending_verification.
   * If the user is already pending or active, returns the current status
   * without side effects. Suspended providers cannot re-enroll through this
   * endpoint (admin intervention required).
   *
   * Does NOT automatically activate — activation requires complete profile,
   * location, limits, and general (Didit) KYC. See GET /providers/readiness.
   */
  app.post(
    '/providers/enroll',
    { preHandler: [authMiddleware] },
    async (request, reply) => {
      const userId = request.user.id;

      const user = await db.getOne<{ provider_status: string }>(
        `SELECT provider_status FROM users WHERE id = $1`,
        [userId],
      );

      if (!user) {
        reply.status(404).send({ code: 'USER_NOT_FOUND', message: 'Usuario no encontrado.' });
        return;
      }

      // Idempotent: already enrolled or pending — return current status.
      if (user.provider_status === 'pending_verification' || user.provider_status === 'active') {
        reply.status(200).send({
          provider_status: user.provider_status,
          message: user.provider_status === 'active'
            ? 'Ya eres un proveedor activo.'
            : 'Tu enrolamiento ya esta en proceso.',
        });
        return;
      }

      // Suspended providers cannot re-enroll without admin intervention.
      if (user.provider_status === 'suspended') {
        reply.status(403).send({
          code: 'PROVIDER_SUSPENDED',
          message: 'Tu cuenta de proveedor esta suspendida. Contacta a soporte.',
        });
        return;
      }

      // not_enrolled → pending_verification
      await db.execute(
        `UPDATE users SET provider_status = 'pending_verification' WHERE id = $1`,
        [userId],
      );

      request.log.info(
        { user_id: userId, category: 'provider' },
        '[provider] Enrollment started',
      );

      reply.status(200).send({
        provider_status: 'pending_verification',
        message: 'Enrolamiento iniciado. Completa tu perfil y verificacion para activar.',
      });
    },
  );

  /**
   * POST /providers/activate
   *
   * Transitions pending_verification → active when all readiness checks pass.
   * Idempotent: returns current status if already active.
   * Re-checks readiness server-side so the client cannot skip requirements.
   */
  app.post(
    '/providers/activate',
    { preHandler: [authMiddleware] },
    async (request, reply) => {
      const userId = request.user.id;

      const user = await db.getOne<{
        provider_status: string;
        username: string | null;
        kyc_level: number | null;
        kyc_provider: string | null;
        is_suspended: boolean;
        is_banned: boolean;
      }>(
        `SELECT provider_status, username, kyc_level, kyc_provider, is_suspended, is_banned
         FROM users WHERE id = $1`,
        [userId],
      );

      if (!user) {
        reply.status(404).send({ code: 'USER_NOT_FOUND', message: 'Usuario no encontrado.' });
        return;
      }

      if (user.is_banned) {
        reply.status(403).send({
          code: 'ACCOUNT_BANNED',
          message: 'Tu cuenta ha sido baneada.',
        });
        return;
      }

      if (user.is_suspended) {
        reply.status(403).send({
          code: 'ACCOUNT_SUSPENDED',
          message: 'Tu cuenta esta suspendida. Contacta a soporte.',
        });
        return;
      }

      if (user.provider_status === 'active') {
        reply.status(200).send({
          provider_status: 'active',
          message: 'Ya eres un proveedor activo.',
        });
        return;
      }

      if (user.provider_status === 'suspended') {
        reply.status(403).send({
          code: 'PROVIDER_SUSPENDED',
          message: 'Tu cuenta de proveedor esta suspendida. Contacta a soporte.',
        });
        return;
      }

      if (user.provider_status !== 'pending_verification') {
        reply.status(409).send({
          code: 'NOT_ENROLLED',
          message: 'Debes completar el enrolamiento primero.',
        });
        return;
      }

      // Re-run readiness checks server-side
      const merchantConfig = await db.getOne<{
        latitude: number | null;
        longitude: number | null;
        min_trade_mxn: number | null;
        max_trade_mxn: number | null;
      }>(
        `SELECT latitude, longitude, min_trade_mxn, max_trade_mxn
         FROM merchant_configs WHERE user_id = $1`,
        [userId],
      );

      const effectiveKycLevel = await getEffectiveKycLevel(userId);

      const checks = {
        profile_complete: Boolean(user.username && user.username.length >= 3),
        location_set: Boolean(merchantConfig?.latitude != null && merchantConfig?.longitude != null),
        limits_set: Boolean(
          merchantConfig?.min_trade_mxn != null &&
          merchantConfig?.max_trade_mxn != null &&
          merchantConfig.max_trade_mxn >= merchantConfig.min_trade_mxn
        ),
        kyc_complete: effectiveKycLevel >= 1 && user.kyc_provider === 'didit',
      };

      const all_ready = Object.values(checks).every(Boolean);

      if (!all_ready) {
        const missing = Object.entries(checks)
          .filter(([, v]) => !v)
          .map(([k]) => k);
        reply.status(422).send({
          code: 'READINESS_INCOMPLETE',
          message: 'Faltan requisitos para activar.',
          missing,
        });
        return;
      }

      await db.execute(
        `UPDATE users
         SET provider_status = 'active',
             merchant_available = true,
             availability = 'online'
         WHERE id = $1`,
        [userId],
      );

      request.log.info(
        { user_id: userId, category: 'provider' },
        '[provider] Provider activated',
      );

      reply.status(200).send({
        provider_status: 'active',
        message: 'Proveedor activo. Ya puedes recibir operaciones.',
      });
    },
  );

  /**
   * GET /providers/readiness
   *
   * Reports what is missing before the provider can be activated.
   * Activation requires ALL of:
   *   1. Profile completeness (username set)
   *   2. Merchant config with location (latitude/longitude set)
   *   3. General KYC level >= 1 via Didit (Etherfuse does NOT satisfy this)
   *
   * The response is advisory — it does not change any state.
   */
  app.get(
    '/providers/readiness',
    { preHandler: [authMiddleware] },
    async (request, reply) => {
      const userId = request.user.id;

      const user = await db.getOne<{
        provider_status: string;
        username: string | null;
        kyc_level: number | null;
        kyc_provider: string | null;
      }>(
        `SELECT provider_status, username, kyc_level, kyc_provider
         FROM users WHERE id = $1`,
        [userId],
      );

      if (!user) {
        reply.status(404).send({ code: 'USER_NOT_FOUND', message: 'Usuario no encontrado.' });
        return;
      }

      // Check merchant config completeness
      const config = await db.getOne<{
        latitude: number | null;
        longitude: number | null;
        min_trade_mxn: number | null;
        max_trade_mxn: number | null;
      }>(
        `SELECT latitude, longitude, min_trade_mxn, max_trade_mxn
         FROM merchant_configs WHERE user_id = $1`,
        [userId],
      );

      // Didit KYC check (effective level, not just stored)
      const effectiveKycLevel = await getEffectiveKycLevel(userId);

      const checks = {
        profile_complete: Boolean(user.username && user.username.length >= 3),
        location_set: Boolean(config?.latitude != null && config?.longitude != null),
        limits_set: Boolean(
          config?.min_trade_mxn != null &&
          config?.max_trade_mxn != null &&
          config.max_trade_mxn >= config.min_trade_mxn
        ),
        // #371: Etherfuse-only approval does NOT satisfy this requirement.
        // Only Didit general KYC counts.
        kyc_complete: effectiveKycLevel >= 1 && user.kyc_provider === 'didit',
      };

      const all_ready = Object.values(checks).every(Boolean);

      reply.status(200).send({
        provider_status: user.provider_status,
        readiness: {
          ...checks,
          all_ready,
        },
        // Guidance for the frontend
        next_steps: all_ready
          ? ['Puedes solicitar activacion desde la app.']
          : [
              ...(!checks.profile_complete ? ['Completa tu perfil (nombre de usuario).'] : []),
              ...(!checks.location_set ? ['Agrega tu ubicacion (latitud/longitud).'] : []),
              ...(!checks.limits_set ? ['Configura tus limites de operacion.'] : []),
              ...(!checks.kyc_complete ? ['Completa tu verificacion de identidad con Didit (nivel 1 o superior).'] : []),
            ],
      });
    },
  );
}
