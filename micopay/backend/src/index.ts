import Fastify from 'fastify';
import fastifyJwt from '@fastify/jwt';
import fastifyCors from '@fastify/cors';
import fastifyHelmet from '@fastify/helmet';
import { config, validateConfig, getCorsOptions } from './config.js';
import { pingDb } from './db/schema.js';
import { runMigrations } from './db/migrate.js';
import { authRoutes } from './routes/auth.js';
import { userRoutes } from './routes/users.js';
import { tradeRoutes } from './routes/trades.js';
import { stellarRoutes } from './routes/stellar.js';
import { defiRoutes } from './routes/defi.js';
import { merchantRoutes } from './routes/merchants.js';
import { adminRoutes } from './routes/admin.js';
import { tradeSafetyRoutes } from './routes/trade-safety.js';
import { rateRoutes } from './routes/rate.js';
import { kycRoutes } from './routes/kyc.js';
import { rampRoutes } from './routes/ramp.js';
import { signRequestsRoutes } from './routes/sign-requests.js';
import { clientErrorRoutes } from './routes/client-errors.js';
import { providerRoutes } from './routes/providers.js';
import { AppError } from './utils/errors.js';
import { Keypair } from '@stellar/stellar-sdk';
import fastifyStatic from '@fastify/static';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { registerRequestId, toSupportCode } from './middleware/requestId.middleware.js';
import { createProductionListener } from './services/event-listener.service.js';
import type { EscrowEventListener } from './services/event-listener.service.js';
import { sweepPendingRefunds } from './services/trade.service.js';
import { startComplianceJob, stopComplianceJob } from './services/compliance.service.js';

// Resolve the absolute path to the public/ directory next to src/
const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, '..', 'public');

// SEC-02 pide redactar el material del QR en logs de API/proxy/analytics. Cubre
// tanto el body de la request como cualquier objeto que se loguee con esas
// claves (el preimage ya no viaja, pero el token de cobro sigue siendo una
// capacidad de un solo uso).
const LOG_REDACT_PATHS = [
  'req.body.claim_token',
  'claim_token',
  'claimToken',
  'qr_payload',
  'qrPayload',
  'secret',
];

const app = Fastify({
  trustProxy: true,
  logger: process.env.NODE_ENV === 'development' ? {
    level: 'info',
    redact: LOG_REDACT_PATHS,
    transport: {
      target: 'pino-pretty',
      options: { colorize: true, translateTime: 'HH:MM:ss Z' },
    },
  } : {
    level: 'info',
    redact: LOG_REDACT_PATHS,
    formatters: {
      bindings: (o) => ({ ...o, service: 'micopay-backend' }),
    },
  },
});

// --- Plugins ---

// Serve files in public/ as static assets (e.g. .well-known/assetlinks.json).
// decorateReply:false avoids conflicts if another plugin adds sendFile.
app.register(fastifyStatic, {
  root: PUBLIC_DIR,
  prefix: '/',
  decorateReply: false,
});

// --- Android Digital Asset Links ---
// Explicit route for /.well-known/assetlinks.json.
// Android's App Links verifier calls this URL and:
//   1. Requires HTTP 200 — it does NOT follow redirects.
//   2. Requires Content-Type: application/json.
//   3. Caches the response (we set 1 hour).
// The fastify-static plugin alone might redirect if the path ends without
// the extension, so this explicit route is the authoritative handler.
app.get('/.well-known/assetlinks.json', async (_request, reply) => {
  const fs = await import('node:fs/promises');
  const filePath = join(PUBLIC_DIR, '.well-known', 'assetlinks.json');
  try {
    const content = await fs.readFile(filePath, 'utf-8');
    reply
      .status(200)
      .header('Content-Type', 'application/json')
      .header('Cache-Control', 'public, max-age=3600')
      .send(content);
  } catch (err) {
    reply.status(404).send({ error: 'assetlinks.json not found' });
  }
});

// --- Security Plugins ---

// Register security headers via @fastify/helmet
app.register(fastifyHelmet, {
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://soroban-testnet.stellar.org", "https://soroban.stellar.org", "https://horizon-testnet.stellar.org"],
    },
  },
  referrerPolicy: {
    policy: "strict-origin-when-cross-origin",
  },
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  },
  frameguard: {
    action: "deny",
  },
  noSniff: true,
  xssFilter: true,
});

// Register CORS with secure configuration
app.register(fastifyCors, getCorsOptions());

// JWT
app.register(fastifyJwt, {
  secret: config.jwtSecret,
});

// Correlation ID — must be registered before any route / error handler reads request.log
registerRequestId(app);

// Rate limit (optional — gracefully skip if not available)
try {
  const rateLimit = await import('@fastify/rate-limit');
  app.register(rateLimit.default, { global: false });
  } catch {
    app.log.warn({ category: 'http' }, '⚠️  @fastify/rate-limit not installed, skipping rate limiting');
  }

// --- Global error handler ---
app.setErrorHandler((error, request, reply) => {
  const requestId: string = (request as any).requestId ?? reply.getHeader('x-request-id') ?? 'unknown';
  const supportCode = toSupportCode(requestId);

  if (error instanceof AppError) {
    if (error.httpStatus >= 500) {
      request.log.error({ err: error }, `[${error.code}] ${error.devMessage}`);
    } else {
      request.log.info({ err: error }, `[${error.code}] ${error.devMessage}`);
    }

    reply.status(error.httpStatus).send({
      code: error.code,
      message: error.userMessage,
      request_id: requestId,
      support_code: supportCode,
    });
    return;
  }

  // Fastify validation errors
  if (error.validation) {
    request.log.warn({ err: error }, `Validation Error: ${error.message}`);
    reply.status(400).send({
      code: 'VALIDATION_ERROR',
      message: 'Por favor, verifica los datos ingresados.',
      request_id: requestId,
      support_code: supportCode,
    });
    return;
  }

  // Unknown errors
  request.log.error({ err: error }, 'Unhandled Error');
  reply.status(500).send({
    code: 'INTERNAL_ERROR',
    message: 'Ocurrió un error inesperado. Por favor, intenta más tarde.',
    request_id: requestId,
    support_code: supportCode,
  });
});

// --- Routes ---

// Holds the singleton event listener (null when disabled or mock mode).
let eventListener: EscrowEventListener | null = null;

app.get('/health', async (_request, reply) => {
  // B-7: real readiness — actually round-trip to PostgreSQL, don't just
  // check that a connection string is present.
  const dbConnected = await pingDb();
  // In production a live DB is required to be "ready"; outside production the
  // in-memory fallback is acceptable for demos/tests.
  const ready = dbConnected || !config.isProduction;
  if (!ready) reply.code(503);
  return {
    status: ready ? 'ok' : 'unavailable',
    timestamp: new Date().toISOString(),
    mockStellar: config.mockStellar,
    dbConnected,
    eventListenerHealthy: eventListener?.isHealthy() ?? false,
    eventListenerState: eventListener?.currentState() ?? 'disabled',
    configCheck: {
      hasPlatformKey: !!config.platformSecretKey,
      hasContractId: !!config.escrowContractId,
      hasDbUrl: !!config.databaseUrl,
      hasSecretKey: !!config.secretEncryptionKey,
    }
  };
});

// Platform account balance from Horizon (public, no auth needed)
app.get('/account/balance', async (request) => {
  try {
    if (!config.platformSecretKey) {
      return { xlm: '0', address: 'Billetera no configurada', status: 'setup_required' };
    }
    const keypair = Keypair.fromSecret(config.platformSecretKey);
    const address = keypair.publicKey();
    const horizonUrl = config.stellarNetwork === 'TESTNET'
      ? 'https://horizon-testnet.stellar.org'
      : 'https://horizon.stellar.org';
    const res = await fetch(`${horizonUrl}/accounts/${address}`);
    if (!res.ok) return { xlm: '0', address, status: 'not_found_on_chain' };
    const data = await res.json() as { balances: { asset_type: string; balance: string }[] };
    const xlm = data.balances.find((b) => b.asset_type === 'native')?.balance ?? '0';
    return { xlm, address, status: 'ok' };
  } catch (err: any) {
    request.log.error({ err: err.message, category: 'stellar.balance' }, '[Stellar] Balance error');
    return { xlm: '0', address: 'Error', error: err.message };
  }
});

app.register(authRoutes, { prefix: '' });
app.register(userRoutes, { prefix: '' });
app.register(tradeRoutes, { prefix: '' });
app.register(stellarRoutes, { prefix: '' });
app.register(defiRoutes, { prefix: '' });
app.register(merchantRoutes, { prefix: '' });
app.register(tradeSafetyRoutes, { prefix: '' });
app.register(adminRoutes, { prefix: '' });
app.register(rateRoutes, { prefix: '' });
app.register(kycRoutes, { prefix: '' });
app.register(rampRoutes, { prefix: '' });
app.register(signRequestsRoutes, { prefix: '' });
app.register(providerRoutes, { prefix: '' });
// El ErrorBoundary del frontend postea aquí; la ruta existía sin registrar, así
// que hasta ahora todo reporte de crash caía en un 404
// (docs/AUDIT_MOBILE_MAINNET.md §6, "Ruta backend definida pero no registrada").
app.register(clientErrorRoutes, { prefix: '' });

// --- Start server ---

async function seedData() {
  const db = (await import('./db/schema.js')).default;
  const existing = await db.getMany('SELECT id FROM trades LIMIT 1');
  if (existing.length > 0) return;

  app.log.info({ category: 'seed' }, '🌱 Seeding demo trades...');
  const users = await db.getMany('SELECT id FROM users');
  if (users.length < 2) {
    // #371: demo seed users are explicitly set as active providers.
    await db.execute(
      `INSERT INTO users (username, stellar_address, merchant_available, availability, provider_status)
       VALUES ('juan_test', 'GBUYER...', true, 'online', 'active')`,
    );
    await db.execute(
      `INSERT INTO users (username, stellar_address, merchant_available, availability, provider_status)
       VALUES ('farmacia_test', 'GSELLER...', true, 'online', 'active')`,
    );
  }
  const allUsers = await db.getMany('SELECT id FROM users');
  const userId = allUsers[0].id;
  const sellerId = allUsers[1].id;

  const statuses = ['completed', 'cancelled', 'pending', 'locked', 'revealing'];
  const now = new Date();

  for (let i = 0; i < 20; i++) {
    const status = statuses[i % statuses.length];
    const amount = 150 + (i * 75);
    const createdAt = new Date(now.getTime() - (i * 3600000 * 2));
    const expiresAt = new Date(createdAt.getTime() + 7200000);
    
    await db.execute(
      `INSERT INTO trades 
       (seller_id, buyer_id, amount_mxn, amount_stroops, platform_fee_mxn, 
        secret_hash, status, created_at, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        i % 2 === 0 ? sellerId : userId,
        i % 2 === 0 ? userId : sellerId,
        amount,
        (amount * 10000000).toString(),
        Math.ceil(amount * 0.008),
        `hash_${i}`,
        status,
        createdAt,
        expiresAt
      ]
    );
  }
  app.log.info({ category: 'seed' }, '✅ Seeding complete');
}

/**
 * Seed demo merchants with real CDMX coordinates so the discovery map has pins
 * during a testnet/demo run. Only runs on the ephemeral in-memory store
 * (ALLOW_IN_MEMORY_DB=true) and is idempotent.
 */
async function seedDemoMerchants(): Promise<void> {
  const db = (await import('./db/schema.js')).default;

  // Demo origin for seeded merchants. Override per-deployment with
  // SEED_ORIGIN_LAT / SEED_ORIGIN_LNG so the discovery map shows agents near
  // wherever the demo is run. Default: northern CDMX metro.
  const center = {
    lat: Number(process.env.SEED_ORIGIN_LAT ?? 19.689),
    lng: Number(process.env.SEED_ORIGIN_LNG ?? -99.179),
  };

  const merchants = [
    { username: 'farmacia_guadalupe',   rate: 1.0, dlat: 0.004,  dlng: 0.003,  addr: 'Av. Juárez 34, Centro',          completed: 12, cancelled: 0 },
    { username: 'abarrotes_la_esquina', rate: 1.5, dlat: -0.005, dlng: 0.006,  addr: 'Calle 5 de Mayo 12, Centro',     completed: 8,  cancelled: 1 },
    { username: 'tienda_don_chendo',    rate: 0.8, dlat: 0.007,  dlng: -0.004, addr: 'Madero 88, Centro Histórico',    completed: 21, cancelled: 1 },
    { username: 'cafe_lopez',           rate: 2.0, dlat: -0.003, dlng: -0.007, addr: 'Regina 19, Col. Centro',         completed: 5,  cancelled: 0 },
  ];

  // If already seeded, just reposition the configs to the current origin (the
  // demo origin env may have changed) and stop — keeps trade history intact.
  const already = await db
    .getOne("SELECT id FROM users WHERE username = 'farmacia_guadalupe'")
    .catch(() => null);
  if (already) {
    for (const m of merchants) {
      await db.execute(
        `UPDATE merchant_configs SET latitude = $2, longitude = $3, updated_at = NOW()
         WHERE user_id = (SELECT id FROM users WHERE username = $1)`,
        [m.username, center.lat + m.dlat, center.lng + m.dlng],
      ).catch(() => {});
    }
    app.log.info({ category: 'seed' }, '📍 Demo merchants repositioned to current origin');
    return;
  }

  app.log.info({ category: 'seed' }, '🌱 Seeding demo merchants for the map…');

  // A shared counterparty so completed trades have a buyer.
  const buyerAddr = 'GDEMOCLIENTE'.padEnd(56, 'X').slice(0, 56);
  let buyer = await db.getOne("SELECT id FROM users WHERE username = 'cliente_demo'");
  if (!buyer) {
    buyer = await db.getOne(
      `INSERT INTO users (username, stellar_address, merchant_available, availability, provider_status)
       VALUES ('cliente_demo', $1, false, 'offline', 'not_enrolled') RETURNING id`,
      [buyerAddr],
    );
  }

  for (const m of merchants) {
    const stellar = ('G' + m.username.toUpperCase().replace(/[^A-Z0-9]/g, 'X')).padEnd(56, 'X').slice(0, 56);
    // #371: demo seed data explicitly creates active providers.
    const user = await db.getOne(
      `INSERT INTO users (username, stellar_address, merchant_available, availability, provider_status)
       VALUES ($1, $2, true, 'online', 'active') RETURNING id`,
      [m.username, stellar],
    );
    await db.execute(`INSERT INTO wallets (user_id, stellar_address) VALUES ($1, $2)`, [user.id, stellar]).catch(() => {});
    await db.execute(
      `INSERT INTO merchant_configs
         (user_id, rate_percent, min_trade_mxn, max_trade_mxn, daily_cap_mxn, latitude, longitude, address_text, updated_at)
       VALUES ($1, $2, 100, 50000, 250000, $3, $4, $5, NOW())`,
      [user.id, m.rate, center.lat + m.dlat, center.lng + m.dlng, m.addr],
    );

    const now = Date.now();
    const rows = [
      ...Array(m.completed).fill('completed'),
      ...Array(m.cancelled).fill('cancelled'),
    ];
    for (let i = 0; i < rows.length; i++) {
      const amount = 200 + (i % 8) * 150;
      const createdAt = new Date(now - i * 86400000);
      await db.execute(
        `INSERT INTO trades
           (seller_id, buyer_id, amount_mxn, amount_stroops, platform_fee_mxn, secret_hash, status, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
        [
          user.id,
          buyer!.id,
          amount,
          (amount * 10000000).toString(),
          Math.ceil(amount * 0.008),
          `seed_${m.username}_${i}`,
          rows[i],
          createdAt,
          new Date(createdAt.getTime() + 7200000),
        ],
      ).catch(() => {});
    }
  }

  app.log.info({ category: 'seed', count: merchants.length }, '✅ Demo merchants seeded');
}

async function startEventListener(): Promise<void> {
  if (!config.eventListenerEnabled || config.mockStellar || !config.escrowContractId) {
    app.log.info(
      { category: 'event-listener', enabled: config.eventListenerEnabled, mock: config.mockStellar },
      '[event-listener] Skipped (disabled, mock mode, or no contract ID configured)',
    );
    return;
  }

  try {
    eventListener = createProductionListener(
      config.escrowContractId,
      config.stellarRpcUrl,
      {
        pollIntervalMs: config.eventListenerPollMs,
        healthStaleMs: config.eventListenerHealthStaleMs,
      },
    );
    await eventListener.start();
    app.log.info(
      { contract_id: config.escrowContractId, poll_ms: config.eventListenerPollMs, category: 'event-listener' },
      '[event-listener] Soroban event listener active',
    );
  } catch (err) {
    // Non-fatal: polling fallback remains active.
    app.log.error({ err, category: 'event-listener' }, '[event-listener] Failed to start — polling fallback is active');
  }
}

// Holds the refund-sweep interval handle (null when disabled, e.g. mock mode).
let refundSweepInterval: NodeJS.Timeout | null = null;
const REFUND_SWEEP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Cancelling a locked/revealing trade doesn't itself settle on-chain funds —
 * the contract's refund() only becomes callable once its timeout passes (see
 * docs/AUDIT_MOBILE_MAINNET.md finding B3). This periodic sweep is the safety
 * net that finishes those refunds automatically instead of leaving them
 * depending on a user manually retrying from the app.
 */
function startRefundSweep(): void {
  if (config.mockStellar) {
    app.log.info({ category: 'refund-sweep' }, '[refund-sweep] Skipped (mock Stellar mode)');
    return;
  }

  refundSweepInterval = setInterval(async () => {
    try {
      const { swept, failed } = await sweepPendingRefunds({ log: app.log });
      if (swept > 0 || failed > 0) {
        app.log.info({ swept, failed, category: 'refund-sweep' }, '[refund-sweep] Cycle complete');
      }
    } catch (err) {
      app.log.error({ err, category: 'refund-sweep' }, '[refund-sweep] Cycle failed');
    }
  }, REFUND_SWEEP_INTERVAL_MS);

  app.log.info(
    { category: 'refund-sweep', interval_ms: REFUND_SWEEP_INTERVAL_MS },
    '[refund-sweep] Started',
  );
}

async function start() {
  try {
    // Validate config at startup. Will throw and crash if critical config is missing.
    validateConfig();

    // Ensure the schema exists before seeding/serving. Idempotent; only runs
    // against a real PostgreSQL connection (the in-memory store needs no migrations).
    if (await pingDb()) {
      try {
        await runMigrations();
      } catch (err) {
        app.log.error({ err, category: 'db' }, '[db] Boot migrations failed');
      }
    }

    // B-4: only seed demo data when explicitly enabled — never in a fresh prod DB.
    if (config.seedDemoData) {
      await seedData();
      // Demo merchants with CDMX coordinates so the discovery map has pins.
      await seedDemoMerchants().catch((err) =>
        app.log.error({ err, category: 'seed' }, 'Demo merchant seed failed'),
      );
    } else {
      app.log.info(
        { category: 'seed' },
        'Skipping demo seed (set SEED_DEMO_DATA=true to enable)',
      );
    }
    await app.listen({ port: config.port, host: '0.0.0.0' });
    app.log.info({ category: 'http', port: config.port }, '🍄 Micopay MVP Backend running');
    app.log.info({ category: 'http', mockStellar: config.mockStellar }, `Mock Stellar: ${config.mockStellar ? 'ON (no on-chain verification)' : 'OFF (real Soroban RPC)'}`);
    app.log.info({ category: 'http', database: config.databaseUrl.replace(/\/\/.*@/, '//***@') }, 'Database connected');
    
    // Log security configuration on startup
    app.log.info({ category: 'security' }, `[SECURITY] NODE_ENV: ${config.nodeEnv}`);
    app.log.info({ category: 'security' }, `[SECURITY] CORS Allowed Origins: ${config.corsAllowedOrigins.length > 0 ? config.corsAllowedOrigins.join(', ') : 'NONE (all CORS requests rejected)'}`);
    app.log.info({ category: 'security' }, `[SECURITY] Security Headers: Helmet enabled with CSP, HSTS, X-Frame-Options, X-Content-Type-Options`);
    
    await startEventListener();
    startRefundSweep();
    startComplianceJob();
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

// Graceful shutdown: stop the listener loop before the process exits.
for (const sig of ['SIGTERM', 'SIGINT'] as const) {
  process.on(sig, () => {
    eventListener?.stop();
    if (refundSweepInterval) clearInterval(refundSweepInterval);
    stopComplianceJob();
    process.exit(0);
  });
}

start();
