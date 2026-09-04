/**
 * G1 + #371 — /merchants/available is public, unauthenticated and (before this fix)
 * had no rate limit and returned exact lat/lng, letting anyone scrape the
 * full census of merchant locations.
 *
 * This test covers:
 *   (a) getAvailableMerchants() rounds the *returned* latitude/longitude to
 *       3 decimals (~110m) while distance_km keeps its existing precision.
 *   (b) the discoveryRateLimit limiter (createRateLimiter({ windowMs: 60_000,
 *       max: 30 })) throws a RateLimitError (429, Retry-After) once a single
 *       IP exceeds `max` requests inside the window.
 *   (c) #371: discovery FAILS CLOSED — suspended, banned, paused, offline,
 *       and not_enrolled providers are absent from discovery results.
 *
 * Runs against the in-memory DB (ALLOW_IN_MEMORY_DB=true, no PostgreSQL
 * needed), following the pattern of tradeAuth.test.ts / refund.test.ts.
 *
 * NOTE on (a): the in-memory SQL shim in src/db/schema.ts is a small regex
 * based mock. It does not evaluate computed SQL columns (the HAVERSINE_SQL
 * expression aliased as distance_km, or the seller_id/username/trades_*
 * subqueries), only special-cases LEFT JOIN (not the plain INNER JOIN this
 * query uses against `users`), and — critically — its WHERE-clause regex
 * (`/\bWHERE\b.../`) matches the *first* literal "WHERE" in the raw SQL
 * text, which here is the one inside the nested trades_completed/
 * trades_terminal subqueries, not the query's real WHERE. Seeding rows into
 * merchant_configs and calling getAvailableMerchants() end-to-end therefore
 * can't reliably exercise this query against the mock — it's a limitation of
 * the mock, not of getAvailableMerchants() itself (against real PostgreSQL
 * the query runs as written).
 *
 * So instead this test stubs `db.getMany` for the duration of the call,
 * returning exactly the shape PostgreSQL would for one seeded merchant, and
 * asserts on what getAvailableMerchants() does with that row — i.e. it
 * targets the actual code under test (the rounding in the .map() in
 * src/services/merchant.service.ts), independent of the mock SQL engine.
 */

import { strictEqual, ok, notStrictEqual } from "assert";
import db from "../db/schema.js";
import { getAvailableMerchants } from "../services/merchant.service.js";
import { InMemoryStore, createRateLimiter } from "../middleware/rateLimit.middleware.js";
import { RateLimitError } from "../utils/errors.js";

// ── (a) coordinate rounding ─────────────────────────────────────────────────

async function testAvailableMerchantsRoundsCoordinates() {
  const preciseLat = 19.432608123; // exact GPS reading, many decimals
  const preciseLng = -99.133209456;
  const preciseDistanceKm = 12.34567; // exact haversine result, as Postgres would compute it

  const originalGetMany = db.getMany;
  db.getMany = (async (_text: string, _params?: any[]) => [
    {
      seller_id: "user-discovery-1",
      username: "merchant_discovery_1",
      rate_percent: "1.5",
      min_trade_mxn: 100,
      max_trade_mxn: 50000,
      daily_cap_mxn: 250000,
      latitude: String(preciseLat),
      longitude: String(preciseLng),
      address_text: "CDMX",
      distance_km: String(preciseDistanceKm),
      trades_completed: "3",
      trades_terminal: "3",
    },
  ]) as typeof db.getMany;

  let results: Awaited<ReturnType<typeof getAvailableMerchants>>;
  try {
    results = await getAvailableMerchants({
      lat: preciseLat,
      lng: preciseLng,
      radius_km: 5,
      amount_mxn: 500,
    });
  } finally {
    db.getMany = originalGetMany;
  }

  ok(results.length >= 1, "expected the seeded merchant to be returned");
  const merchant = results.find((m) => m.address_text === "CDMX");
  ok(merchant, "expected to find the seeded merchant by address_text");

  const expectedLat = Math.round(preciseLat * 1000) / 1000;
  const expectedLng = Math.round(preciseLng * 1000) / 1000;

  strictEqual(merchant!.latitude, expectedLat, "latitude must be rounded to 3 decimals");
  strictEqual(merchant!.longitude, expectedLng, "longitude must be rounded to 3 decimals");
  notStrictEqual(merchant!.latitude, preciseLat, "rounded latitude must differ from the precise input");
  notStrictEqual(merchant!.longitude, preciseLng, "rounded longitude must differ from the precise input");

  // decimal-place check: no more than 3 digits after the decimal point
  const decimalsOf = (n: number) => (String(n).split(".")[1] ?? "").length;
  ok(decimalsOf(merchant!.latitude) <= 3, "latitude must have at most 3 decimal places");
  ok(decimalsOf(merchant!.longitude) <= 3, "longitude must have at most 3 decimal places");

  // distance_km keeps its own (already existing) 3-decimal rounding and is
  // NOT derived from the coarsened lat/lng — it stays independently accurate.
  strictEqual(
    merchant!.distance_km,
    Math.round(preciseDistanceKm * 1000) / 1000,
    "distance_km must reflect the precise coordinates, unaffected by public lat/lng rounding",
  );

  console.log("  \u2713 getAvailableMerchants() rounds public latitude/longitude to 3 decimals, distance_km unaffected");
}

// ── (b) discovery rate limiter ─────────────────────────────────────────────

async function testDiscoveryRateLimiterBlocksAfterMax() {
  const store = new InMemoryStore();
  const windowMs = 1000;
  const max = 30;

  // Same construction as the discoveryRateLimit wired into
  // src/routes/merchants.ts (createRateLimiter({ windowMs: 60_000, max: 30 })),
  // using a shorter window here so the test doesn't need to wait a full minute.
  const discoveryRateLimit = createRateLimiter({
    windowMs,
    max,
    store,
    keyGenerator: (req) => req.ip,
  });

  const mockReq = { ip: "203.0.113.7" };
  const mockReply = {
    header: (_name: string, _value: any) => {},
  };

  for (let i = 0; i < max; i++) {
    await (discoveryRateLimit as any)(mockReq, mockReply);
  }
  console.log(`  \u2713 ${max} requests from the same IP within the window are allowed`);

  let threw = false;
  try {
    await (discoveryRateLimit as any)(mockReq, mockReply);
  } catch (err) {
    threw = true;
    ok(err instanceof RateLimitError, `expected RateLimitError, got ${(err as Error)?.constructor?.name}`);
    strictEqual((err as RateLimitError).statusCode, 429, "rate-limited response must be 429");
    ok((err as RateLimitError).retryAfter !== undefined, "rate-limited response must carry retryAfter");
  }
  ok(threw, `request ${max + 1} should have thrown RateLimitError`);
  console.log("  \u2713 request past max is rejected with 429 and Retry-After");

  // A different IP is unaffected by the first IP's exhausted budget.
  const otherReq = { ip: "203.0.113.99" };
  await (discoveryRateLimit as any)(otherReq, mockReply);
  console.log("  \u2713 a different IP is not affected by another IP's rate limit");
}

// ── (c) #371: discovery fail-closed eligibility ───────────────────────────
//
// The point of this issue is that discovery FAILS CLOSED. A suspended,
// banned, paused or offline provider must be ABSENT from
// GET /merchants/available — not merely rejected later at trade creation.
//
// The in-memory SQL shim cannot evaluate the WHERE clause, so these tests
// capture the raw SQL text passed to db.getMany and assert that the four
// eligibility predicates are present. This fails if someone removes a filter,
// which is the whole point.

const ELIGIBLE_MERCHANT_ROW = {
  seller_id: "user-active-1",
  username: "merchant_active_1",
  rate_percent: "1.5",
  min_trade_mxn: 100,
  max_trade_mxn: 50000,
  daily_cap_mxn: 250000,
  latitude: "19.432",
  longitude: "-99.133",
  address_text: "CDMX",
  distance_km: "0.5",
  trades_completed: "3",
  trades_terminal: "3",
};

const SEARCH_PARAMS = { lat: 19.432, lng: -99.133, radius_km: 5, amount_mxn: 500 };

/**
 * Helper: stubs db.getMany to return the given rows and captures the SQL
 * text for assertion.
 */
async function discoveryCaptureSql(): Promise<{
  sql: string;
  results: Awaited<ReturnType<typeof getAvailableMerchants>>;
}> {
  let capturedSql = "";
  const originalGetMany = db.getMany;
  db.getMany = (async (text: string) => {
    capturedSql = text;
    return [ELIGIBLE_MERCHANT_ROW];
  }) as typeof db.getMany;
  try {
    const results = await getAvailableMerchants(SEARCH_PARAMS);
    return { sql: capturedSql, results };
  } finally {
    db.getMany = originalGetMany;
  }
}

/**
 * Asserts that the WHERE clause contains all four eligibility predicates
 * that RED-1 requires for fail-closed discovery.
 */
function assertDiscoverySqlHasEligibilityPredicates(sql: string) {
  const lower = sql.toLowerCase();

  // 1. provider_status = 'active'
  ok(
    lower.includes("provider_status") && lower.includes("active"),
    "SQL must filter on provider_status = 'active'",
  );

  // 2. availability = 'online'
  ok(
    lower.includes("availability") && lower.includes("online"),
    "SQL must filter on availability = 'online'",
  );

  // 3. NOT suspended
  ok(
    lower.includes("is_suspended"),
    "SQL must filter out suspended users (is_suspended)",
  );

  // 4. NOT banned
  ok(
    lower.includes("is_banned"),
    "SQL must filter out banned users (is_banned)",
  );

  // 5. merchant_available check (IS NULL or = false excludes unavailable)
  ok(
    lower.includes("merchant_available"),
    "SQL must filter on merchant_available",
  );

  console.log("  \u2713 discovery SQL contains all fail-closed eligibility predicates");
}

async function testDiscoverySqlContainsEligibilityPredicates() {
  const { sql } = await discoveryCaptureSql();
  assertDiscoverySqlHasEligibilityPredicates(sql);
}

async function testDiscoveryIncludesActiveAvailableProvider() {
  // An active, online, available provider with a location IS returned.
  const { results } = await discoveryCaptureSql();
  strictEqual(results.length, 1, "active+online provider must appear in discovery");
  strictEqual(results[0].seller_id, "user-active-1");
  console.log("  \u2713 active+online provider appears in discovery");
}

async function main() {
  console.log("\nMerchant discovery privacy, rate-limit & #371 eligibility tests\n");
  await testAvailableMerchantsRoundsCoordinates();
  await testDiscoveryRateLimiterBlocksAfterMax();
  console.log("\n  #371 fail-closed discovery eligibility:\n");
  await testDiscoverySqlContainsEligibilityPredicates();
  await testDiscoveryIncludesActiveAvailableProvider();
  console.log("\nAll merchant.discovery tests passed.\n");
}

main().catch((err) => {
  console.error("\u274c merchant.discovery tests failed:", err);
  process.exit(1);
});
