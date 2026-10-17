import { z } from "zod";

const nodeEnvironment = z
  .enum(["development", "test", "production"])
  .catch("development")
  .parse(process.env.NODE_ENV);

const developmentSecret = "development-only-secret-change-before-production-123456";
const suppliedSecret = process.env.SESSION_SECRET?.trim();
const unsafeProductionSecret =
  !suppliedSecret ||
  /change-(?:me|before-production)|development-only|playwright-only|placeholder|replace-me|example/i.test(
    suppliedSecret
  );

if (nodeEnvironment === "production" && unsafeProductionSecret) {
  throw new Error(
    "SESSION_SECRET is required in production, must be at least 32 characters long and cannot be a placeholder."
  );
}

const schema = z.object({
  DATABASE_URL: z.string().min(1).default("file:./dev.db"),
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must contain at least 32 characters."),
  SCAN_MODE: z.enum(["mock", "safe-live"]).default("mock"),
  APP_URL: z.string().url().default("http://localhost:3000"),
  SESSION_COOKIE_NAME: z.string().min(1).default("riskmap_session"),
  SESSION_TTL_HOURS: z.coerce.number().int().positive().default(168),
  LOGIN_RATE_LIMIT: z.coerce.number().int().positive().default(10),
  LOGIN_RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(900_000),
  SCAN_WORKER_POLL_MS: z.coerce.number().int().min(500).default(2500),
  SCAN_MAX_CONCURRENCY: z.coerce.number().int().min(1).max(5).default(2),
  SCAN_TIMEOUT_MS: z.coerce.number().int().min(1000).max(15_000).default(5000),
  SCAN_RESPONSE_LIMIT_BYTES: z.coerce
    .number()
    .int()
    .min(4096)
    .max(1_048_576)
    .default(65_536),
  SCAN_ALLOWED_PORTS: z
    .string()
    .default(
      "21,22,25,53,80,110,143,443,465,587,993,995,3306,5432,6379,8080,8443,9200,27017,3389"
    ),
  ASSET_ABSENCE_THRESHOLD: z.coerce.number().int().min(1).max(10).default(2),
  SERVICE_ABSENCE_THRESHOLD: z.coerce.number().int().min(1).max(10).default(2),
  FINDING_RESOLUTION_ABSENCE_THRESHOLD: z.coerce.number().int().min(1).max(10).default(1),
  SCAN_ORGANISATION_RATE_LIMIT: z.coerce.number().int().positive().default(6),
  SCAN_GLOBAL_RATE_LIMIT: z.coerce.number().int().positive().default(100),
  SCAN_RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(3_600_000),
  SCAN_JOB_TIMEOUT_MS: z.coerce.number().int().min(30_000).max(3_600_000).default(300_000),
  SCAN_JOB_MAX_ATTEMPTS: z.coerce.number().int().min(1).max(10).default(3),
  SCAN_JOB_RETRY_BASE_MS: z.coerce.number().int().min(1000).max(300_000).default(10_000),
  WORKER_HEARTBEAT_INTERVAL_MS: z.coerce
    .number()
    .int()
    .min(1000)
    .max(300_000)
    .default(15_000),
  WORKER_STALE_AFTER_MS: z.coerce.number().int().min(5000).max(900_000).default(60_000),
  WORKER_HEARTBEAT_FILE: z.string().min(1).default(".runtime/worker-heartbeat.json"),
  WORKER_LOCK_FILE: z.string().min(1).default(".runtime/worker.lock"),
  LOG_LEVEL: z.enum(["debug", "info", "warn", "error"]).default("info"),
  QUICK_CHECK_RATE_LIMIT: z.coerce.number().int().positive().default(10),
  QUICK_CHECK_WINDOW_MS: z.coerce.number().int().positive().default(60_000),
  ALLOW_LOOPBACK_DEMO_VERIFICATION: z
    .enum(["true", "false"])
    .default("false")
    .transform((value) => value === "true"),
  NODE_ENV: z.enum(["development", "test", "production"])
});

export const env = schema.parse({
  ...process.env,
  NODE_ENV: nodeEnvironment,
  SESSION_SECRET: suppliedSecret ?? developmentSecret
});

export const secureCookies = new URL(env.APP_URL).protocol === "https:";
const appHostname = new URL(env.APP_URL).hostname;
const appIsLoopback = new Set(["localhost", "127.0.0.1", "::1"]).has(appHostname);
export const demoVerificationEnabled =
  env.SCAN_MODE === "mock" &&
  (env.NODE_ENV !== "production" ||
    (appIsLoopback && env.ALLOW_LOOPBACK_DEMO_VERIFICATION));

if (env.NODE_ENV === "production") {
  const appUrl = new URL(env.APP_URL);
  if (appUrl.protocol !== "https:" && !appIsLoopback) {
    throw new Error(
      "APP_URL must use HTTPS in production unless it targets a local loopback address."
    );
  }
}

export const SAFE_LIVE_PORT_ALLOWLIST = Object.freeze([
  21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8080, 8443, 9200,
  27017, 3389
]);

const hardAllowedPorts = new Set<number>(SAFE_LIVE_PORT_ALLOWLIST);

export const allowedPorts = [
  ...new Set(
    env.SCAN_ALLOWED_PORTS.split(",")
      .map((value) => Number(value.trim()))
      .filter((value) => Number.isInteger(value) && hardAllowedPorts.has(value))
  )
].sort((left, right) => left - right);
