/**
 * Optional Cloudflare Worker -> TiDB Cloud Starter honeypot event sink.
 * Only derived, bounded observations are written; never credentials, request
 * bodies, raw IP, query strings, cookies or untrusted paths.
 *
 * IMPORTANT: DB account must be INSERT-only on honeypot_events. A root
 * connection URL is explicitly rejected. Only known honeypot routes invoke it.
 * No opt-in or random sampling flag; missing/invalid secret fails closed.
 * URL components are validated and decoded once before passing as separate
 * serverless-driver credential fields; no secret values are logged.
 */
import { connect } from "@tidbcloud/serverless";
import { buildAxiomSecurityEvent } from "./axiom-honeypot.js";

const HOST = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com";
const INSERT_SQL = `INSERT INTO vynalth_honeypot.honeypot_events
  (event_type, source, protocol, source_ip_hash, country_code, request_path, action_taken)
  VALUES (?, ?, ?, ?, ?, ?, ?)`;

// Privacy-safe time-limited outcome telemetry. No raw IP, request URL, credentials,
// SQL parameters, error messages, device IDs or raw HTTP headers are logged.
const SAFE_OUTCOMES = new Set([
  "no_lifecycle", "not_configured",
  "invalid_event", "inserted", "failed",
]);
// Single-deployment short observation window. Expiration is evaluated per
// request, so logging automatically stops without another production release.
// A missing/malformed/too-distant UTC deadline fails closed.
export function honeypotDiagnosticsEnabled(env, now = Date.now()) {
  if (env?.TIDB_HONEYPOT_DIAGNOSTICS_ENABLED !== "true") return false;
  const until = env?.TIDB_HONEYPOT_DIAGNOSTICS_UNTIL;
  if (typeof until !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(until)) return false;
  const end = Date.parse(until);
  return Number.isFinite(end) && end > now && end - now <= 2 * 60 * 60 * 1000;
}
function logSafeOutcome(env, state, reason = "none", stage = "unknown") {
  if (!honeypotDiagnosticsEnabled(env) || !SAFE_OUTCOMES.has(state)) return;
  const allowedReasons = new Set([
    "none", "missing_ctx", "bad_url", "event", "insert", "schema", "auth",
    "quota", "transport", "timeout", "other",
  ]);
  const allowedStages = new Set(["normalization", "connect", "execute", "unknown"]);
  const outcome = {
    event: "tidb_honeypot_write_result",
    state,
    reason: allowedReasons.has(reason) ? reason : "other",
    event_version: "tidb-sampled-result-v1",
  };
  // Stage is a bounded, non-sensitive label. Never log error objects or SQL.
  if (state === "failed")
    outcome.stage = allowedStages.has(stage) ? stage : "unknown";
  console.info("[HONEY TIDB OUTCOME]", JSON.stringify(outcome));
}
function safeErrorCategory(error) {
  const message = typeof error?.message === "string" ? error.message : "";
  // Only emit fixed labels; raw errors may contain connection strings/secrets.
  if (/unknown column|unknown table|doesn't exist|42s22|42s02/i.test(message)) return "schema";
  if (/access denied|permission|privilege|invalid password|authentication|401|403/i.test(message)) return "auth";
  if (/quota|rate limit|too many requests|402|429/i.test(message)) return "quota";
  if (/timeout|timed out|abort/i.test(message)) return "timeout";
  if (/network|fetch failed|econn|enotfound|tls|dns/i.test(message)) return "transport";
  return "other";
}

export function safeTiDBFailureSummary(error, stage = "unknown") {
  const known = new Set(["normalization", "connect", "execute"]);
  return {
    event: "tidb_honeypot_write_failure",
    reason: safeErrorCategory(error),
    stage: known.has(stage) ? stage : "unknown",
  };
}
const lastFailureLogAt = new Map();
let lastInsertAckLogAt = 0;
function logLimitedTiDBFailure(summary, now = Date.now()) {
  const key = summary.stage + ":" + summary.reason;
  if (now - (lastFailureLogAt.get(key) || 0) < 60000) return;
  lastFailureLogAt.set(key, now);
  // Never log the exception, SQL text, DB URL, IP or request details.
  console.warn("[TIDB HONEYPOT] insert failed", JSON.stringify(summary));
}
function logLimitedTiDBSuccess(now = Date.now()) {
  if (now - lastInsertAckLogAt < 60000) return;
  lastInsertAckLogAt = now;
  console.info("[TIDB HONEYPOT] insert acknowledged");
}

function validDatabaseConfig(env) {
  const raw = env?.TIDB_HONEYPOT_DATABASE_URL;
  if (typeof raw !== "string" || raw.length > 1024) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== "mysql:" || u.hostname !== HOST || u.port ||
        u.pathname !== "/vynalth_honeypot" || u.search || u.hash ||
        !u.username || !u.password) return null;
    // The public TiDB serverless driver supports discrete credential fields.
    // Decode a properly percent-encoded URL exactly once to avoid ambiguous
    // special-character treatment at the HTTP authentication boundary.
    // Never log or expose these fields; malformed escapes fail closed.
    const username = decodeURIComponent(u.username);
    const password = decodeURIComponent(u.password);
    if (!username || !password || username.toLowerCase().endsWith(".root") ||
        username.toLowerCase() === "root") return null;
    return { host: HOST, username, password, database: "vynalth_honeypot" };
  } catch {
    return null;
  }
}

export async function dispatchTidbHoneypotEvent(args, connectImpl = connect) {
  const config = validDatabaseConfig(args.env);
  if (!config) {
    logSafeOutcome(args.env, "not_configured", "bad_url");
    return { state: "not_configured" };
  }
  let failureStage = "normalization";
  try {
    const observation = await buildAxiomSecurityEvent(args);
    if (!observation || observation.source !== "cloudflare_worker") {
      logSafeOutcome(args.env, "invalid_event", "event");
      return { state: "invalid_event" };
    }
    // Only known static decoys / explicit WordPress installer blocks.
    if (args.kind !== "wp_installer_block" &&
        !["php", "phpinfo", "diagnostics", "login", "database", "config",
          "files", "backup"].includes(args.kind)) {
      logSafeOutcome(args.env, "invalid_event", "event");
      return { state: "invalid_event" };
    }
    failureStage = "connect";
    const connection = connectImpl(config);
    failureStage = "execute";
    await connection.execute(INSERT_SQL, [
      "suspicious_probe",
      "cloudflare_worker",
      "HTTP",
      observation.network_actor_id,
      observation.country,
      observation.path,
      observation.action === "block" ? "blocked" : "logged",
    ]);
    logSafeOutcome(args.env, "inserted", "insert");
    if (!honeypotDiagnosticsEnabled(args.env)) logLimitedTiDBSuccess();
    return { state: "inserted" };
  } catch (error) {
    // Sanitized fixed categories only; no raw connection URL or exception text.
    const summary = safeTiDBFailureSummary(error, failureStage);
    if (honeypotDiagnosticsEnabled(args?.env))
      logSafeOutcome(args.env, "failed", summary.reason, summary.stage);
    else logLimitedTiDBFailure(summary);
    return { state: "failed" };
  }
}


/**
 * Operator-only, explicitly requested TiDB acceptance probe. This produces
 * event_type=acceptance_probe, not a forged hostile security observation.
 * The sole write principal stays INSERT-only. Independent readback requires
 * a distinct optional SELECT-only SQL credential; absence is never PASS.
 */
const ACCEPTANCE_MARKER_RE = new RegExp(
  "^/__ops/tidb-acceptance/[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$", "i"
);
const READBACK_SQL = `SELECT id FROM vynalth_honeypot.honeypot_events
 WHERE source = ? AND event_type = ? AND request_path = ? LIMIT 1`;

function acceptanceReadConfig(env, writer) {
  const reader = validDatabaseConfig({
    TIDB_HONEYPOT_DATABASE_URL: env?.TIDB_HONEYPOT_READONLY_DATABASE_URL,
  });
  // Readback must never try to SELECT using the INSERT-only writer principal.
  return reader && writer && reader.username !== writer.username ? reader : null;
}

export function tidbAcceptanceConnectionStatus(env) {
  const writer = validDatabaseConfig(env);
  return {
    writerConfigured: Boolean(writer),
    readerConfigured: Boolean(acceptanceReadConfig(env, writer)),
  };
}

export async function runTidbAcceptanceProbe(env, marker, connectImpl = connect) {
  if (typeof marker !== "string" || !ACCEPTANCE_MARKER_RE.test(marker))
    return { state: "invalid_marker" };
  const writer = validDatabaseConfig(env);
  if (!writer) return { state: "not_configured" };
  let stage = "connect";
  try {
    const conn = connectImpl(writer);
    stage = "execute";
    await conn.execute(INSERT_SQL, [
      "acceptance_probe", "cloudflare_worker", "HTTP", null, null, marker, "logged",
    ]);
  } catch (error) {
    const summary = safeTiDBFailureSummary(error, stage);
    return { state: "failed", reason: summary.reason, stage: summary.stage };
  }
  const reader = acceptanceReadConfig(env, writer);
  if (!reader) return { state: "insert_acknowledged", readback: "manual_required" };
  try {
    const rows = await connectImpl(reader).execute(READBACK_SQL, [
      "cloudflare_worker", "acceptance_probe", marker,
    ]);
    const found = Array.isArray(rows)
      ? rows.length > 0
      : Array.isArray(rows?.rows) && rows.rows.length > 0;
    return found
      ? { state: "verified", readback: "confirmed" }
      : { state: "insert_acknowledged", readback: "not_found" };
  } catch (error) {
    return {
      state: "insert_acknowledged",
      readback: "failed",
      readbackReason: safeTiDBFailureSummary(error, "execute").reason,
    };
  }
}

export function scheduleTidbHoneypotEvent(args) {
  // Only reached by an allowlisted honeypot route from src/index.js.
  // Every eligible event attempts an async INSERT; invalid configuration
  // fails closed, and database failure never blocks the decoy response.
  if (typeof args?.ctx?.waitUntil !== "function") {
    logSafeOutcome(args?.env, "no_lifecycle", "missing_ctx");
    return false;
  }
  if (!validDatabaseConfig(args.env)) {
    logSafeOutcome(args.env, "not_configured", "bad_url");
    return false;
  }
  args.ctx.waitUntil(dispatchTidbHoneypotEvent(args));
  return true;
}
