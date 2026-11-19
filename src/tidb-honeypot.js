/**
 * Optional Cloudflare Worker -> TiDB Cloud Starter honeypot event sink.
 * Only derived, bounded observations are written; never credentials, request
 * bodies, raw IP, query strings, cookies or untrusted paths.
 *
 * IMPORTANT: DB account must be INSERT-only on honeypot_events. A root
 * connection URL is explicitly rejected. This feature is disabled by default.
 */
import { connect } from "@tidbcloud/serverless";
import { buildAxiomSecurityEvent } from "./axiom-honeypot.js";

const HOST = "gateway01.ap-southeast-1.prod.aws.tidbcloud.com";
const INSERT_SQL = `INSERT INTO vynalth_honeypot.honeypot_events
  (event_type, source, protocol, source_ip_hash, country_code, request_path, action_taken)
  VALUES (?, ?, ?, ?, ?, ?, ?)`;

// Privacy-safe sampled outcome telemetry. No raw IP, request URL, credentials,
// SQL parameters, error messages, device IDs or raw HTTP headers are logged.
// Disabled until the owner explicitly enables it for ONE planned release.
const SAFE_OUTCOMES = new Set([
  "disabled", "no_lifecycle", "sampled_out", "not_configured",
  "invalid_event", "inserted", "failed",
]);
// Single-deployment short observation window. Expiration is evaluated per
// request, so logging automatically stops without another production release.
// A missing/malformed/too-distant UTC deadline fails closed.
export function honeypotDiagnosticsEnabled(env, now = Date.now()) {
  if (env?.TIDB_HONEYPOT_DIAGNOSTICS_ENABLED !== "true") return false;
  const until = env?.TIDB_HONEYPOT_DIAGNOSTICS_UNTIL;
  if (typeof until !== "string" ||
      !/^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}Z$/.test(until)) return false;
  const end = Date.parse(until);
  return Number.isFinite(end) && end > now && end - now <= 2 * 60 * 60 * 1000;
}
function logSafeOutcome(env, state, reason = "none") {
  if (!honeypotDiagnosticsEnabled(env) || !SAFE_OUTCOMES.has(state)) return;
  const allowedReasons = new Set([
    "none", "disabled", "missing_ctx", "sampling", "bad_url", "event", "insert", "schema", "auth",
    "quota", "transport", "timeout", "other",
  ]);
  console.info("[HONEY TIDB OUTCOME]", JSON.stringify({
    event: "tidb_honeypot_write_result",
    state,
    reason: allowedReasons.has(reason) ? reason : "other",
    event_version: "tidb-sampled-result-v1",
  }));
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

function validDatabaseUrl(env) {
  const raw = env?.TIDB_HONEYPOT_DATABASE_URL;
  if (typeof raw !== "string" || raw.length > 1024) return null;
  try {
    const u = new URL(raw);
    if (u.protocol !== "mysql:" || u.hostname !== HOST || u.port ||
        u.pathname !== "/vynalth_honeypot" || u.search || u.hash ||
        !u.username || !u.password || u.username.toLowerCase().endsWith(".root") ||
        u.username.toLowerCase() === "root") return null;
    return raw;
  } catch {
    return null;
  }
}

function shouldSample(env, random = Math.random) {
  const value = env?.TIDB_HONEYPOT_SAMPLE_RATE ?? "0.1";
  const rate = Number(value);
  return Number.isFinite(rate) && rate > 0 && rate <= 1 &&
    (rate === 1 || random() < rate);
}

export async function dispatchTidbHoneypotEvent(args, connectImpl = connect) {
  if (args?.env?.TIDB_HONEYPOT_INGEST_ENABLED !== "true")
    return { state: "disabled" };
  const url = validDatabaseUrl(args.env);
  if (!url) {
    logSafeOutcome(args.env, "not_configured", "bad_url");
    return { state: "not_configured" };
  }
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
    const connection = connectImpl({ url });
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
    return { state: "inserted" };
  } catch (error) {
    // Sanitized fixed categories only; no raw connection URL or exception text.
    const reason = safeErrorCategory(error);
    if (honeypotDiagnosticsEnabled(args?.env))
      logSafeOutcome(args.env, "failed", reason);
    else console.warn("[TIDB HONEYPOT] insert failed");
    return { state: "failed" };
  }
}

export function scheduleTidbHoneypotEvent(args, random = Math.random) {
  // Only reached by an allowlisted honeypot route from src/index.js.
  // These fixed outcome labels diagnose why a successful decoy GET
  // may not produce a new row, without reflecting any request attributes.
  if (args?.env?.TIDB_HONEYPOT_INGEST_ENABLED !== "true") {
    logSafeOutcome(args?.env, "disabled", "disabled");
    return false;
  }
  if (typeof args?.ctx?.waitUntil !== "function") {
    logSafeOutcome(args.env, "no_lifecycle", "missing_ctx");
    return false;
  }
  if (!validDatabaseUrl(args.env)) {
    logSafeOutcome(args.env, "not_configured", "bad_url");
    return false;
  }
  if (!shouldSample(args.env, random)) {
    logSafeOutcome(args.env, "sampled_out", "sampling");
    return false;
  }
  args.ctx.waitUntil(dispatchTidbHoneypotEvent(args));
  return true;
}
