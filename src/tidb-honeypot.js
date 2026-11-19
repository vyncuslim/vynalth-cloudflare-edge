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
  
// Schema v2 is explicitly gated. It must not run until the operator executes
// docs/sql/honeypot-events-v2.sql against the existing TiDB Starter instance.
const ENRICHED_INSERT_SQL = `INSERT INTO vynalth_honeypot.honeypot_events
  (event_type, source, protocol, source_ip_hash, country_code, request_path, action_taken,
   event_id, target_host, http_method, http_status, trap_kind, network_asn,
   edge_colo, bot_score, verified_bot, ip_attribution, bot_claim, sample_rate)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

function validatedExtraFields(args, event) {
  const cf = args.request?.cf;
  const verifiedNetwork = event.ip_attestation_status === "cloudflare_edge_observed";
  const asn = verifiedNetwork && Number.isInteger(cf?.asn) &&
    cf.asn >= 1 && cf.asn <= 4294967295 ? cf.asn : null;
  const colo = typeof cf?.colo === "string" && /^[A-Z]{3}$/.test(cf.colo)
    ? cf.colo : null;
  const botScore = verifiedNetwork && Number.isInteger(cf?.botManagement?.score) &&
    cf.botManagement.score >= 1 && cf.botManagement.score <= 99
    ? cf.botManagement.score : null;
  const verifiedBot = verifiedNetwork && typeof event.bot_verified === "boolean"
    ? event.bot_verified : null;
  const eventId = typeof event.request_id === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(event.request_id)
    ? event.request_id : null;
  const sampleRate = Number(args.env?.TIDB_HONEYPOT_SAMPLE_RATE ?? "0.1");
  return [
    eventId,
    event.host,
    event.http_method,
    event.status_code,
    event.trap,
    asn,
    colo,
    botScore,
    verifiedBot,
    event.ip_attestation_status,
    event.bot_claim,
    Number.isFinite(sampleRate) && sampleRate > 0 && sampleRate <= 1
      ? sampleRate : 0.1,
  ];
}

function failureCategory(error) {
  // Match locally but never log message, error stack, connection URL, SQL or parameters.
  const message = typeof error?.message === "string" ? error.message : "";
  if (/unknown column|schema|42S22/i.test(message)) return "schema_mismatch";
  if (/access denied|permission|privilege|403/i.test(message)) return "permission";
  if (/unauthorized|authentication|password|401/i.test(message)) return "authentication";
  if (/429|quota|rate.limit|throttl/i.test(message)) return "rate_limited";
  if (/timeout|timed out|abort/i.test(message)) return "timeout";
  if (/network|fetch failed|ECONN|ENOTFOUND/i.test(message)) return "transport";
  return "unknown";
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
  if (!url) return { state: "not_configured" };
  try {
    const observation = await buildAxiomSecurityEvent(args);
    if (!observation || observation.source !== "cloudflare_worker")
      return { state: "invalid_event" };
    // Only known static decoys / explicit WordPress installer blocks.
    if (args.kind !== "wp_installer_block" &&
        !["php", "phpinfo", "diagnostics", "login", "database", "config",
          "files", "backup"].includes(args.kind))
      return { state: "invalid_event" };
    const baseValues = [
      "suspicious_probe",
      "cloudflare_worker",
      "HTTP",
      observation.network_actor_id,
      observation.country,
      observation.path,
      observation.action === "block" ? "blocked" : "logged",
    ];
    const enriched = args.env?.TIDB_HONEYPOT_ENRICHED_ENABLED === "true";
    const values = enriched ? [...baseValues, ...validatedExtraFields(args, observation)]
      : baseValues;
    const connection = connectImpl({ url });
    await connection.execute(enriched ? ENRICHED_INSERT_SQL : INSERT_SQL, values);
    // Logs contain only a fixed event class, no identifiable request attributes.
    return { state: "inserted", schema: enriched ? "v2" : "v1" };
  } catch (error) {
    console.warn("[TIDB HONEYPOT] insert failed", failureCategory(error));
    return { state: "failed" };
  }
}

export function scheduleTidbHoneypotEvent(args, random = Math.random) {
  if (args?.env?.TIDB_HONEYPOT_INGEST_ENABLED !== "true" ||
      typeof args?.ctx?.waitUntil !== "function" ||
      !validDatabaseUrl(args.env) || !shouldSample(args.env, random))
    return false;
  args.ctx.waitUntil(dispatchTidbHoneypotEvent(args));
  return true;
}
