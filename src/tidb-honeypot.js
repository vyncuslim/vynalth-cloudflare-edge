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
    return { state: "inserted" };
  } catch {
    // Never echo connection strings, SQL parameters, or sensitive request data.
    console.warn("[TIDB HONEYPOT] insert failed");
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
