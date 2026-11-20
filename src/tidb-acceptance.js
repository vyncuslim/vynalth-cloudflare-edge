/**
 * Private TiDB acceptance console. Routed on the managed apex only.
 * GET page is innocuous UI; ALL status and write endpoints require the
 * existing HMAC-signed IP administration session. POST is CSRF protected,
 * body-limited and bounded by existing KV; no public SQL execution.
 */
import {
  tidbAcceptanceSession,
  tidbAcceptanceLogin,
  tidbAcceptanceLogout,
} from "./tidb-acceptance-auth.js";
import {
  runTidbAcceptanceProbe,
  tidbAcceptanceConnectionStatus,
} from "./tidb-honeypot.js";
import { TIDB_ACCEPTANCE_HTML, TIDB_ACCEPTANCE_SCRIPT } from "./tidb-acceptance-html.js";

const ROOT = "/__ops/tidb-acceptance";
const API_STATUS = ROOT + "/api/status";
const API_RUN = ROOT + "/api/run";
const API_LOGIN = ROOT + "/api/login";
const API_LOGOUT = ROOT + "/api/logout";
const JS_ROUTE = ROOT + "/app.js";
const COOLDOWN_KEY = "ops:tidb-acceptance:cooldown:v1";
const COOLDOWN_SECONDS = 300;
let busy = false;

const commonHeaders = {
  "Cache-Control": "private, no-store, max-age=0",
  "X-Robots-Tag": "noindex,nofollow",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "X-Frame-Options": "DENY",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};
function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status, headers: {
      ...commonHeaders, "Content-Type": "application/json; charset=utf-8",
      ...headers,
    },
  });
}
function noAccess() {
  return json(401, { error: "ADMIN_SESSION_REQUIRED", login: "/admin/ip" });
}
function sameOriginPost(request, url, csrf) {
  if (!csrf || request.headers.get("X-CSRF-Token") !== csrf ||
      request.headers.get("Origin") !== url.origin) return false;
  const site = request.headers.get("Sec-Fetch-Site");
  return !site || site === "same-origin";
}
async function confirmation(request) {
  if (!request.headers.get("Content-Type")?.toLowerCase().startsWith("application/json") ||
      Number(request.headers.get("Content-Length") || 0) > 128) return false;
  try {
    const raw = await request.text();
    if (raw.length > 128) return false;
    const input = JSON.parse(raw);
    return input && !Array.isArray(input) && input.confirm === "RUN_SINGLE_PROBE" &&
      Object.keys(input).length === 1;
  } catch { return false; }
}
const allowedStates = new Set([
  "verified", "insert_acknowledged", "failed", "not_configured", "invalid_marker",
]);
const allowedReasons = new Set(["auth", "schema", "quota", "transport", "timeout", "other"]);
const allowedStages = new Set(["connect", "execute", "normalization", "unknown"]);
const allowedReadback = new Set(["confirmed", "not_found", "manual_required", "failed"]);
function safeProbeResult(result, marker) {
  const state = allowedStates.has(result?.state) ? result.state : "failed";
  const output = { state, marker };
  if (state === "failed") {
    output.reason = allowedReasons.has(result?.reason) ? result.reason : "other";
    output.stage = allowedStages.has(result?.stage) ? result.stage : "unknown";
  }
  if (state === "verified") output.readback = "confirmed";
  if (state === "insert_acknowledged") {
    output.readback = allowedReadback.has(result?.readback)
      ? result.readback : "manual_required";
    if (output.readback === "failed") {
      output.readbackReason = allowedReasons.has(result?.readbackReason)
        ? result.readbackReason : "other";
    }
  }
  return output;
}

export async function handleTidbAcceptance(
  request, env, url,
  { authenticate = tidbAcceptanceSession,
    login = tidbAcceptanceLogin,
    logout = tidbAcceptanceLogout,
    runProbe = runTidbAcceptanceProbe } = {}
) {
  if (url.hostname !== "vynalthai.com") return null;
  const path = url.pathname;
  if (path !== ROOT && path !== JS_ROUTE &&
      path !== API_STATUS && path !== API_RUN &&
      path !== API_LOGIN && path !== API_LOGOUT) return null;
  if (path === ROOT && request.method === "GET") {
    return new Response(TIDB_ACCEPTANCE_HTML, {
      status: 200, headers: {
        ...commonHeaders,
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy":
          "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; " +
          "connect-src 'self'; img-src 'none'; base-uri 'none'; form-action 'self'; " +
          "frame-ancestors 'none'",
      },
    });
  }
  if (path === JS_ROUTE && request.method === "GET")
    return new Response(TIDB_ACCEPTANCE_SCRIPT, {
      status: 200, headers: {
        ...commonHeaders, "Content-Type": "text/javascript; charset=utf-8",
      },
    });
  if (path === API_LOGIN) {
    if (request.method !== "POST")
      return json(405, { error: "METHOD_NOT_ALLOWED" }, { Allow: "POST" });
    return login(request, env, url);
  }
  if (path !== API_STATUS && path !== API_RUN && path !== API_LOGOUT)
    return json(405, { error: "METHOD_NOT_ALLOWED" }, { Allow: "GET" });
  if (path === API_STATUS && request.method !== "GET")
    return json(405, { error: "METHOD_NOT_ALLOWED" }, { Allow: "GET" });
  if ((path === API_RUN || path === API_LOGOUT) && request.method !== "POST")
    return json(405, { error: "METHOD_NOT_ALLOWED" }, { Allow: "POST" });

  let auth;
  try { auth = await authenticate(request, env); } catch { auth = null; }
  if (!auth) return noAccess();
  if (path === API_STATUS) {
    return json(200, {
      authenticated: true,
      csrf: auth.csrf,
      ...tidbAcceptanceConnectionStatus(env),
      cooldownSeconds: COOLDOWN_SECONDS,
      note: "READY and an INSERT acknowledgment are not SQL readback proof.",
    });
  }
  if (!sameOriginPost(request, url, auth.csrf))
    return json(403, { error: "CSRF_OR_ORIGIN_REJECTED" });
  if (path === API_LOGOUT) return logout(request, env);
  if (!await confirmation(request))
    return json(400, { error: "EXPLICIT_CONFIRMATION_REQUIRED" });
  if (busy) return json(429, { error: "PROBE_ALREADY_RUNNING" });

  const kv = env?.SCHOOL_IP_KV;
  if (!kv || typeof kv.get !== "function" || typeof kv.put !== "function")
    return json(503, { error: "RATE_LIMIT_STORE_UNAVAILABLE" });
  busy = true;
  try {
    // Best-effort global cooldown; Workers KV is eventually consistent.
    // In-isolate busy gate and signed admin session limit abuse further.
    if (await kv.get(COOLDOWN_KEY))
      return json(429, { error: "COOLDOWN_ACTIVE", retryAfterSeconds: COOLDOWN_SECONDS });
    await kv.put(COOLDOWN_KEY, "1", { expirationTtl: COOLDOWN_SECONDS });
    const marker = ROOT + "/" + crypto.randomUUID();
    const outcome = await runProbe(env, marker);
    return json(200, safeProbeResult(outcome, marker));
  } catch {
    // No raw SQL, driver exception, URL or secrets in the response/log.
    return json(503, { error: "PROBE_UNAVAILABLE" });
  } finally {
    busy = false;
  }
}
