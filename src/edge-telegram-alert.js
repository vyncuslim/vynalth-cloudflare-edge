import { isObservedSecurityProbe } from "./threat-telemetry.js";
import { formatEdgeSecurityAlert } from "./edge-alert-details.js";

/**
 * Nonblocking Cloudflare edge security notifications. Normal 2xx/3xx and
 * routine 4xx are not Telegram incidents; those remain in access/security logs.
 * Only known sensitive-path probes, observed 5xx and HTTP 429 are notified.
 * A per-isolate best-effort cooldown prevents alert storms without extra
 * databases, Durable Objects or paid broadcasting. Other Workers may have
 * their own isolates: this is NOT a globally guaranteed Telegram queue.
 * Specific GPS denials have their own independent notification pipeline.
 */
const TOKEN_RE = /^[0-9]{5,20}:[A-Za-z0-9_-]{25,}$/;
const CHAT_RE = /^(?:-?[0-9]{3,24}|@[A-Za-z0-9_]{5,32})$/;
// A single Cloudflare isolate may handle many requests at once. Bound outbound
// Telegram attempts even when attackers send floods of suspicious-path GETs.
export function createEdgeTelegramLimiter({ spacingMs = 6000 } = {}) {
  const gap = Number.isFinite(spacingMs) && spacingMs >= 0 ? spacingMs : 6000;
  let nextAllowedAt = 0;
  let inFlight = false;
  return {
    acquire(now = Date.now()) {
      if (inFlight || now < nextAllowedAt) return false;
      inFlight = true;
      nextAllowedAt = now + gap;
      return true;
    },
    complete(result, now = Date.now()) {
      inFlight = false;
      if (result?.state === "rate_limited") {
        const seconds = Number.isInteger(result.retryAfterSeconds)
          ? Math.min(3600, Math.max(1, result.retryAfterSeconds)) : 60;
        nextAllowedAt = Math.max(nextAllowedAt, now + seconds * 1000);
      } else if (result?.state === "failed" || result?.state === "rejected" ||
                 result?.state === "unconfirmed") {
        // Failed fetches and non-429 API errors must not be retried per request.
        nextAllowedAt = Math.max(nextAllowedAt, now + 60 * 1000);
      }
    }
  };
}
const defaultTelegramLimiter = createEdgeTelegramLimiter();

export function edgeTelegramStatus(env) {
  const enabled = env?.EDGE_TELEGRAM_ALERTS_ENABLED === "true";
  const token = env?.EDGE_TELEGRAM_BOT_TOKEN || env?.TELEGRAM_BOT_TOKEN;
  const chat = env?.EDGE_TELEGRAM_CHAT_ID || env?.TELEGRAM_CHAT_ID || env?.ADMIN_TELEGRAM_CHAT_ID;
  const configured = TOKEN_RE.test(String(token || "")) &&
    CHAT_RE.test(String(chat || ""));
  return { enabled, configured };
}

function issueFor(request, response, env=null) {
  const status = response.status;
  if (status >= 500 && status <= 599) {
    return { code: "HTTP_5XX", severity: "High",
      status, description: "Server/edge error observed" };
  }
  if (isObservedSecurityProbe(request)) {
    return { code: "SUSPICIOUS_PROBE", severity: "Warning", status,
      description: "Known sensitive-path probe observed; intrusion UNVERIFIED" };
  }
  if (status >= 400 && status <= 499) {
    return { code: "HTTP_4XX", severity: status === 429 ? "High" : "Warning",
      status, description: "Client/request error or access denial observed; may be expected, not a verified incident" };
  }
  if(env?.EDGE_TELEGRAM_NOTIFY_ALL_REQUESTS==="true" && status>=200 && status<400){
    let expectedRedirect=false;
    if(status===301){
      try{
        const from=new URL(request.url);
        const to=new URL(response.headers.get("Location")||"",from);
        expectedRedirect=from.hostname==="www.vynalthai.com" &&
          to.hostname==="vynalthai.com" && to.pathname===from.pathname;
      }catch{ /* malformed Location is not a verified canonical redirect */ }
    }
    return {code:"HTTP_REQUEST",severity:"Info",status,
      description:expectedRedirect?
        "Expected www-to-apex canonical redirect; no intrusion evidence":
        "A request completed at the Cloudflare edge Worker"};
  }
  return null;
}

export function classifyEdgeAlert(request, response, env=null) {
  if (!request || !response) return null;
  return issueFor(request, response, env);
}

async function dispatch({ env, request, url, response, requestId, responseTimeMs, fetchImpl }) {
  const issue = issueFor(request, response, env);
  if (!issue) return { state: "ignored" };

  try {
    const token = env.EDGE_TELEGRAM_BOT_TOKEN || env.TELEGRAM_BOT_TOKEN;
    const chat = env.EDGE_TELEGRAM_CHAT_ID || env.TELEGRAM_CHAT_ID || env.ADMIN_TELEGRAM_CHAT_ID;
    const message=formatEdgeSecurityAlert({
      request,url,response,issue,requestId,responseTimeMs
    });

    const ack = await fetchImpl("https://api.telegram.org/bot" + token + "/sendMessage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chat, text: message, disable_web_page_preview: true }),
      signal: AbortSignal.timeout(4500)
    });
    if (ack.status === 429) {
      // Official Bot API retry_after is advisory; never log raw response.
      const denied = await ack.json().catch(() => null);
      const retryAfterSeconds = denied?.parameters?.retry_after;
      console.warn("[EDGE TELEGRAM] rate-limited; suppressing more alerts");
      return { state: "rate_limited", retryAfterSeconds };
    }
    if (!ack.ok) {
      console.warn("[EDGE TELEGRAM] Telegram rejected alert; HTTP", ack.status);
      return { state: "rejected" };
    }
    const body = await ack.json().catch(() => null);
    if (body?.ok !== true || !Number.isInteger(body?.result?.message_id)) {
      console.warn("[EDGE TELEGRAM] Telegram acknowledgment missing");
      return { state: "unconfirmed" };
    }
    return { state: "sent" };
  } catch {
    // Do not log fetch URLs, request bodies or error objects containing secrets.
    console.warn("[EDGE TELEGRAM] delivery failed; retry on next event");
    return { state: "failed" };
  }
}

export function scheduleEdgeTelegramAlert({
  env, ctx, request, url, response, requestId, responseTimeMs, fetchImpl = fetch,
  limiter = defaultTelegramLimiter, now = Date.now
}) {
  const config = edgeTelegramStatus(env);
  if (!config.enabled) return false;
  if (!config.configured) {
    console.warn("[EDGE TELEGRAM] enabled but Bot/Chat credentials are incomplete");
    return false;
  }
  if (!ctx || typeof ctx.waitUntil !== "function") return false;
  const issue = issueFor(request, response, env);
  if (!issue) return false;
  // Routine 4xx are not emergencies. Suspicious probes are separately tagged.
  if (issue.code === "HTTP_4XX" && issue.status !== 429) return false;
  if (!limiter.acquire(now())) return false;
  try {
    ctx.waitUntil(Promise.resolve().then(() =>
      dispatch({ env, request, url, response, requestId, responseTimeMs, fetchImpl })
    ).then(result => {
      limiter.complete(result, now());
      return result;
    }, () => {
      limiter.complete({ state: "failed" }, now());
      return { state: "failed" };
    }));
    return true;
  } catch {
    limiter.complete({ state: "failed" }, now());
    return false;
  }
}
