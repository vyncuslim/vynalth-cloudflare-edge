import { isObservedSecurityProbe } from "./threat-telemetry.js";

/**
 * Nonblocking, privacy-minimized Cloudflare edge alerts for all hosts that
 * actually pass through this Worker. The Bot token never enters the browser.
 *
 * Every 4xx/5xx response (including expected denials) is reported per request.\n * This is intentionally noisy; do not mislabel ordinary 4xx as outages.
 * Specific GPS denials have their own independent notification pipeline.
 * This is not Cloudflare WAF analytics, a client-side error collector, or
 * proof of a successful Telegram delivery until Telegram acknowledges it.
 */
const TOKEN_RE = /^[0-9]{5,20}:[A-Za-z0-9_-]{25,}$/;
const CHAT_RE = /^(?:-?[0-9]{3,24}|@[A-Za-z0-9_]{5,32})$/;
const ALLOWED_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
// Each HTTP failure is an independent event. Do not suppress other failures just\n// because their path family/status matches a previous failure.

export function edgeTelegramStatus(env) {
  const enabled = env?.EDGE_TELEGRAM_ALERTS_ENABLED === "true";
  const token = env?.EDGE_TELEGRAM_BOT_TOKEN || env?.TELEGRAM_BOT_TOKEN;
  const chat = env?.EDGE_TELEGRAM_CHAT_ID || env?.TELEGRAM_CHAT_ID || env?.ADMIN_TELEGRAM_CHAT_ID;
  const configured = TOKEN_RE.test(String(token || "")) &&
    CHAT_RE.test(String(chat || "")) &&
    true;
  return { enabled, configured };
}

function hostLabel(host) {
  return /^[a-z0-9.-]{1,160}$/.test(host) ? host : "unavailable";
}

function routeFamily(path) {
  if (/^\/api\/ai\//.test(path)) return "/api/ai/*";
  if (/^\/api\/auth\//.test(path)) return "/api/auth/*";
  if (/^\/api\/security\//.test(path)) return "/api/security/*";
  if (/^\/api\//.test(path)) return "/api/*";
  if (/^\/__shield\/gps\//.test(path)) return "/__shield/gps/*";
  if (/^\/__vynalth\//.test(path)) return "/__vynalth/*";
  if (/^\/assets\//.test(path)) return "/assets/*";
  return "/web/*";
}

function issueFor(request, response) {
  if (!ALLOWED_METHODS.has(request.method)) return null;
  const status = response.status;
  if (status >= 500 && status <= 599) {
    return { code: "HTTP_5XX", severity: status >= 502 ? "Critical" : "High",
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
  return null;
}

export function classifyEdgeAlert(request, response) {
  if (!request || !response) return null;
  return issueFor(request, response);
}

function safeRef(id) {
  return /^[a-zA-Z0-9_-]{8,64}$/.test(String(id || "")) ? id : "unavailable";
}

async function dispatch({ env, request, url, response, requestId, fetchImpl }) {
  const issue = issueFor(request, response);
  if (!issue) return { state: "ignored" };

  const kv = env.CONSENT_KV;
  const host = hostLabel(url.hostname.toLowerCase());
  const family = routeFamily(url.pathname);

  try {
    const token = env.EDGE_TELEGRAM_BOT_TOKEN || env.TELEGRAM_BOT_TOKEN;
    const chat = env.EDGE_TELEGRAM_CHAT_ID || env.TELEGRAM_CHAT_ID || env.ADMIN_TELEGRAM_CHAT_ID;
    const message = [
      issue.severity === "Critical" ? "🚨 Vynalth AI — Sitewide alert" : "⚠️ Vynalth AI — Sitewide alert",
      "Event: " + issue.code,
      "Severity: " + issue.severity,
      "Host: " + host,
      "Route family: " + family,
      "HTTP status: " + issue.status,
      "Method: " + request.method,
      "Event ID: " + safeRef(requestId),
      "Time (UTC): " + new Date().toISOString(),
      "Evidence: " + issue.description,\n      "Delivery: Telegram Bot API acknowledged this individual event (if received).",
      "Source: Cloudflare edge Worker",
      "Privacy: no IP, GPS, user identifier, query, Cookie, request body or secret."
    ].join("\n");

    const ack = await fetchImpl("https://api.telegram.org/bot" + token + "/sendMessage", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: chat, text: message, disable_web_page_preview: true }),
      signal: AbortSignal.timeout(4500)
    });
    if (!ack.ok) {
      console.warn("[EDGE TELEGRAM] Telegram rejected alert; HTTP", ack.status);
      return { state: "rejected" };
    }
    const body = await ack.json().catch(() => null);
    if (body?.ok !== true) {
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
  env, ctx, request, url, response, requestId, fetchImpl = fetch
}) {
  const config = edgeTelegramStatus(env);
  if (!config.enabled) return false;
  if (!config.configured) {
    console.warn("[EDGE TELEGRAM] enabled but Bot/Chat/KV binding is incomplete");
    return false;
  }
  if (!ctx || typeof ctx.waitUntil !== "function" ||
      !issueFor(request, response)) return false;
  ctx.waitUntil(dispatch({ env, request, url, response, requestId, fetchImpl }));
  return true;
}
