const ORIGINS = Object.freeze({
  "vynalthai.com": "somno-ai-digital-sleep-lab.vercel.app",
  "www.vynalthai.com": "somno-ai-digital-sleep-lab.vercel.app",
  "trust.vynalthai.com": "somno-ai-digital-sleep-lab.vercel.app",
  "status.vynalthai.com": "somno-ai-digital-sleep-lab.vercel.app",
  "partner.vynalthai.com": "somno-ai-digital-sleep-lab.vercel.app",
  "cf-test.vynalthai.com": "somno-ai-digital-sleep-lab.vercel.app",
  "vynova.vynalthai.com": "social-puce-nine.vercel.app",
  "shield.vynalthai.com": "vita-shield.vercel.app",
  "navigator.vynalthai.com": "vynalth-ai-navigator.vercel.app",
  "pedia.vynalthai.com": "pedia-peach.vercel.app",
  "search.vynalthai.com": "vynalth-ai-search.vercel.app",
  "sleepsomno.com": "somno-ai-digital-sleep-lab.vercel.app",
  "www.sleepsomno.com": "somno-ai-digital-sleep-lab.vercel.app",
  "trust.sleepsomno.com": "somno-ai-digital-sleep-lab.vercel.app",
  "status.sleepsomno.com": "somno-ai-digital-sleep-lab.vercel.app",
  "shield.sleepsomno.com": "vita-shield.vercel.app",
  "vitamindai.online": "somno-ai-digital-sleep-lab.vercel.app",
  "vyncuslim.com": "vv-seven-tau.vercel.app",
  "www.vyncuslim.com": "vv-seven-tau.vercel.app",
  "powiismunc.com": "powiis-mun-2027.vercel.app",
  "www.powiismunc.com": "powiis-mun-2027.vercel.app",
});

const REQUEST_ID_HEADER = "x-vynalth-request-id";
const RAY_ID_HEADER = "x-vynalth-ray-id";
const REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

function getOriginHost(hostname) {
  return ORIGINS[hostname.toLowerCase()] ?? null;
}

function getRequestId(request) {
  const supplied = request.headers.get(REQUEST_ID_HEADER);
  return supplied && REQUEST_ID_PATTERN.test(supplied) ? supplied : crypto.randomUUID();
}

function shouldNotifyTelegram(pathname) {
  // Internal log-centre reads and refreshes are auditable, but never alert-worthy.
  return pathname !== "/api/admin/logs";
}

function getSampleRate(env) {
  const configured = Number(env.LOG_SAMPLE_RATE ?? "1");
  return Number.isFinite(configured) ? Math.max(0, Math.min(1, configured)) : 1;
}

function truncate(value, maximumLength) {
  if (!value) return null;
  return value.length > maximumLength ? value.slice(0, maximumLength) : value;
}

function getRefererOrigin(value) {
  if (!value) return null;
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

async function hashIp(clientIp, salt) {
  if (!clientIp || !salt) return null;
  const data = new TextEncoder().encode(`${salt}:${clientIp}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function ingestEdgeLog(event, env) {
  if (!env.AXIOM_TOKEN || !env.AXIOM_DATASET) return;

  const result = await fetch(
    `https://api.axiom.co/v1/datasets/${encodeURIComponent(env.AXIOM_DATASET)}/ingest`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.AXIOM_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify([event]),
    },
  );

  if (!result.ok) console.error("Axiom edge log ingestion failed", result.status);
}

async function sendTelegramRequestNotice(event, env) {
  if (!env.TELEGRAM_BOT_TOKEN || !env.TELEGRAM_CHAT_ID) return;

  const message = [
    "📡 Vynalth Edge Request",
    `Site: ${event.site}`,
    `Host: ${event.host}`,
    `Path: ${event.path}`,
    `Method: ${event.method}`,
    `Status: ${event.status}`,
    `Country: ${event.country ?? "unknown"}`,
    `ASN: ${event.asn ?? "unknown"}`,
    `Request ID: ${event.request_id}`,
    `Ray ID: ${event.ray_id ?? "unavailable"}`,
  ].join("\n");

  const response = await fetch(
    `https://api.telegram.org/bot${env.TELEGRAM_BOT_TOKEN}/sendMessage`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        chat_id: env.TELEGRAM_CHAT_ID,
        text: message,
        disable_web_page_preview: true,
      }),
    },
  );

  if (!response.ok) console.error("Telegram edge notification failed", response.status);
}

function rewriteRedirect(location, incomingUrl, originHost) {
  if (!location) return null;

  try {
    const redirectUrl = new URL(location, `https://${originHost}`);

    if (redirectUrl.hostname === originHost) {
      redirectUrl.protocol = incomingUrl.protocol;
      redirectUrl.hostname = incomingUrl.hostname;
      redirectUrl.port = "";
      return redirectUrl.toString();
    }
  } catch {
    // Keep the original Location header if it cannot be parsed.
  }

  return location;
}

export default {
  async fetch(request, env, ctx) {
    const startedAt = Date.now();
    const incomingUrl = new URL(request.url);

    // Cloudflare-owned endpoints must bypass the proxy and are logged by Cloudflare.
    if (incomingUrl.pathname.startsWith("/cdn-cgi/")) return fetch(request);

    const originHost = getOriginHost(incomingUrl.hostname);
    if (!originHost) return new Response("Not Found", { status: 404 });

    const requestId = getRequestId(request);
    const rayId = request.headers.get("cf-ray");
    const originUrl = new URL(request.url);
    originUrl.protocol = "https:";
    originUrl.hostname = originHost;
    originUrl.port = "";

    const headers = new Headers(request.headers);
    headers.set("x-forwarded-host", incomingUrl.host);
    headers.set("x-vynalth-edge-host", incomingUrl.host);
    headers.set(REQUEST_ID_HEADER, requestId);
    if (rayId) headers.set(RAY_ID_HEADER, rayId);
    headers.delete("host");

    const originRequest = new Request(originUrl.toString(), {
      method: request.method,
      headers,
      body: request.body,
      redirect: "manual",
    });

    let originResponse;
    let status = 502;

    try {
      originResponse = await fetch(originRequest, { redirect: "manual" });
      status = originResponse.status;
    } catch (error) {
      console.error("Vercel origin request failed", error);
      originResponse = null;
    }

    const clientIp = request.headers.get("cf-connecting-ip");
    const edgeEvent = {
      timestamp: new Date().toISOString(),
      source: "cloudflare-edge",
      site: incomingUrl.hostname.split(".").slice(-2).join("."),
      request_id: requestId,
      ray_id: rayId,
      host: incomingUrl.hostname,
      path: incomingUrl.pathname,
      method: request.method,
      status,
      duration_ms: Date.now() - startedAt,
      country: request.cf?.country ?? null,
      region: request.cf?.region ?? null,
      city: request.cf?.city ?? null,
      colo: request.cf?.colo ?? null,
      asn: request.cf?.asn ?? null,
      as_organization: request.cf?.asOrganization ?? null,
      ip_hash: await hashIp(clientIp, env.IP_HASH_SALT),
      user_agent: truncate(request.headers.get("user-agent"), 512),
      referer_origin: getRefererOrigin(request.headers.get("referer")),
      cache_status: originResponse?.headers.get("cf-cache-status") ?? null,
      content_type: truncate(originResponse?.headers.get("content-type") ?? null, 128),
    };

    // Axiom and Telegram are non-blocking: a destination outage never blocks visitors.
    ctx.waitUntil(
      Promise.allSettled([
        Math.random() < getSampleRate(env) ? ingestEdgeLog(edgeEvent, env) : Promise.resolve(),
        shouldNotifyTelegram(incomingUrl.pathname)
          ? sendTelegramRequestNotice(edgeEvent, env)
          : Promise.resolve(),
      ]),
    );

    if (!originResponse) {
      return new Response("Bad Gateway", {
        status: 502,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          [REQUEST_ID_HEADER]: requestId,
          ...(rayId ? { [RAY_ID_HEADER]: rayId } : {}),
          "x-vynalth-edge": "cloudflare-worker",
        },
      });
    }

    const responseHeaders = new Headers(originResponse.headers);
    const rewrittenLocation = rewriteRedirect(
      responseHeaders.get("location"),
      incomingUrl,
      originHost,
    );

    if (rewrittenLocation) responseHeaders.set("location", rewrittenLocation);
    responseHeaders.set(REQUEST_ID_HEADER, requestId);
    if (rayId) responseHeaders.set(RAY_ID_HEADER, rayId);
    responseHeaders.set("x-vynalth-edge", "cloudflare-worker");
    responseHeaders.set("x-vynalth-origin", "vercel");

    return new Response(originResponse.body, {
      status: originResponse.status,
      statusText: originResponse.statusText,
      headers: responseHeaders,
    });
  },
};
