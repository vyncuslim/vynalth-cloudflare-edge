const ROOT_DOMAIN = "vynalthai.com";
const ORIGIN_HOST = "somno-ai-digital-sleep-lab.vercel.app";
const REQUEST_ID_HEADER = "x-vynalth-request-id";
const RAY_ID_HEADER = "x-vynalth-ray-id";
const REQUEST_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

function isAllowedHostname(hostname) {
  const normalized = hostname.toLowerCase();
  return normalized === ROOT_DOMAIN || normalized.endsWith(`.${ROOT_DOMAIN}`);
}

function getRequestId(request) {
  const supplied = request.headers.get(REQUEST_ID_HEADER);
  return supplied && REQUEST_ID_PATTERN.test(supplied) ? supplied : crypto.randomUUID();
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

  if (!result.ok) {
    console.error("Axiom edge log ingestion failed", result.status);
  }
}

function rewriteRedirect(location, incomingUrl) {
  if (!location) return null;

  try {
    const redirectUrl = new URL(location, `https://${ORIGIN_HOST}`);

    if (redirectUrl.hostname === ORIGIN_HOST) {
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

    // Cloudflare-owned endpoints must bypass the proxy and must not be logged here.
    if (incomingUrl.pathname.startsWith("/cdn-cgi/")) return fetch(request);

    // Accept the production apex and any subdomain below vynalthai.com.
    if (!isAllowedHostname(incomingUrl.hostname)) {
      return new Response("Not Found", { status: 404 });
    }

    const requestId = getRequestId(request);
    const rayId = request.headers.get("cf-ray");
    const originUrl = new URL(request.url);
    originUrl.protocol = "https:";
    originUrl.hostname = ORIGIN_HOST;
    originUrl.port = "";

    const headers = new Headers(request.headers);

    // Preserve the public hostname for application-side logging/routing without
    // forcing the HTTP Host header back to vynalthai.com (which would recurse).
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

    // The log is deliberately non-blocking. It contains no body, cookies,
    // authorization headers, query string, full referer or raw IP address.
    if (Math.random() < getSampleRate(env)) {
      const clientIp = request.headers.get("cf-connecting-ip");
      ctx.waitUntil(
        (async () => {
          await ingestEdgeLog(
            {
              timestamp: new Date().toISOString(),
              source: "cloudflare-edge",
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
            },
            env,
          );
        })(),
      );
    }

    if (!originResponse) {
      return new Response("Bad Gateway", {
        status: 502,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          [REQUEST_ID_HEADER]: requestId,
          ...(rayId ? { [RAY_ID_HEADER]: rayId } : {}),
        },
      });
    }

    const responseHeaders = new Headers(originResponse.headers);
    const rewrittenLocation = rewriteRedirect(responseHeaders.get("location"), incomingUrl);

    if (rewrittenLocation) responseHeaders.set("location", rewrittenLocation);

    // Browser, backend, Axiom and Telegram can all use these IDs for one trace.
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
