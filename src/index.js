const ROOT_DOMAIN = "vynalthai.com";
const WWW_HOST = `www.${ROOT_DOMAIN}`;

const VERCEL_HOSTS = new Set([
  ROOT_DOMAIN,
  WWW_HOST,
  `partner.${ROOT_DOMAIN}`,
  `status.${ROOT_DOMAIN}`,
  `trust.${ROOT_DOMAIN}`,
  `cf-test.${ROOT_DOMAIN}`,
]);

function isAllowedHostname(hostname) {
  const normalized = hostname.toLowerCase();
  return normalized === ROOT_DOMAIN || normalized.endsWith(`.${ROOT_DOMAIN}`);
}

function isValidationPath(pathname) {
  return (
    pathname.startsWith("/.well-known/acme-challenge/") ||
    pathname.startsWith("/.well-known/vercel/")
  );
}

function buildEdgeHeaders(existingHeaders, request, incomingUrl, requestId) {
  const headers = new Headers(existingHeaders);
  const hostname = incomingUrl.hostname.toLowerCase();
  const cfRay = request.headers.get("cf-ray");

  headers.set("x-vynalth-edge", "cloudflare-worker");
  headers.set("x-vynalth-edge-host", incomingUrl.host);
  headers.set("x-vynalth-request-id", requestId);

  if (cfRay) {
    headers.set("x-vynalth-ray-id", cfRay.split("-")[0]);
  }

  headers.set(
    "x-vynalth-origin",
    VERCEL_HOSTS.has(hostname) ? "vercel" : "dns-origin",
  );

  return headers;
}

function edgeResponse(response, request, incomingUrl, requestId) {
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: buildEdgeHeaders(
      response.headers,
      request,
      incomingUrl,
      requestId,
    ),
  });
}

export default {
  async fetch(request) {
    const incomingUrl = new URL(request.url);
    const hostname = incomingUrl.hostname.toLowerCase();
    const requestId = crypto.randomUUID();

    if (!isAllowedHostname(hostname)) {
      return edgeResponse(
        new Response("Not Found", { status: 404 }),
        request,
        incomingUrl,
        requestId,
      );
    }

    // Canonicalize www to the apex, but never interfere with certificate or
    // Vercel ownership validation paths.
    if (hostname === WWW_HOST && !isValidationPath(incomingUrl.pathname)) {
      const target = new URL(request.url);
      target.hostname = ROOT_DOMAIN;
      target.port = "";

      return edgeResponse(
        new Response(null, {
          status: 301,
          headers: { location: target.toString() },
        }),
        request,
        incomingUrl,
        requestId,
      );
    }

    let originResponse;

    try {
      // Keep the original public hostname and Host header. Cloudflare DNS is
      // responsible for selecting the configured origin for each hostname.
      originResponse = await fetch(request, {
        redirect: "manual",
      });
    } catch (error) {
      console.error("Origin request failed", error);

      return edgeResponse(
        new Response("Bad Gateway", {
          status: 502,
          headers: {
            "content-type": "text/plain; charset=utf-8",
            "cache-control": "no-store",
          },
        }),
        request,
        incomingUrl,
        requestId,
      );
    }

    return edgeResponse(
      originResponse,
      request,
      incomingUrl,
      requestId,
    );
  },
};
