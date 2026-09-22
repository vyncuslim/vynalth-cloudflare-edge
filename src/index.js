const ROOT_DOMAIN = "vynalthai.com";
const WWW_HOST = `www.${ROOT_DOMAIN}`;

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

export default {
  async fetch(request) {
    const incomingUrl = new URL(request.url);
    const hostname = incomingUrl.hostname.toLowerCase();

    // Only serve the production apex and subdomains below vynalthai.com.
    if (!isAllowedHostname(hostname)) {
      return new Response("Not Found", { status: 404 });
    }

    // Canonicalize www to the apex, but never interfere with certificate or
    // Vercel ownership validation paths.
    if (hostname === WWW_HOST && !isValidationPath(incomingUrl.pathname)) {
      const target = new URL(request.url);
      target.hostname = ROOT_DOMAIN;
      target.port = "";
      return Response.redirect(target.toString(), 301);
    }

    let originResponse;

    try {
      // Keep the original public hostname and Host header. Cloudflare DNS is
      // responsible for selecting the configured origin for each hostname.
      // Rewriting the URL to the *.vercel.app alias causes Vercel to issue a
      // canonical redirect back to vynalthai.com, which creates an apex loop.
      originResponse = await fetch(request, {
        redirect: "manual",
      });
    } catch (error) {
      console.error("Origin request failed", error);
      return new Response("Bad Gateway", {
        status: 502,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        },
      });
    }

    const responseHeaders = new Headers(originResponse.headers);

    // Useful for confirming the request traversed the Vynalth Cloudflare edge.
    responseHeaders.set("x-vynalth-edge", "cloudflare-worker");
    responseHeaders.set("x-vynalth-origin", "vercel");
    responseHeaders.set("x-vynalth-edge-host", incomingUrl.host);

    return new Response(originResponse.body, {
      status: originResponse.status,
      statusText: originResponse.statusText,
      headers: responseHeaders,
    });
  },
};
