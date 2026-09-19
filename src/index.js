const ORIGIN_HOST = "somno-ai-digital-sleep-lab.vercel.app";

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
  async fetch(request) {
    const incomingUrl = new URL(request.url);

    // This Worker is only intended to front the production apex domain.
    if (incomingUrl.hostname !== "vynalthai.com") {
      return new Response("Not Found", { status: 404 });
    }

    const originUrl = new URL(request.url);
    originUrl.protocol = "https:";
    originUrl.hostname = ORIGIN_HOST;
    originUrl.port = "";

    const headers = new Headers(request.headers);

    // Preserve the public hostname for application-side logging/routing without
    // forcing the HTTP Host header back to vynalthai.com (which would recurse).
    headers.set("x-forwarded-host", incomingUrl.host);
    headers.set("x-vynalth-edge-host", incomingUrl.host);
    headers.delete("host");

    const originRequest = new Request(originUrl.toString(), {
      method: request.method,
      headers,
      body: request.body,
      redirect: "manual",
    });

    let originResponse;

    try {
      originResponse = await fetch(originRequest, {
        redirect: "manual",
      });
    } catch (error) {
      console.error("Vercel origin request failed", error);
      return new Response("Bad Gateway", {
        status: 502,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
        },
      });
    }

    const responseHeaders = new Headers(originResponse.headers);
    const rewrittenLocation = rewriteRedirect(
      responseHeaders.get("location"),
      incomingUrl,
    );

    if (rewrittenLocation) {
      responseHeaders.set("location", rewrittenLocation);
    }

    // Useful for confirming that traffic reached the Cloudflare Worker.
    responseHeaders.set("x-vynalth-edge", "cloudflare-worker");
    responseHeaders.set("x-vynalth-origin", "vercel");

    return new Response(originResponse.body, {
      status: originResponse.status,
      statusText: originResponse.statusText,
      headers: responseHeaders,
    });
  },
};
