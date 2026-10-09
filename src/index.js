import { handleSchoolVolunteer } from "./school-volunteer.js";

import { handleCampusBeacon } from "./school-beacon.js";
const ROOT_DOMAINS = [
  "vynalthai.com",
  "vyncuslim.com",
  "sleepsomno.com",
  "powiismunc.com",
  "vitamindai.online",
  "vynalthai.si",
  "vyncuslim.si",
];

const VYNALTH_APEX = "vynalthai.com";
const VYNALTH_WWW = `www.${VYNALTH_APEX}`;

function getRootDomain(hostname) {
  const normalized = hostname.toLowerCase();

  for (const root of ROOT_DOMAINS) {
    if (normalized === root || normalized.endsWith(`.${root}`)) {
      return root;
    }
  }

  return null;
}

function isValidationPath(pathname) {
  return (
    pathname.startsWith("/.well-known/acme-challenge/") ||
    pathname.startsWith("/.well-known/vercel/")
  );
}

function detectOrigin(headers) {
  if (headers.has("x-vercel-id")) return "vercel";
  if (headers.has("x-served-by") && headers.get("x-served-by")?.toLowerCase().includes("fastly")) {
    return "fastly";
  }
  return "dns-origin";
}

function buildEdgeHeaders(existingHeaders, request, incomingUrl, requestId, rootDomain) {
  const headers = new Headers(existingHeaders);
  const cfRay = request.headers.get("cf-ray");

  headers.set("x-vynalth-edge", "cloudflare-worker");
  headers.set("x-vynalth-edge-host", incomingUrl.host);
  headers.set("x-vynalth-zone", rootDomain);
  headers.set("x-vynalth-request-id", requestId);
  headers.set("x-vynalth-origin", detectOrigin(existingHeaders));

  if (cfRay) {
    headers.set("x-vynalth-ray-id", cfRay.split("-")[0]);
  }

  return headers;
}

function edgeResponse(response, request, incomingUrl, requestId, rootDomain) {
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: buildEdgeHeaders(
      response.headers,
      request,
      incomingUrl,
      requestId,
      rootDomain,
    ),
  });
}


// Only activate after operator verification and an explicit config change.
// Health handshake ensures stale policy Worker cannot loop back into edge.
async function checkSchoolPolicy(request, env) {
  if (env?.SCHOOL_POLICY_ENABLED !== "true") return null;
  if (!env?.SCHOOL_POLICY || typeof env.SCHOOL_POLICY.fetch !== "function") return null;
  const clientIp = request.headers.get("CF-Connecting-IP");
  if (!clientIp) return null;
  try {
    const health = await env.SCHOOL_POLICY.fetch(
      new Request("https://website-block-by-school-powiis.ongyuze1401.workers.dev/health")
    );
    if (health.status !== 200) return null;
    const protocol = await health.json();
    if (protocol?.policyProtocol !== "internal-204-v1" ||
        protocol?.kvBound !== true) {
      console.warn("School policy incompatible; failing open");
      return null;
    }
    const uri = new URL(request.url);
    uri.search = "";
    uri.hash = "";
    const decision = await env.SCHOOL_POLICY.fetch(new Request(uri.toString(), {
      method: request.method,
      headers: { "X-Vynalth-Policy-Client-IP": clientIp }
    }));
    if (decision.status === 403 &&
        decision.headers.get("X-School-Policy") === "blocked") return decision;
    if (decision.status !== 204) console.warn("Unexpected school policy status", decision.status);
  } catch (error) {
    console.warn("School policy unavailable; failing open", String(error));
  }
  return null;
}

export default {
  async fetch(request, env, ctx) {
    const incomingUrl = new URL(request.url);
    // Narrow authenticated enrollment endpoint. The WAF exception is only
    // for this exact path on vynalthai.com; all other URLs remain protected.
    if (incomingUrl.hostname === "vynalthai.com" &&
        incomingUrl.pathname === "/__shield/campus-beacon") {
      return handleCampusBeacon(request, env);
    }
    const hostname = incomingUrl.hostname.toLowerCase();
    const rootDomain = getRootDomain(hostname);
    const requestId = crypto.randomUUID();

    // Standalone consent-based campus egress observation; only on main Vynalth AI
    // domain. It never adds or changes Cloudflare WAF deny rules automatically.
    if (hostname === "vynalthai.com" &&
        (incomingUrl.pathname === "/school-ip-report" ||
         incomingUrl.pathname === "/_shield/school-egress/candidates")) {
      return handleSchoolVolunteer(request, env, incomingUrl.pathname);
    }

    if (!rootDomain) {
      return new Response("Not Found", { status: 404 });
    }

    // Existing signed beacon / volunteer report handlers run above this policy.
    if (!isValidationPath(incomingUrl.pathname)) {
      const denial = await checkSchoolPolicy(request, env);
      if (denial) return edgeResponse(denial, request, incomingUrl, requestId, rootDomain);
    }

    // Keep the existing canonical redirect only for the Vynalth AI website.
    // Validation endpoints must remain untouched for certificate/domain checks.
    if (
      hostname === VYNALTH_WWW &&
      !isValidationPath(incomingUrl.pathname)
    ) {
      const target = new URL(request.url);
      target.hostname = VYNALTH_APEX;
      target.port = "";

      return edgeResponse(
        new Response(null, {
          status: 301,
          headers: { location: target.toString() },
        }),
        request,
        incomingUrl,
        requestId,
        rootDomain,
      );
    }

    let originResponse;

    try {
      // Preserve the original hostname and Host header. Cloudflare DNS for the
      // matching zone decides the real origin, so every domain/subdomain can
      // keep its own backend while sharing one edge Worker.
      originResponse = await fetch(request, {
        redirect: "manual",
      });
    } catch (error) {
      console.error("Origin request failed", {
        hostname,
        requestId,
        error,
      });

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
        rootDomain,
      );
    }

    return edgeResponse(
      originResponse,
      request,
      incomingUrl,
      requestId,
      rootDomain,
    );
  },
};
