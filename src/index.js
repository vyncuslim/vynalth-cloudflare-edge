import { handleUniversalConsent, shieldAccountExempt } from "./universal-consent.js";
import { guestGpsGate } from "./guest-gps.js";
import { handleEgressIpCheck,checkSchoolEgressRestriction } from "./egress-ip-check.js";
import { handleJingxinMedia } from "./jingxin-media.js";
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


// A Cloudflare Service Binding makes policy decisions without overwriting any
// route, Host header, existing Shield rules, redirects or application handler.
async function checkSchoolPolicy(request, env, rootDomain) {
  // Authenticate SSO status on the server. These three statuses are
  // exempt from this School IP policy only; Cloudflare WAF, abuse and
  // mandatory security controls still apply independently.
  if (env?.SCHOOL_TRUSTED_SSO_EXEMPTION_ENABLED === "true" &&
      await shieldAccountExempt(request, env, rootDomain)) return null;
  if (!env?.SCHOOL_POLICY || typeof env.SCHOOL_POLICY.fetch !== "function") return null;

  // The upstream CF-Connecting-IP is authoritative for this edge request.
  // Construct an internal request and DO NOT pass browser-provided policy headers.
  const sourceIp = request.headers.get("CF-Connecting-IP");
  if (!sourceIp) return null;

  const url = new URL(request.url);
  url.search = ""; // Do not forward sensitive URL query parameters to policy Worker.
  url.hash = "";

  const policyRequest = new Request(url.toString(), {
    method: request.method,
    headers: { "X-Vynalth-Policy-Client-IP": sourceIp },
  });

  try {
    const decision = await env.SCHOOL_POLICY.fetch(policyRequest);
    if (
      decision.status === 403 &&
      decision.headers.get("X-School-Policy") === "blocked"
    ) return decision;
    if (decision.status !== 204) {
      console.warn("Unexpected School Policy status; failing open", decision.status);
    }
  } catch (error) {
    console.error("School Policy binding unavailable; failing open", String(error));
  }
  return null;
}

export default {
  async fetch(request, env, ctx) {
    const incomingUrl = new URL(request.url);
    const hostname = incomingUrl.hostname.toLowerCase();
    const rootDomain = getRootDomain(hostname);
    const requestId = crypto.randomUUID();

    if (!rootDomain) {
      return new Response("Not Found", { status: 404 });
    }

    // Dedicated, read-only, same-origin network observer for an opted-in
    // administrator's mobile browser. Never creates an IP block or whitelist.
    // Existing Cloudflare WAF runs before this Worker as usual.
    const networkObservation = await handleEgressIpCheck(request,env,incomingUrl);
    if(networkObservation){
      return edgeResponse(networkObservation,request,incomingUrl,requestId,rootDomain);
    }

    // Time-limited founder-approved network restrictions. The browser cannot
    // choose a third-party IP: only CF-Connecting-IP is considered.
    const schoolEgressDenial=await checkSchoolEgressRestriction(request,env,incomingUrl);
    if(schoolEgressDenial){
      return edgeResponse(schoolEgressDenial,request,incomingUrl,requestId,rootDomain);
    }

    // Keep School IP Policy enforcement for protected photo bytes. A guest's
    // self-reported GPS verdict alone must never bypass independent School
    // IP restrictions. Canonical server-signed trust/contact/status identities
    // remain exempt from this feature-specific school blocking.
    const photoResource = rootDomain === "vyncuslim.com" &&
      incomingUrl.pathname.startsWith("/media/jingxin/");
    if (photoResource && env?.JINGXIN_PRIVATE_MEDIA_ENABLED === "true" &&
        !(await shieldAccountExempt(request,env,rootDomain))) {
      const schoolDenial = await checkSchoolPolicy(request,env,rootDomain);
      if (schoolDenial) {
        return edgeResponse(schoolDenial,request,incomingUrl,requestId,rootDomain);
      }
    }
    // Private Jingxin media is handled entirely at the edge before generic
    // origin proxying. A denied/failed R2 request never falls through
    // to potentially public static photo assets.
    const photoDecision = await handleJingxinMedia(request,env,incomingUrl,rootDomain);
    if (photoDecision) {
      return edgeResponse(photoDecision,request,incomingUrl,requestId,rootDomain);
    }

    // Dedicated consent endpoints are first-party and must work without GPS
    // consent and without bypassing the existing host routing/security model.
    const consentDecision = await handleUniversalConsent(request, env, incomingUrl, rootDomain);
    if (consentDecision) {
      return edgeResponse(consentDecision, request, incomingUrl, requestId, rootDomain);
    }

    // GPS and Cookie Consent are independent modules in ONE existing Worker.
    // Signed canonical SSO trust/contact/status is exempt from this GPS
    // challenge, but does not bypass unrelated WAF or mandatory auth.
    // Public GPS documentation/endpoints remain available to every visitor.
    const gpsEndpoint = incomingUrl.pathname.startsWith("/__shield/gps/");
    const canonicallyExempt = env?.GPS_GATE_ENABLED === "true" &&
      !gpsEndpoint && await shieldAccountExempt(request,env,rootDomain);
    if (!canonicallyExempt) {
      const gpsDecision = await guestGpsGate(request,env,incomingUrl);
      if (gpsDecision) {
        return edgeResponse(gpsDecision,request,incomingUrl,requestId,rootDomain);
      }
    }

    // Preserve domain validation/ACME checks; apply the school IP policy to
    // remaining requests without changing upstream Cloudflare WAF behavior.
    if (!isValidationPath(incomingUrl.pathname)) {
      const denial = await checkSchoolPolicy(request, env, rootDomain);
      if (denial) {
        return edgeResponse(denial, request, incomingUrl, requestId, rootDomain);
      }
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
