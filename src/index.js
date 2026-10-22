import { signedVisitorOriginRequest } from "./signed-visitor-ip.js";
import { handleUniversalConsent, shieldAccountExempt } from "./universal-consent.js";
import { guestGpsGate } from "./guest-gps.js";
import { isVerifiedGooglePublicCrawler } from "./public-crawler-access.js";
import { hasPermanentOwnerAccess } from "./permanent-owner-access.js";
import { handleJingxinMedia } from "./jingxin-media.js";
import { temporaryIpBlockResponse } from "./temporary-ip-block.js";
import { verifyGpsServiceCall } from "./gps-service-policy.js";
import { handleTemporaryOwnerAccess,hasTemporaryOwnerPass,hasSchoolPolicyOwnerPass } from "./temporary-owner-access.js";
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
  // Only a freshly verified owner session on the exact apex host can bypass
  // the School IP restriction, and only with explicit production opt-in.
  // Do not extend this to other users, hosts, WAF, or application authorization.
  if (rootDomain === "vynalthai.com" &&
      (await hasPermanentOwnerAccess(request,env,new URL(request.url)) ||
       await hasSchoolPolicyOwnerPass(request,env,new URL(request.url)))) return null;
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

    // Authenticated Service Binding calls from vv are a policy check only.
    // They NEVER run origin fetch, R2 handling, redirects or the vv Worker.
    // A missing/invalid signature cannot unlock any protected content.
    const internalGps = await verifyGpsServiceCall(request,env,incomingUrl);
    if (internalGps) {
      if (!internalGps.authenticated) {
        return edgeResponse(new Response("Forbidden",{status:403,
          headers:{"Cache-Control":"no-store","X-Vynalth-GPS-Policy":"invalid-service-auth"}}),
          request,incomingUrl,requestId,rootDomain);
      }
      const forwarded = internalGps.request;
      const temporary = temporaryIpBlockResponse(forwarded,incomingUrl);
      if (temporary && !(await shieldAccountExempt(forwarded,env,rootDomain)))
        return edgeResponse(temporary,forwarded,incomingUrl,requestId,rootDomain);
      if (env?.GPS_GATE_ENABLED!=="true")
        return edgeResponse(new Response("GPS policy is not enabled",{status:503,
          headers:{"Cache-Control":"no-store","X-Vynalth-GPS-Policy":"not-ready"}}),
          forwarded,incomingUrl,requestId,rootDomain);
      const protectedEndpoint=incomingUrl.pathname.startsWith("/__shield/gps/");
      const trusted=!protectedEndpoint&&(
        await shieldAccountExempt(forwarded,env,rootDomain) ||
        await hasPermanentOwnerAccess(forwarded,env,incomingUrl));
      if (!trusted) {
        const decision=await guestGpsGate(forwarded,env,incomingUrl,ctx,requestId,
          internalGps.country);
        if (decision)return edgeResponse(decision,forwarded,incomingUrl,requestId,rootDomain);
      }
      return edgeResponse(new Response(null,{status:204,
        headers:{"Cache-Control":"no-store","X-Vynalth-GPS-Policy":"allow"}}),
        forwarded,incomingUrl,requestId,rootDomain);
    }

    // Temporary, self-expiring owner-requested network restriction. The
    // verified trust/contact/status identity exemption is unconditional for
    // this feature. This runs before GPS and origin proxying.
    const temporaryDenial = temporaryIpBlockResponse(request,incomingUrl);
    if (temporaryDenial && !(await shieldAccountExempt(request,env,rootDomain))) {
      return edgeResponse(temporaryDenial,request,incomingUrl,requestId,rootDomain);
    }

    // Owner's 10-minute access portal is served by the Worker before the GPS
    // challenge, but after existing temporary IP restrictions. It never
    // creates an application admin/SSO session or bypasses School Policy.
    const temporaryOwnerPage=await handleTemporaryOwnerAccess(request,env,incomingUrl);
    if(temporaryOwnerPage){
      return edgeResponse(temporaryOwnerPage,request,incomingUrl,requestId,rootDomain);
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
    const temporaryOwnerExempt = !gpsEndpoint && hostname==="vynalthai.com" &&
      await hasTemporaryOwnerPass(request,env,incomingUrl);
    const permanentOwnerExempt = !gpsEndpoint &&
      await hasPermanentOwnerAccess(request,env,incomingUrl);
    // Search crawlers cannot grant browser geolocation permission. Let only
    // source-IP-verified Google crawlers reach ZoKivo public search resources;
    // private APIs, human GPS checks, and School IP Policy still apply.
    const verifiedPublicCrawler = !gpsEndpoint &&
      await isVerifiedGooglePublicCrawler(request);
    if (!canonicallyExempt && !temporaryOwnerExempt && !permanentOwnerExempt && !verifiedPublicCrawler) {
      const gpsDecision = await guestGpsGate(request,env,incomingUrl,ctx,requestId);
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
      // Strip any spoofed client-IP attestation headers and forward only
      // Cloudflare-signed visitor identity when the shared secret is enabled.
      const originRequest = await signedVisitorOriginRequest(request, env);
      originResponse = await fetch(originRequest, {
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

    // On every reload the browser must reach the Worker again, not use a
    // cached HTML copy of a previous successful GPS visit. Never leak a
    // navigation proof through referrers to third parties.
    if (env?.GPS_RECHECK_EVERY_DOCUMENT === "true" &&
        request.headers.get("Accept")?.includes("text/html") &&
        (request.headers.get("Sec-Fetch-Dest") || "document") === "document" &&
        originResponse.headers.get("Content-Type")?.includes("text/html")) {
      const safeHeaders = new Headers(originResponse.headers);
      safeHeaders.set("Cache-Control", "private, no-store, max-age=0");
      safeHeaders.set("Referrer-Policy", "no-referrer");
      originResponse = new Response(originResponse.body, {
        status: originResponse.status,
        statusText: originResponse.statusText,
        headers: safeHeaders
      });
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
