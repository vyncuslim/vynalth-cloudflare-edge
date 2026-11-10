/**
 * Privacy-bounded Cloudflare edge Telegram diagnostics.
 *
 * - No Cookie, Authorization, API key, query values, or request body contents.
 * - No claimed device ID or user identity is treated as authenticated.
 * - Only the Cloudflare runtime's request.cf metadata + CF-Connecting-IP can
 *   justify an edge-observed IP label, NEVER an origin-verified HMAC claim.
 * - No precise GPS coordinates, even when the request is GPS verification.
 * - Plain text only, with bounded and control-character-free untrusted data.
 */
function safeText(value,max=160){
 if(typeof value!=="string"||!value)return "Unknown";
 return value.replace(/[\u0000-\u001f\u007f-\u009f]/g," ")
   .replace(/\s+/g," ").trim().slice(0,max)||"Unknown";
}
function plausibleIp(s){
 if(typeof s!=="string"||s.length>45)return false;
 if(/^(?:\d{1,3}\.){3}\d{1,3}$/.test(s))
  return s.split(".").every(x=>Number(x)<=255&&String(Number(x))===x);
 return /:/.test(s)&&/^[a-fA-F0-9:.]+$/.test(s)&&s.length>=3;
}
function redactedPath(url){
 let path=url.pathname||"/";
 // Never echo sensitive path identifiers or injected content to Telegram.
 // Keep path names such as /api/visitor-info, /.env, and /__shield/gps/.
 path=path.replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi,"[ID]")
  .replace(/\b[A-Za-z0-9_-]{30,}\b/g,"[REDACTED]")
  .replace(/%[0-9a-f]{2}/gi,"[ENCODED]");
 return safeText(path,220);
}
function cfGeo(request){
 const cf=request?.cf;
 if(!cf||typeof cf!=="object")return {country:"Unknown",region:"Unknown"};
 const country=String(cf.country||"").trim().toUpperCase();
 const region=String(cf.regionCode||"").trim().toUpperCase();
 return {
  country:/^[A-Z]{2}$/.test(country)&&country!=="XX"&&country!=="T1"?country:"Unknown",
  region:/^[A-Z0-9-]{1,12}$/.test(region)?region:"Unknown"
 };
}
function location(country,region){
 if(country==="Unknown")return "Unknown (no trusted edge geo metadata)";
 return country+(region==="Unknown"?"":"-"+region)+
   " (Cloudflare edge IP geolocation; approximate, not GPS)";
}
function querySummary(url){
 const count=Array.from(url.searchParams).length;
 return count===0?"None":count+" parameter(s) [REDACTED]";
}
function tokenSummary(request,url){
 const sensitiveHeaders=["authorization","x-api-key","x-auth-token","x-access-token"];
 const hasHeader=sensitiveHeaders.some(key=>request.headers.has(key));
 const hasQuery=Array.from(url.searchParams.keys()).some(key=>
  /^(?:token|key|api[_-]?key|access[_-]?token|auth|authorization|secret|password|code)$/i.test(key));
 return hasHeader||hasQuery?"Present [REDACTED]":"None";
}
function bodySummary(request){
 const contentType=request.headers.get("Content-Type");
 // Never report MIME parameters (multipart boundaries may include secrets).
 const media=contentType?.split(";")[0]?.trim().toLowerCase()||"";
 const safeType=/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(media)?
  media:"unspecified";
 const len=request.headers.get("Content-Length");
 const hasBody=len!==null?Number(len)>0:
  !["GET","HEAD"].includes(request.method)?"unknown":false;
 if(hasBody===false)return "None (Content-Type: "+safeType+")";
 return (hasBody===true?"Present [REDACTED]":"Unknown (not read)")+
   " (Content-Type: "+safeType+")";
}
function claimedDeviceId(request){
 const raw=request.headers.get("X-Vynalth-Device-Id")||
   request.headers.get("X-Device-Id");
 if(!raw)return "None";
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(raw))
  return "Unusable claim [REDACTED]";
 return raw+" (unverified browser claim)";
}
export function formatEdgeSecurityAlert({request,url,response,issue,requestId,responseTimeMs}){
 const cf=cfGeo(request);
 const rawIp=request.headers.get("CF-Connecting-IP")?.trim()||"";
 const edgeObserved=plausibleIp(rawIp)&&!!request.cf;
 const ip=edgeObserved?rawIp:"Unknown";
 const hasIp=ip!=="Unknown";
 // Cloudflare supplies this shared address for cross-zone Worker subrequests;
 // it is not the real requestor's IP and must never be called visitor-verified.
 const crossZone=hasIp&&ip.toLowerCase()==="2a06:98c0:3600::103";
 const ua=request.headers.get("User-Agent");
 const elapsed=Number.isFinite(responseTimeMs)&&responseTimeMs>=0?
  String(Math.round(responseTimeMs)):"Unknown (not instrumented)";
 const note=issue?.description||"Request processed by the Cloudflare edge Worker";
 const isProbe=issue?.code==="SUSPICIOUS_PROBE";
 const header="🚨 Vynalth AI Security Alert";
 return [
  header,
  "=============================",
  "Type: "+safeText(issue?.code||"HTTP_REQUEST",40),
  "Severity: "+safeText((issue?.severity||"Info").toUpperCase(),15),
  "IP: "+(hasIp?ip+(crossZone?
    " (Cloudflare cross-zone Worker proxy; visitor IP unknown)":
    " (Cloudflare edge observed; origin verification not checked)"):"Unknown (NOT VERIFIED)"),
  "Path: "+redactedPath(url),
  "Message: "+safeText(note,220),
  "Details:",
  " • Request Id: "+safeText(requestId,64),
  " • Host: "+safeText(url.hostname.toLowerCase(),100),
  " • Method: "+safeText(request.method,12),
  " • Status Code: "+response.status,
  " • Response Time Ms: "+elapsed+" (measured at Cloudflare Worker)",
  " • Ip Verified: "+(crossZone?
    "false (shared Cloudflare Worker IP; not a visitor)":hasIp?
    "true (edge metadata only; not origin HMAC verified)":"false"),
  " • Ip Source: "+(crossZone?"cloudflare_cross_zone_worker_ip":
    hasIp?"cloudflare_cf_connecting_ip":"unavailable"),
  " • Ip Verification Reason: "+(crossZone?"cross_zone_worker_proxy_not_visitor":
    hasIp?"cloudflare_runtime_request_cf_present":"no_confirmed_edge_ip"),
  " • Visitor Attribution: "+(crossZone?"unknown (Cloudflare Worker intermediary)":
    hasIp?"edge-observed network only; user identity unverified":"unknown"),
  " • Network Peer IP: Unknown (proxy peer may not be the visitor)",
  " • Device Id: Unknown (not authenticated at this edge)",
  " • Claimed Device Id: "+claimedDeviceId(request),
  " • User: Unknown (not authenticated at this edge)",
  " • Query: "+querySummary(url),
  " • Cookie: "+(request.headers.has("Cookie")?"Present [REDACTED]":"None"),
  " • Token: "+tokenSummary(request,url),
  " • Body: "+bodySummary(request),
  " • Country: "+(crossZone?"Unknown (Worker proxy; visitor origin unavailable)":
    cf.country==="Unknown"?"Unknown":cf.country+" (Cloudflare edge; approximate)"),
  " • Location: "+(crossZone?"Unknown (shared Worker IP cannot establish visitor location)":
    location(cf.country,cf.region)),
  " • Proxy Location: Unknown (not a verified visitor location)",
  " • GPS: Not verified or provided; precise GPS never inferred",
  " • User Agent: "+(ua?safeText(ua,160):"Unknown"),
  " • Verified Bot: "+(request.cf?.botManagement?.verifiedBot===true?
    "true (Cloudflare bot metadata)":"not established"),
  " • Suspicious Bot: "+(isProbe?
    "Unverified; sensitive-path probing pattern detected":
    "Not established (no verified bot classification)"),
  " • Time (UTC): "+new Date().toISOString(),
 ].join("\n").slice(0,3700);
}
