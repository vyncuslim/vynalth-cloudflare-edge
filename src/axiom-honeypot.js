/**
 * First-party Cloudflare Worker -> Axiom honeypot security events (opt-in).
 * This records network observations, NOT authenticated visitor identity.
 * No IP, raw user-agent, query, request body, cookies, tokens, device IDs,
 * secrets, GPS or response body leave the Worker.
 *
 * Axiom token must be an ingest-only secret for vynalth-security-logs.
 * Axiom event delivery is best-effort; never claim queued == delivered.
 */
const ENDPOINT = "https://us-east-1.aws.edge.axiom.co/v1/ingest/vynalth-security-logs";
const CROSS_ZONE_WORKER_IP = "2a06:98c0:3600::103";
const METHODS = new Set(["GET","POST","HEAD","PUT","PATCH","DELETE","OPTIONS"]);

function plausibleIp(ip) {
  if (typeof ip !== "string" || ip.length < 3 || ip.length > 45) return false;
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(ip))
    return ip.split(".").every(n => Number(n) <= 255);
  return ip.includes(":") && /^[0-9a-f:]+$/i.test(ip) && ip.split(":").length >= 3;
}

export function classifyNetworkAttribution(request) {
  const ip = request?.headers?.get("CF-Connecting-IP")?.trim() || "";
  if (!request?.cf || !plausibleIp(ip))
    return { attribution: "unknown", ip: null, ip_source: "unavailable" };
  if (ip.toLowerCase() === CROSS_ZONE_WORKER_IP)
    return { attribution: "cloudflare_cross_zone_worker_proxy", ip: null,
      ip_source: "cloudflare_worker_subrequest" };
  return { attribution: "cloudflare_edge_observed", ip,
    ip_source: "cloudflare_cf_connecting_ip" };
}

function botClaim(request) {
  const agent = request.headers.get("User-Agent") || "";
  // These are unverified *claims*, not evidence of real bot ownership.
  if (/Twitterbot/i.test(agent)) return "Twitterbot_claimed";
  if (/facebookexternalhit|Facebot/i.test(agent)) return "MetaBot_claimed";
  if (/Googlebot/i.test(agent)) return "Googlebot_claimed";
  if (/Bingbot/i.test(agent)) return "Bingbot_claimed";
  return "not_identified";
}
async function networkHash(ip, now, env) {
  const secret = String(env?.AXIOM_HONEYPOT_ACTOR_SECRET ||
    env?.VISITOR_IP_SIGNING_SECRET || "");
  if (!ip || secret.length < 32) return null;
  // Domain-separated, daily rotating HMAC; shared NAT != one authenticated user.
  const date = new Date(now).toISOString().slice(0,10);
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret),
    { name:"HMAC", hash:"SHA-256" }, false, ["sign"]);
  const signed = await crypto.subtle.sign("HMAC", key,
    new TextEncoder().encode("vynalth-honeypot-network-v1|" + date + "|" + ip));
  return [...new Uint8Array(signed)].map(v=>v.toString(16).padStart(2,"0")).join("");
}

export async function buildAxiomSecurityEvent({request,url,requestId,status,path,kind,env,now=Date.now()}) {
  if (!request || !url || !/^[a-z0-9.-]{1,150}$/i.test(url.hostname)) return null;
  if (typeof path !== "string" || !/^\/[a-z0-9._/*-]{1,120}$/i.test(path))
    return null;
  if (!METHODS.has(request.method)) return null;
  const net = classifyNetworkAttribution(request);
  const actorHash = await networkHash(net.ip, now, env);
  const country = typeof request.cf?.country === "string" &&
    /^[A-Z]{2}$/.test(request.cf.country) ? request.cf.country : null;
  const id = typeof requestId === "string" && /^[a-z0-9-]{8,64}$/i.test(requestId)
    ? requestId : null;
  return {
    _time: new Date(now).toISOString(),
    event: kind === "wp_installer_block" ? "SENSITIVE_ROUTE_PROBE" : "HONEYPOT_TRIGGER",
    event_version: "php-honeypot-v2",
    severity: "warning",
    source: "cloudflare_worker",
    host: url.hostname.toLowerCase(),
    path,
    http_method: request.method,
    status_code: Number.isInteger(status) && status >= 100 && status <= 599 ? status : null,
    action: kind === "wp_installer_block" ? "block" : "observe_decoy",
    trap: typeof kind === "string" ? kind.slice(0,32) : "unknown",
    request_id: id,
    country: net.attribution === "cloudflare_edge_observed" ? country : null,
    ip_source: net.ip_source,
    ip_attestation_status: net.attribution,
    origin_ip_verified: false,
    network_actor_id: actorHash,
    actor_scope: actorHash ? "pseudonymous_network_daily" : "unavailable",
    bot_claim: botClaim(request),
    bot_verified: typeof request.cf?.botManagement?.verifiedBot === "boolean" ?
      request.cf.botManagement.verifiedBot : null,
    intrusion_verified: false,
  };
}

export async function dispatchAxiomSecurityEvent(args, fetchImpl=fetch) {
  const {env} = args || {};
  if (env?.AXIOM_HONEYPOT_INGEST_ENABLED !== "true") return {state:"disabled"};
  const token = env?.AXIOM_INGEST_TOKEN;
  if (typeof token !== "string" || token.length < 32)
    return {state:"not_configured"};
  let event;
  try { event = await buildAxiomSecurityEvent(args); }
  catch { return {state:"event_failed"}; }
  if (!event) return {state:"invalid_event"};
  try {
    const response = await fetchImpl(ENDPOINT, {
      method:"POST",
      headers:{
        "Authorization":"Bearer "+token,
        "Content-Type":"application/json",
      },
      body:JSON.stringify([event]),
      redirect:"manual",
      signal:AbortSignal.timeout(4500),
    });
    if (!response.ok) {
      console.warn("[HONEY AXIOM] ingest rejected", response.status);
      return {state:"rejected",status:response.status};
    }
    const ack = await response.json().catch(()=>null);
    if (ack?.ingested === 1 && (!ack.failed || ack.failed === 0))
      return {state:"ingested"};
    console.warn("[HONEY AXIOM] ingest response not confirmed");
    return {state:"unconfirmed"};
  } catch {
    console.warn("[HONEY AXIOM] ingest transport failed");
    return {state:"failed"};
  }
}

export function scheduleAxiomSecurityEvent(args) {
  if (!args?.ctx || typeof args.ctx.waitUntil !== "function") return false;
  if (args.env?.AXIOM_HONEYPOT_INGEST_ENABLED !== "true") return false;
  if (typeof args.env?.AXIOM_INGEST_TOKEN !== "string" ||
      args.env.AXIOM_INGEST_TOKEN.length < 32) {
    console.warn("[HONEY AXIOM] enabled but ingest token is missing");
    return false;
  }
  args.ctx.waitUntil(dispatchAxiomSecurityEvent(args));
  return true;
}
