/**
 * A privacy-limited, first-party public egress IP echo.
 *
 * IMPORTANT: an observed address is evidence about a network path, not proof
 * of school attendance, shared-IP membership, identity, or malicious activity.
 * The endpoint is READ ONLY. No block, WAF update, KV write or logging.
 */
const PATH="/__shield/network/egress-ip";
const HOST="vynalthai.com";
const HEADERS={
 "Content-Type":"application/json; charset=utf-8",
 "Cache-Control":"private, no-store, max-age=0",
 "Pragma":"no-cache",
 "X-Content-Type-Options":"nosniff",
 "X-Robots-Tag":"noindex,nofollow",
 "Referrer-Policy":"no-referrer",
 "Access-Control-Allow-Origin":"", // no usable cross-origin credential grant
};
function reply(status,data){
 const h={...HEADERS};
 delete h["Access-Control-Allow-Origin"];
 return new Response(JSON.stringify(data),{status,headers:h});
}
export function handleEgressIpCheck(request,url){
 if(url.hostname!==HOST||url.pathname!==PATH)return null;
 if(request.method!=="GET")return reply(405,{error:"METHOD_NOT_ALLOWED"});
 const site=request.headers.get("Sec-Fetch-Site");
 if(site&&site!=="same-origin"&&site!=="none")
  return reply(403,{error:"SAME_ORIGIN_REQUIRED"});
 // CF-Connecting-IP is populated at the Cloudflare edge. It is NOT a claim
 // about all other users or who controls the address.
 const ip=(request.headers.get("CF-Connecting-IP")||"").trim();
 const ipv4=ip.split(".");
 const four=ipv4.length===4&&ipv4.every(n=>/^\d{1,3}$/.test(n)&&Number(n)<=255);
 // Syntactic sanity, not IPv6 canonicalization (Cloudflare owns this header).
 const six=ip.includes(":")&&ip.length<=45&&
  /^[0-9a-fA-F:.]+$/.test(ip)&&
  ip.split(":").filter(Boolean).length<=8;
 if(!four&&!six)return reply(503,{error:"EGRESS_IP_UNAVAILABLE"});
 return reply(200,{
  ip,
  ipVersion:four?4:6,
  observedAt:new Date().toISOString(),
  source:"cloudflare-edge-request",
  networkIdentityVerified:false,
  autoBlockEnabled:false
 });
}
