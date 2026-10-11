/**
 * Founder-requested 12-hour temporary egress IP restriction (one observed
 * shared public IPv4, not an assertion that a visitor attends a school).
 * Expires by an absolute UTC epoch even if nobody revokes it manually.
 * This rule applies only to hostnames actually routed to this Worker.
 */
export const TEMPORARY_IP_BLOCK={
 ip:"60.51.219.195",
 expiresAtUnix:1791766673,
 reason:"operator-12h-school-egress"
};

function isPublicRecoveryRoute(host,path){
 // Trusted contacts, support, service status and legal/auth recovery cannot
 // be blocked by the temporary network rule.
 if(/^(trust|status|contact)\./i.test(host))return true;
 if(path==="/contact"||path.startsWith("/contact/")||
    path==="/status"||path.startsWith("/status/")||
    path==="/trust"||path.startsWith("/trust/")||
    path.startsWith("/auth/")||path==="/auth"||
    path.startsWith("/api/auth/")||
    path.startsWith("/api/security/recovery")||
    path.startsWith("/.well-known/")||
    path.startsWith("/en/legal/")||path.startsWith("/cn/legal/")||
    path.startsWith("/ms/legal/")||
    path==="/__shield/gps/status"||path==="/__shield/gps/disclaimer"||
    path==="/en/contact"||path.startsWith("/en/contact/"))return true;
 return false;
}

export function temporaryIpBlockResponse(request,url,nowMs=Date.now()){
 if(nowMs>=TEMPORARY_IP_BLOCK.expiresAtUnix*1000)return null;
 // CF-Connecting-IP must be set by the trusted Cloudflare edge, not by any
 // browser-supplied X-Forwarded-For or arbitrary custom header.
 if(request.headers.get("CF-Connecting-IP")!==TEMPORARY_IP_BLOCK.ip)
  return null;
 if(isPublicRecoveryRoute(url.hostname,url.pathname))return null;
 const remaining=Math.max(1,Math.ceil(TEMPORARY_IP_BLOCK.expiresAtUnix-nowMs/1000));
 return new Response(
  "Temporary access restriction for this network. Please try again after the 12-hour restriction expires. Recovery, trust, contact and status services remain available.",
  {status:403,headers:{
   "Content-Type":"text/plain; charset=utf-8",
   "Cache-Control":"no-store",
   "Referrer-Policy":"no-referrer",
   "Retry-After":String(remaining),
   "X-Vynalth-Temporary-IP-Block":"12h",
  }}
 );
}
