/**
 * Short-lived, founder-approved source-network restriction.
 * - Cloudflare measures the observed IP; neither a mobile client nor a user
 *   supplied IP can select the target.
 * - Backend verifies a founder Supabase session and signs a one-use-window
 *   authorization. Both services use SCHOOL_EGRESS_SIGNING_SECRET (server only).
 * - KV holds one HMAC of the latest observed IP (no raw address) for <=3h.
 * - No user/device identity claim; no Cloudflare WAF/IP Access Rule side effects.
 */
const HOST="vynalthai.com";
const PATH="/__shield/network/egress-ip";
const KEY="school-egress:current-v1";
const TTL=3*60*60;
const MAX_PROOF_AGE=120;
const HEAD={"Content-Type":"application/json; charset=utf-8","Cache-Control":"private, no-store, max-age=0",
 "X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Robots-Tag":"noindex,nofollow"};
const reply=(status,obj,more={})=>new Response(JSON.stringify(obj),{status,headers:{...HEAD,...more}});
const enc=new TextEncoder();
const bytes=b=>Array.from(new Uint8Array(b)).map(v=>String.fromCharCode(v)).join("");
const toB64=b=>btoa(bytes(b)).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
const keyFor=async s=>crypto.subtle.importKey("raw",enc.encode(s),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"]);
const sign=async(s,msg)=>toB64(await crypto.subtle.sign("HMAC",await keyFor(s),enc.encode(msg)));
const equal=async(s,msg,mac)=>typeof mac==="string"&&/^[A-Za-z0-9_-]{43}$/.test(mac)&&
 (await sign(s,msg))===mac;
const secret=env=>typeof env?.SCHOOL_EGRESS_SIGNING_SECRET==="string"&&
 env.SCHOOL_EGRESS_SIGNING_SECRET.length>=32?env.SCHOOL_EGRESS_SIGNING_SECRET:null;
const kv=env=>env?.SCHOOL_EGRESS_KV&&
 ["get","put","delete"].every(k=>typeof env.SCHOOL_EGRESS_KV[k]==="function")?env.SCHOOL_EGRESS_KV:null;
const originOK=r=>r.headers.get("Origin")==="https://"+HOST&&
 (!r.headers.get("Sec-Fetch-Site")||r.headers.get("Sec-Fetch-Site")==="same-origin");
const observedIp=r=>{
 const ip=(r.headers.get("CF-Connecting-IP")||"").trim();
 const octets=ip.split(".");
 const is4=octets.length===4&&octets.every(n=>/^\d{1,3}$/.test(n)&&Number(n)<=255);
 // Minimal syntax: Cloudflare normalizes IPv6 in CF-Connecting-IP.
 const is6=ip.includes(":")&&ip.length<=45&&/^[0-9A-Fa-f:.]+$/.test(ip)&&
 ip.split(":").filter(Boolean).length<=8;
 return is4||is6?ip:null;
};
const ipDigest=async(s,ip)=>sign(s,"egress-v1|address|"+ip);
const observeMessage=(ip,at)=>"egress-v1|observed|"+ip+"|"+at;
const permitMessage=(ip,at,expiry)=>"egress-v1|approved|"+ip+"|"+at+"|"+expiry;
const within=(at,now)=>{
 if(!Number.isSafeInteger(at))return false;
 return at>=now-MAX_PROOF_AGE&&at<=now+15;
};
const isPolicyException=path=>path===PATH||path===PATH+"/block"||path===PATH+"/clear"||
 path.startsWith("/.well-known/")||path.startsWith("/assets/")||
 path.startsWith("/api/auth/")||path.startsWith("/auth/")||
 path==="/api/admin/school-egress/authorize"||path==="/api/admin/school-egress/revoke"||
 path==="/en/legal/privacy"||path==="/robots.txt"||
 path==="/network-egress"||
 /^\\/(?:en|cn|ms)\\/(?:network-egress|auth)(?:\\/|$)/.test(path);

export async function checkSchoolEgressRestriction(request,env,url){
 if(env?.SCHOOL_EGRESS_BLOCK_ENABLED!=="true"||isPolicyException(url.pathname))return null;
 const store=kv(env),s=secret(env),ip=observedIp(request);
 if(!store||!s||!ip)return null;
 let policy;
 try{policy=JSON.parse(await store.get(KEY)||"null");}catch{return null;}
 if(!policy||!Number.isInteger(policy.expiresAt)||
    policy.expiresAt<=Math.floor(Date.now()/1000))return null;
 const digest=await ipDigest(s,ip);
 if(digest!==policy.ipDigest)return null;
 return reply(403,{error:"SCHOOL_NETWORK_RESTRICTED",
  message:"This shared network has been temporarily restricted by the website operator.",
  review:"https://vynalthai.com/en/legal/privacy"}, {"Retry-After":String(Math.max(1,policy.expiresAt-Math.floor(Date.now()/1000)))});
}

export async function handleEgressIpCheck(request,env,url){
 if(url.hostname!==HOST||![PATH,PATH+"/block",PATH+"/clear"].includes(url.pathname))return null;
 if(url.pathname===PATH){
  if(request.method!=="GET")return reply(405,{error:"METHOD_NOT_ALLOWED"});
  const fetchSite=request.headers.get("Sec-Fetch-Site");
  if(fetchSite&&fetchSite!=="same-origin"&&fetchSite!=="none")return reply(403,{error:"SAME_ORIGIN_REQUIRED"});
  const ip=observedIp(request);
  if(!ip)return reply(503,{error:"EGRESS_IP_UNAVAILABLE"});
  const at=Math.floor(Date.now()/1000);
  const s=secret(env);
  // A proof is worthless without the backend's real administrator login check.
  return reply(200,{ip,ipVersion:ip.includes(":")?6:4,
   observedAt:at,proof:s?await sign(s,observeMessage(ip,at)):null,
   source:"cloudflare-edge-request",networkIdentityVerified:false,
   temporaryNetworkRestrictionEnabled:env?.SCHOOL_EGRESS_BLOCK_ENABLED==="true"});
 }
 if(request.method!=="POST")return reply(405,{error:"METHOD_NOT_ALLOWED"});
 if(!originOK(request))return reply(403,{error:"ORIGIN_NOT_ALLOWED"});
 if(url.pathname===PATH+"/clear"){
  const s=secret(env),store=kv(env);
  if(!s||!store)return reply(503,{error:"NETWORK_RESTRICTION_NOT_CONFIGURED"});
  let payload;
  try{
   const raw=await request.text();if(raw.length>500)return reply(413,{error:"REQUEST_TOO_LARGE"});
   payload=JSON.parse(raw);
  }catch{return reply(400,{error:"INVALID_JSON"});}
  const at=payload?.at,now=Math.floor(Date.now()/1000);
  if(!Number.isSafeInteger(at)||at<now-60||at>now+10||
     !await equal(s,"egress-v1|revoke|"+at,payload?.authorization))
   return reply(403,{error:"OWNER_APPROVAL_REQUIRED"});
  try{await store.delete(KEY);}catch{return reply(503,{error:"RESTRICTION_STORAGE_UNAVAILABLE"});}
  return reply(200,{active:false,cleared:true});
 }
 if(env?.SCHOOL_EGRESS_BLOCK_ENABLED!=="true")return reply(503,{error:"NETWORK_RESTRICTION_DISABLED"});
 const s=secret(env),store=kv(env);
 if(!s||!store)return reply(503,{error:"NETWORK_RESTRICTION_NOT_CONFIGURED"});
 const ip=observedIp(request);
 if(!ip)return reply(503,{error:"EGRESS_IP_UNAVAILABLE"});
 const headerSize=Number(request.headers.get("Content-Length")||0);
 if(headerSize>1200)return reply(413,{error:"REQUEST_TOO_LARGE"});
 let input;
 try{let raw=await request.text();if(raw.length>1200)return reply(413,{error:"REQUEST_TOO_LARGE"});input=JSON.parse(raw);}
 catch{return reply(400,{error:"INVALID_JSON"});}
 if(input?.confirmedSchoolNetwork!==true||input.ip!==ip)return reply(403,{error:"NETWORK_NOT_CONFIRMED"});
 const at=input.observedAt,now=Math.floor(Date.now()/1000);
 if(!within(at,now)||!await equal(s,observeMessage(ip,at),input.proof))
  return reply(403,{error:"INVALID_OBSERVATION_PROOF"});
 const expiry=input?.expiresAt;
 if(!Number.isSafeInteger(expiry)||expiry<=now||expiry>now+120||
    !await equal(s,permitMessage(ip,at,expiry),input.authorization))
  return reply(403,{error:"OWNER_APPROVAL_REQUIRED"});
 const expiresAt=now+TTL;
 try{
  await store.put(KEY,JSON.stringify({
   ipDigest:await ipDigest(s,ip),expiresAt,updatedAt:now
  }),{expirationTtl:TTL});
 }catch{return reply(503,{error:"RESTRICTION_STORAGE_UNAVAILABLE"});}
 return reply(200,{active:true,expiresAt,expiresInSeconds:TTL,
  note:"Active for this observed public IP only; new observations replace older ones."});
}
