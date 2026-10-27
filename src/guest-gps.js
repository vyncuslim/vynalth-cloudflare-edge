import { parseCampusPolygons, decideCampusPolygons, MAX_GPS_ACCURACY_METERS } from "./gps-polygons.js";
import { GPS_HTML,GPS_CLIENT } from "./gps-verification-ui.js";
import { scheduleGpsDenialAlert,telegramGpsStatus } from "./gps-telegram-alert.js";
import { gpsRegionalDecision } from "./gps-regional-trigger.js";
const GEO_HTML=GPS_HTML;
const GEO_CLIENT=GPS_CLIENT;
const DISCLAIMER_HTML="<!doctype html>\n<html lang=\"zh-CN\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<meta name=\"robots\" content=\"noindex,nofollow\"><meta name=\"referrer\" content=\"no-referrer\">\n<title>GPS Verification Disclaimer · Vynalth AI</title>\n<style>\n:root{color-scheme:dark;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#eaf1fc;background:#05070e}\nbody{padding:28px 17px;margin:0;background:radial-gradient(circle at 20% 0,#172840,transparent 60%),#05070e}\nmain{margin:auto;max-width:780px;background:#101827;border:1px solid #364563;border-radius:21px;padding:clamp(24px,4vw,42px)}\nheader{color:#98c8ff;font-size:12px;font-weight:800;letter-spacing:.1em}\nh1{font-size:clamp(30px,5vw,42px);margin:16px 0}\nh2{font-size:18px;color:#d6e7ff;margin:26px 0 10px}\np,li{color:#bbcbdf;line-height:1.8;font-size:14px}\na{color:#9cceff}aside{padding:14px;border:1px solid #465b81;border-radius:12px;background:#192b44}\n</style></head>\n<body><main><header>VYNALTH AI · LOCATION POLICY</header>\n<h1>声明 · Penafian · Disclaimer</h1>\n<aside>\n<strong>独立网站政策 / Dasar laman bebas / Independent website policy</strong>\n<p>此功能由 Vynalth AI 网站运营者提供，不属于 POWIIS 校方官方定位或访问系统。</p>\n<p>Fungsi ini bukan perkhidmatan rasmi POWIIS.</p>\n<p>This location requirement is not operated or endorsed by POWIIS.</p>\n</aside>\n<h2>1. 为什么请求位置 / Tujuan / Purpose</h2>\n<p>网页仅在访客点击授权按钮、并同意浏览器的位置权限后才请求地理位置，用于判断设备报告的位置是否位于网站运营者设置的校园地理围栏之内。精确位置并不能可靠证明某人的学校身份、账号身份或当前网络。</p>\n<p>Lokasi hanya diminta selepas persetujuan melalui pelayar, bagi semakan kawasan geografi. Lokasi bukan bukti identiti.</p>\n<p>After browser permission, the reported position is checked against an operator-defined campus area. Browser location can be inaccurate or spoofed.</p>\n<h2>2. 不提供位置 / Jika menolak / If you decline</h2>\n<p>访客可以拒绝授权，但启用此功能的网站可能因此不允许继续访问并展示访问限制页面。拒绝授权本身不会导致永久账号封锁。你可以修改浏览器权限后重新尝试。</p>\n<p>Anda boleh menolak; akses tetamu mungkin dihadkan, tetapi akaun tidak diharamkan secara kekal hanya kerana penolakan.</p>\n<p>You may refuse location access. When the gate is enabled, guest access may be restricted, but refusing does not permanently ban your account.</p>\n<h2>3. Cookie 与数据 / Kuki dan data / Cookies and data</h2>\n<p>验证时通过 HTTPS 将报告的经纬度及精度传送至本站 Worker，本功能不主动将精确 GPS 坐标写入 Cookie 或 KV。成功通过验证或处于限制区域时，本站可设置最长约 15 分钟、仅对本站有效的签名状态 Cookie。浏览器可在设置中删除 Cookie；各独立根域名无法直接读取其他域的 Cookie。</p>\n<p>Koordinat digunakan untuk keputusan permintaan sahaja dan tidak disimpan dalam kuki. Kuki status sementara terikat pada domain sendiri.</p>\n<p>Precise coordinates are used for the current verification and are not intentionally stored in persistent application data by this feature. Short-lived signed status cookies do not contain GPS coordinates. Standard server/network logs and browser behavior are governed by their own policies.</p>\n<h2>4. 豁免和错误 / Pengecualian dan ralat / Exemptions and mistakes</h2>\n<p>由服务器身份验证并确认状态为 <strong>trust</strong> 或 <strong>contact</strong> 的账号可豁免此项 GPS 检查。浏览器自身声明并不构成有效凭证。如判断有误、设备无法定位、位于边界或需要访问帮助，请联系网站管理员；可要求人工复核与删除相关记录。</p>\n<p>Status akaun trust/contact mesti disahkan oleh pelayan. Untuk semakan atau pemadaman, hubungi pentadbir laman.</p>\n<p>Authenticated trust/contact accounts are exempt once the website validates their status server-side. Contact the website operator to dispute a decision or request applicable data deletion.</p>\n<h2>5. 儿童及未成年人 / Pengguna bawah umur / Minors</h2>\n<p>学校访客可能包括未成年人。请勿在未经适当授权的情况下提交他人位置，亦不要通过其他设备代替他人授权。网站不会因为一次位置报告而永久封锁账号。</p>\n<p>Jangan kongsi lokasi orang lain tanpa persetujuan yang sewajarnya.</p>\n<p>Do not submit someone else's location without appropriate permission. This feature must be reviewed for applicable privacy requirements before production activation.</p>\n<p><a href=\"https://vynalthai.com/en/legal/privacy\" rel=\"noopener noreferrer\" referrerpolicy=\"no-referrer\">Vynalth AI Privacy Policy</a></p>\n<p><a href=\"/__shield/gps/verify-info\">查看位置验证信息 / View verification information</a></p>\n</main></body></html>";
const SESSION_COOKIE="__Host-vynalth-geo";
const STATUS_COOKIE="__Host-vynalth-status";
const BLOCK_COOKIE="__Host-vynalth-geo-block";
const HANDOFF_STATE_COOKIE="__Host-vynalth-geo-handoff";
const FRESH_BRIDGE_COOKIE="__Host-vynalth-gps-fresh";
const GPS_BRIDGE_HUB="vynalthai.com";
const GPS_BRIDGE_ROOTS=Object.freeze([
 "vynalthai.com","vyncuslim.com","vynalthai.si","vyncuslim.si",
 "vitamindai.online","sleepsomno.com","powiismunc.com"
]);
function allowedTarget(host){
 if(typeof host!=="string"||host.length>253||host===GPS_BRIDGE_HUB||
    !/^[a-z0-9.-]+$/.test(host))return false;
 return GPS_BRIDGE_ROOTS.some(root=>host===root||host.endsWith("."+root));
}
function isBrowserDocument(request){
 // Only top-level HTML navigation may leave this site for a first-party
 // consent flow; API/POST/assets remain protected without redirects.
 const accept=request.headers.get("Accept")||"";
 const dest=request.headers.get("Sec-Fetch-Dest");
 return request.method==="GET" && accept.includes("text/html") &&
    (!dest||dest==="document"||dest==="empty");
}

const SESSION_TTL=900;
const GPS_POLICY_REVISION="gps-outside-coarse-accuracy-v3";
const NAV_PROOF_PARAM="__vynalth_gps_visit";
const NAV_PROOF_TTL=60;
const NAV_PROOF_USED_TTL=120;
const enc=new TextEncoder();
const head={"Cache-Control":"private, no-store, max-age=0","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Robots-Tag":"noindex,nofollow","Vary":"Cookie","Permissions-Policy":"geolocation=(self)"};
const reply=(status,data,extra={})=>new Response(JSON.stringify(data),{status,headers:{...head,"Content-Type":"application/json; charset=utf-8",...extra}});
function b64(bytes){let s="";for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/g,"");}
function ub64(s){if(!/^[a-zA-Z0-9_-]{40,90}$/.test(s||""))return null;try{let x=s.replace(/-/g,"+").replace(/_/g,"/");return Uint8Array.from(atob(x+"=".repeat((4-x.length%4)%4)),v=>v.charCodeAt(0));}catch{return null}}
async function hkey(key){return crypto.subtle.importKey("raw",enc.encode(key),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"])}
async function sign(key,msg){return b64(new Uint8Array(await crypto.subtle.sign("HMAC",await hkey(key),enc.encode(msg))))}
async function valid(key,msg,tag){const signature=ub64(tag);return !!signature&&signature.length===32&&b64(signature)===tag&&await crypto.subtle.verify("HMAC",await hkey(key),signature,enc.encode(msg))}
function getCookie(req,name){const x=(req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));return x?x.slice(name.length+1):null}
function config(env){
 if(env?.GPS_GATE_ENABLED!=="true")return null;
 const {GPS_GATE_SESSION_SECRET:s,GPS_ACCOUNT_STATUS_SECRET:a}=env||{};
 const polygonMode=env?.GPS_POLYGON_MODE??"off";
 if(!["off","shadow","enforce"].includes(polygonMode)||
    typeof s!=="string"||s.length<32)return null;
 let polygons=null;
 if(polygonMode!=="off"){
  polygons=parseCampusPolygons(env?.GPS_CAMPUS_POLYGONS_JSON);
  if(!polygons)return null;
 }
 // Candidate OSM polygons are not certified. Approximate enforcement requires
 // explicit separate operator consent and will never claim survey authority.
 const provisional=env?.GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED==="true";
 if(polygonMode==="enforce"&&(
    env?.GPS_POLYGON_ENFORCEMENT_APPROVED!=="true"||
    polygons.some(c=>!c.officialBoundaryVerified&&! (
      provisional&&c.boundaryClassification==="OSM_MAPPED"&&
      ["powiis-balik-pulau","powiis-tanjung-bungah"].includes(c.id)))))return null;
 const bufferMeters=polygonMode==="enforce"?Number(env?.GPS_BOUNDARY_BUFFER_METERS??30):0;
 if(!Number.isFinite(bufferMeters)||bufferMeters<0||bufferMeters>100)return null;
 let campuses=[];
 if(polygonMode!=="enforce"){
  // Legacy circle policy is still authoritative while shadow evaluates.
  if(env?.GPS_CAMPUS_GEOFENCES_JSON!==undefined){
   const raw=env.GPS_CAMPUS_GEOFENCES_JSON;
   if(typeof raw!=="string"||raw.length>4096)return null;
   try{campuses=JSON.parse(raw);}catch{return null;}
  }else{
   const numeric=v=>(typeof v==="string"&&v.trim()==="")?NaN:Number(v);
   campuses=[{id:"legacy",lat:numeric(env?.GPS_CAMPUS_LAT),
    lon:numeric(env?.GPS_CAMPUS_LON),radius:numeric(env?.GPS_CAMPUS_RADIUS_METERS)}];
  }
  if(!Array.isArray(campuses)||campuses.length<1||campuses.length>8||
     campuses.some(c=>!c||typeof c!=="object"||typeof c.id!=="string"||
      !/^[a-z0-9-]{2,48}$/.test(c.id)||typeof c.lat!=="number"||
      typeof c.lon!=="number"||typeof c.radius!=="number"||
      !Number.isFinite(c.lat)||!Number.isFinite(c.lon)||!Number.isFinite(c.radius)||
      Math.abs(c.lat)>90||Math.abs(c.lon)>180||c.radius<50||c.radius>1000)||
     new Set(campuses.map(c=>c.id)).size!==campuses.length)return null;
 }
 return {s,a:typeof a==="string"&&a.length>=32?a:null,campuses,polygons,polygonMode,bufferMeters};
}
async function exempt(req,cfg,host){
 // Only the trusted application's server can mint a valid signed status cookie.
 // Format: exp.status.nonce.signature. Signature covers the originating host.
 if(!cfg.a)return false; // Guest GPS does not require login/SSO or an account-status key.
 const value=getCookie(req,STATUS_COOKIE);if(!value||value.length>320)return false;
 const parts=value.split(".");if(parts.length!==4)return false;
 const [exp,status,nonce,tag]=parts;
 if(status!=="trust"&&status!=="contact"&&status!=="status")return false;
 if(!/^\d{10,12}$/.test(exp)||!/^[a-zA-Z0-9_-]{22}$/.test(nonce))return false;
 const now=Math.floor(Date.now()/1000),ttl=Number(exp);
 if(ttl<=now||ttl>now+3600)return false;
 return valid(cfg.a,[exp,status,nonce,host].join("|"),tag);
}
async function sessionVerdict(req,cfg,host){
 const value=getCookie(req,SESSION_COOKIE);if(!value||value.length>320)return null;
 const parts=value.split(".");if(parts.length!==3)return null;
 const [exp,nonce,tag]=parts;
 if(!/^\d{10,12}$/.test(exp)||!/^[a-zA-Z0-9_-]{22}$/.test(nonce))return null;
 const now=Math.floor(Date.now()/1000),time=Number(exp);
 if(time<=now||time>now+SESSION_TTL)return null;
 if(await valid(cfg.s,[exp,nonce,host,"outside"].join("|"),tag))return "outside";
 if(time<=now+300&&await valid(cfg.s,[exp,nonce,host,"nearby"].join("|"),tag))return "nearby";
 return null;
}
async function permitted(req,cfg,host){return (await sessionVerdict(req,cfg,host))!==null;}

function policyCookie(name,value,age=SESSION_TTL){
 return name+"="+value+"; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age="+age;
}
async function verdictToken(cfg,host,verdict){
 if(!["inside","outside","nearby"].includes(verdict))throw Error("Invalid verdict");
 const expiry=Math.floor(Date.now()/1000)+(verdict==="nearby"?300:SESSION_TTL);
 const nonceBytes=new Uint8Array(16);crypto.getRandomValues(nonceBytes);
 const nonce=b64(nonceBytes);
 const sig=await sign(cfg.s,[expiry,nonce,host,verdict].join("|"));
 return expiry+"."+nonce+"."+sig;
}
async function hasBlockVerdict(request,cfg,host){
 const value=getCookie(request,BLOCK_COOKIE);
 if(!value||value.length>320)return false;
 const chunks=value.split(".");
 if(chunks.length!==3)return false;
 const [expiry,nonce,sig]=chunks;
 if(!/^\d{10,12}$/.test(expiry)||!/^[a-zA-Z0-9_-]{22}$/.test(nonce))return false;
 const now=Math.floor(Date.now()/1000),end=Number(expiry);
 if(end<=now||end>now+SESSION_TTL)return false;
 return valid(cfg.s,[expiry,nonce,host,"inside"].join("|"),sig);
}
// Private media may use the same existing *signed* first-party GPS verdict.
// No browser-supplied status/coordinates are trusted as authorization here.
export async function gpsOutsideOrLegacyExempt(request,env,host){
 const cfg=config(env);
 if(!cfg)return false;
 if(await exempt(request,cfg,host))return true;
 if(await hasBlockVerdict(request,cfg,host))return false;
 // Nearby access is for ordinary pages only; do not extend it to private media.
 return (await sessionVerdict(request,cfg,host))==="outside";
}
function safeRelativePath(path){
 return typeof path==="string"&&path.length<=300&&path.startsWith("/")&&
   !path.startsWith("//")&&!path.includes("\\")&&!/[\r\n]/.test(path)&&
   !path.startsWith("/__shield/gps/");
}
function validState(v){return typeof v==="string"&&/^[A-Za-z0-9_-]{32}$/.test(v)}
// Signed, path-bound, short-lived, one-navigation proof. Store ONLY a random
// replay marker (never GPS coordinates) in the existing bound Worker KV.
function cleanVisitPath(url){
 const next=new URL(url.toString());next.searchParams.delete(NAV_PROOF_PARAM);
 const path=next.pathname+next.search;
 return path.length<=400&&safeRelativePath(next.pathname)&&
        !/[\\\r\n]/.test(path)&&!path.startsWith("//")?path:null;
}
async function visitProof(cfg,host,path){
 const expiry=Math.floor(Date.now()/1000)+NAV_PROOF_TTL;
 const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);
 const nonce=b64(bytes);
 const signature=await sign(cfg.s,[expiry,nonce,host,path,"document"].join("|"));
 return expiry+"."+nonce+"."+signature;
}
async function consumeVisitProof(req,env,cfg,url){
 const kv=env?.CONSENT_KV;
 if(typeof kv?.get!=="function"||typeof kv?.put!=="function")return false;
 const proof=url.searchParams.get(NAV_PROOF_PARAM);
 if(!proof||proof.length>200)return false;
 const [expiry,nonce,signature,...extra]=proof.split(".");
 if(extra.length||!/^\d{10,12}$/.test(expiry||"")||
    !/^[A-Za-z0-9_-]{22}$/.test(nonce||""))return false;
 const now=Math.floor(Date.now()/1000),end=Number(expiry);
 if(end<=now||end>now+NAV_PROOF_TTL)return false;
 const path=cleanVisitPath(url);
 if(!path||!(await valid(cfg.s,[expiry,nonce,url.hostname,path,"document"].join("|"),signature)))
  return false;
 // Authentication still uses the existing signed per-domain status cookie.
 if(!(await permitted(req,cfg,url.hostname)))return false;
 const key="gps:visit:used:"+nonce;
 try{
  if(await kv.get(key))return false;
  await kv.put(key,"1",{expirationTtl:NAV_PROOF_USED_TTL});
  return true;
 }catch(err){
  console.error("GPS navigation proof storage unavailable",String(err));
  return false;
 }
}
async function mintFreshBridge(cfg,host){
 const expiry=Math.floor(Date.now()/1000)+NAV_PROOF_TTL;
 const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);
 const nonce=b64(bytes);
 return expiry+"."+nonce+"."+await sign(cfg.s,[expiry,nonce,host,"gps-fresh"].join("|"));
}
async function consumeFreshBridge(req,env,cfg,host){
 const kv=env?.CONSENT_KV,raw=getCookie(req,FRESH_BRIDGE_COOKIE);
 if(typeof kv?.get!=="function"||typeof kv?.put!=="function"||!raw||raw.length>200)
  return false;
 const [expiry,nonce,sig,...extra]=raw.split(".");
 if(extra.length||!/^\d{10,12}$/.test(expiry||"")||
   !/^[A-Za-z0-9_-]{22}$/.test(nonce||""))return false;
 const end=Number(expiry),now=Math.floor(Date.now()/1000);
 if(end<=now||end>now+NAV_PROOF_TTL||
    !(await valid(cfg.s,[expiry,nonce,host,"gps-fresh"].join("|"),sig)))return false;
 const key="gps:bridge:used:"+nonce;
 try{
  if(await kv.get(key))return false;
  await kv.put(key,"1",{expirationTtl:NAV_PROOF_USED_TTL});
  return true;
 }catch(err){
  console.error("GPS cross-domain freshness storage unavailable",String(err));
  return false;
 }
}
function appendVisitProof(path,proof){
 const next=new URL("https://"+GPS_BRIDGE_HUB+path);
 next.searchParams.delete(NAV_PROOF_PARAM);
 next.searchParams.set(NAV_PROOF_PARAM,proof);
 return next.pathname+next.search;
}

async function handoffToken(cfg,target,path,state,verdict){
 const expires=Math.floor(Date.now()/1000)+60;
 const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);
 const nonce=b64(bytes);
 const tag=await sign(cfg.s,[expires,verdict,nonce,target,path,state].join("|"));
 return [expires,verdict,nonce,tag].join(".");
}
async function validateHandoff(cfg,target,path,state,ticket){
 if(!validState(state)||typeof ticket!=="string"||ticket.length>260)return null;
 const parts=ticket.split(".");
 if(parts.length!==4)return null;
 const [expires,verdict,nonce,tag]=parts;
 if(!["inside","outside","nearby"].includes(verdict))return null;
 if(!/^\d{10,12}$/.test(expires)||!/^[A-Za-z0-9_-]{22}$/.test(nonce))return null;
 const expiry=Number(expires),now=Math.floor(Date.now()/1000);
 if(expiry<=now||expiry>now+60)return null;
 return await valid(cfg.s,[expires,verdict,nonce,target,path,state].join("|"),tag)?verdict:null;
}

function redirect(to,headers={}){
 return new Response(null,{status:302,headers:{...head,Location:to,...headers}});
}
function beginHandoff(url,recheck=false){
 if(!allowedTarget(url.hostname))return reply(400,{error:"INVALID_HANDOFF_TARGET"});
 const bytes=new Uint8Array(24);crypto.getRandomValues(bytes);
 const state=b64(bytes),path=safeRelativePath(url.pathname)?url.pathname:"/";
 const dest=new URL("https://"+GPS_BRIDGE_HUB+"/__shield/gps/"+(recheck?"recheck":"bridge"));
 dest.searchParams.set("host",url.hostname);
 dest.searchParams.set("return",path);
 dest.searchParams.set("state",state);
 return redirect(dest.toString(),{
  "Set-Cookie":policyCookie(HANDOFF_STATE_COOKIE,state,120),
  "Referrer-Policy":"no-referrer"
 });
}

// Browsers cannot read other registrable domain's cookies. Instead perform
// an explicit top-level redirect through the first-party Vynalth AI hub,
// transfer only a signed short-lived verdict, and set the target's own cookie.
async function bridge(request,url,cfg,env){
 if(request.method!=="GET"||url.hostname!==GPS_BRIDGE_HUB)
   return reply(404,{error:"NOT_FOUND"});
 const target=url.searchParams.get("host");
 const path=url.searchParams.get("return"),state=url.searchParams.get("state");
 if(!allowedTarget(target)||!safeRelativePath(path)||!validState(state))
   return reply(400,{error:"INVALID_BRIDGE_DESTINATION"});
 if(env?.GPS_RECHECK_EVERY_DOCUMENT==="true"&&
    !(await consumeFreshBridge(request,env,cfg,url.hostname)))
   return reply(403,{error:"FRESH_GPS_REQUIRED"});
 let verdict=null;
 if(await hasBlockVerdict(request,cfg,url.hostname))return blockedPage();
 verdict=await sessionVerdict(request,cfg,url.hostname);
 if(!verdict)return page(); // First-party hub asks for browser GPS; NO login needed.
 const ticket=await handoffToken(cfg,target,path,state,verdict);
 const destination=new URL("https://"+target+"/__shield/gps/import");
 destination.searchParams.set("ticket",ticket);
 destination.searchParams.set("return",path);
 destination.searchParams.set("state",state);
 return redirect(destination.toString(),{"Referrer-Policy":"no-referrer"});
}
async function importHandoff(request,url,cfg,env){
 if(request.method!=="GET"||!allowedTarget(url.hostname))
   return reply(404,{error:"NOT_FOUND"});
 const path=url.searchParams.get("return"),state=url.searchParams.get("state");
 if(!safeRelativePath(path)||!validState(state))return reply(400,{error:"INVALID_RETURN_PATH"});
 if(getCookie(request,HANDOFF_STATE_COOKIE)!==state)return reply(403,{error:"HANDOFF_STATE_MISMATCH"});
 const verdict=await validateHandoff(cfg,url.hostname,path,state,url.searchParams.get("ticket"));
 if(!verdict)return reply(403,{error:"INVALID_OR_EXPIRED_HANDOFF"});
 // Legacy signed inside tickets never set a blocking cookie on this host.
 if(verdict==="inside"){
  const denial=blockedPage();
  const headers=new Headers(denial.headers);
  if(getCookie(request,SESSION_COOKIE))headers.append("Set-Cookie",policyCookie(SESSION_COOKIE,"",0));
  if(getCookie(request,BLOCK_COOKIE))headers.append("Set-Cookie",policyCookie(BLOCK_COOKIE,"",0));
  return new Response(denial.body,{status:403,headers});
 }
 const name=SESSION_COOKIE;
 const old=verdict==="inside"?SESSION_COOKIE:BLOCK_COOKIE;
 const value=await verdictToken(cfg,url.hostname,verdict);
 const headers=new Headers(head);
 const proof=env?.GPS_RECHECK_EVERY_DOCUMENT==="true"?
  await visitProof(cfg,url.hostname,path):null;
 headers.set("Location",proof?appendVisitProof(path,proof):path);
 headers.append("Set-Cookie",policyCookie(name,value,verdict==="nearby"?300:SESSION_TTL));
 headers.append("Set-Cookie",policyCookie(old,"",0));
 headers.append("Set-Cookie",policyCookie(HANDOFF_STATE_COOKIE,"",0));
 return new Response(null,{status:302,headers});
}

async function createSession(cfg,host){
 const exp=Math.floor(Date.now()/1000)+SESSION_TTL;
 const n=new Uint8Array(16);crypto.getRandomValues(n);const nonce=b64(n);
 const tag=await sign(cfg.s,[exp,nonce,host,"outside"].join("|"));
 return exp+"."+nonce+"."+tag;
}
function distance(a,b,c,d){const r=Math.PI/180,dy=(c-a)*r,dx=(d-b)*r,z=Math.sin(dy/2)**2+Math.cos(a*r)*Math.cos(c*r)*Math.sin(dx/2)**2;return 6371000*2*Math.asin(Math.min(1,Math.sqrt(z)))}
function sameOrigin(req,url){const o=req.headers.get("Origin"),site=req.headers.get("Sec-Fetch-Site");return o===url.origin&&(!site||site==="same-origin")}
async function verify(req,url,cfg,env,ctx,requestId){
 if(req.method!=="POST")return reply(405,{error:"METHOD_NOT_ALLOWED"});
 if(!sameOrigin(req,url))return reply(403,{error:"ORIGIN_NOT_ALLOWED"});
 if(!req.headers.get("Content-Type")?.toLowerCase().startsWith("application/json"))return reply(415,{error:"JSON_REQUIRED"});
 if(Number(req.headers.get("Content-Length")||0)>1024)return reply(413,{error:"REQUEST_TOO_LARGE"});
 let data;try{const raw=await req.text();if(raw.length>1024)return reply(413,{error:"REQUEST_TOO_LARGE"});data=JSON.parse(raw)}catch{return reply(400,{error:"INVALID_JSON"})}
 const {lat,lon,accuracy}=data||{};
 const recheckDocument=env?.GPS_RECHECK_EVERY_DOCUMENT==="true";
 if(recheckDocument&&(typeof env?.CONSENT_KV?.get!=="function"||
    typeof env?.CONSENT_KV?.put!=="function"))
  return reply(503,{error:"GPS_NAVIGATION_STATE_UNAVAILABLE"});
 // This is the destination of the original document, NOT an arbitrary URL.
 const requestedPath=typeof data?.returnPath==="string"?
    data.returnPath:"/";
 const targetPath=(()=>{try{
    if(!requestedPath.startsWith("/")||requestedPath.startsWith("//")||
       requestedPath.length>400)return null;
    return cleanVisitPath(new URL(url.origin+requestedPath));
   }catch{return null}})();
 if(recheckDocument&&!targetPath)return reply(400,{error:"INVALID_RETURN_PATH"});
 if([lat,lon,accuracy].some(x=>typeof x!=="number"||!Number.isFinite(x))||Math.abs(lat)>90||Math.abs(lon)>180||accuracy<=0||accuracy>MAX_GPS_ACCURACY_METERS)return reply(422,{error:"PRECISE_LOCATION_UNAVAILABLE"});
 // Polygon assessment is intentionally side-effect free: no persistence,
 // response field or analytics carries exact GPS coordinates or shadow verdict.
 let verdict;
 if(cfg.polygonMode==="enforce"){
  verdict=decideCampusPolygons(cfg.polygons,lat,lon,accuracy,cfg.bufferMeters);
  if(verdict==="INVALID")return reply(503,{error:"GPS_POLYGON_CONFIGURATION_UNAVAILABLE"});
 }else{
  if(cfg.polygonMode==="shadow")void decideCampusPolygons(cfg.polygons,lat,lon,accuracy);
  // Existing circle decisions remain completely unchanged for shadow mode.
  const circles=cfg.campuses.map(c=>({distance:distance(lat,lon,c.lat,c.lon),
   radius:c.radius}));
  verdict=circles.some(c=>Math.abs(c.distance-c.radius)<=accuracy)?"UNCERTAIN":
   circles.some(c=>c.distance+accuracy<c.radius)?"INSIDE":"OUTSIDE";
 }
 if(verdict==="INSIDE_UNCERTAIN"){
  // A point mapped inside the OSM campus, but close to the approximate
  // boundary, is not sufficiently reliable to assert definitive INSIDE.
  // Require a new GPS fix (403); NEVER mint a near-boundary allow token.
  const headers=new Headers(head);
  headers.set("Content-Type","application/json; charset=utf-8");
  if(getCookie(req,SESSION_COOKIE))
   headers.append("Set-Cookie",policyCookie(SESSION_COOKIE,"",0));
  if(getCookie(req,BLOCK_COOKIE))
   headers.append("Set-Cookie",policyCookie(BLOCK_COOKIE,"",0));
  scheduleGpsDenialAlert({env,request:req,url,event:"CAMPUS_BOUNDARY_UNCERTAIN",ctx,requestId});
  return new Response(JSON.stringify({
   error:"CAMPUS_BOUNDARY_UNCERTAIN",blocked:true,retryable:true
  }),{status:403,headers});
 }
 if(verdict==="UNCERTAIN"){
  // A GPS location OUTSIDE the approximate campus border may receive a
  // short 5-minute access token; a point reported INSIDE never may.
  // Coarse fixes (over 100m) may allow access only when the full reported
  // uncertainty area is outside every campus buffer. The existing 5-minute
  // near-boundary concession remains limited to genuinely precise readings.
  if(cfg.polygonMode!=="enforce"||accuracy>100)
   return reply(403,{error:"LOCATION_UNCERTAIN",blocked:true,retryable:true});
  const headers=new Headers(head);
  headers.set("Content-Type","application/json; charset=utf-8");
  headers.append("Set-Cookie",policyCookie(SESSION_COOKIE,await verdictToken(cfg,url.hostname,"nearby"),300));
  if(recheckDocument&&url.hostname===GPS_BRIDGE_HUB)
   headers.append("Set-Cookie",policyCookie(FRESH_BRIDGE_COOKIE,await mintFreshBridge(cfg,url.hostname),NAV_PROOF_TTL));
  headers.append("Set-Cookie",policyCookie(BLOCK_COOKIE,"",0));
  const proof=recheckDocument?await visitProof(cfg,url.hostname,targetPath):null;
  return new Response(JSON.stringify({verified:false,nearBoundary:true,classification:"near_outside",expiresInSeconds:300,
   ...(proof?{navigationTicket:proof}:{})}),{status:200,headers});
 }
 if(verdict==="INSIDE"){
  // Never mint or inject a restriction/allow credential after an INSIDE verdict.
  // Expire any previously granted outside/nearby cookie on this hostname so
  // a visitor cannot simply reload with the older authorization.
  const headers=new Headers(head);
  headers.set("Content-Type","application/json; charset=utf-8");
  if(getCookie(req,SESSION_COOKIE))headers.append("Set-Cookie",policyCookie(SESSION_COOKIE,"",0));
  if(getCookie(req,BLOCK_COOKIE))headers.append("Set-Cookie",policyCookie(BLOCK_COOKIE,"",0));
  scheduleGpsDenialAlert({env,request:req,url,event:"CAMPUS_RESTRICTED",ctx,requestId});
  return new Response(JSON.stringify({error:"CAMPUS_RESTRICTED"}),{status:403,headers});
 }
 const headers=new Headers(head);
 headers.set("Content-Type","application/json; charset=utf-8");
 headers.append("Set-Cookie",policyCookie(SESSION_COOKIE,await verdictToken(cfg,url.hostname,"outside")));
 if(recheckDocument&&url.hostname===GPS_BRIDGE_HUB)
  headers.append("Set-Cookie",policyCookie(FRESH_BRIDGE_COOKIE,await mintFreshBridge(cfg,url.hostname),NAV_PROOF_TTL));
 headers.append("Set-Cookie",policyCookie(BLOCK_COOKIE,"",0));
 const proof=recheckDocument?await visitProof(cfg,url.hostname,targetPath):null;
 return new Response(JSON.stringify({verified:true,classification:"outside",expiresInSeconds:SESSION_TTL,
    ...(proof?{navigationTicket:proof}:{})}),{
   status:200,headers
 });
}
function page(){return new Response(GEO_HTML,{status:403,headers:{...head,"Content-Type":"text/html; charset=utf-8","X-Frame-Options":"DENY","Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"}})}
function disclaimerPage(){
 return new Response(DISCLAIMER_HTML,{status:200,headers:{...head,"Content-Type":"text/html; charset=utf-8",
  "X-Frame-Options":"DENY",
  "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"}});
}
function blockedPage(){
 const visible=GEO_HTML.replace('<section id="prompt">','<section id="prompt" hidden>')
  .replace('<section id="blocked" hidden>','<section id="blocked">')
  .replace('<p class="notice-error" id="reason" role="alert">Location permission unavailable</p>',
    '<p class="notice-error" id="reason" role="alert">Your last location fell within a restricted area. Please retry verification; protected content remains unavailable until the check passes.</p>');
 return new Response(visible,{status:403,headers:{...head,"Content-Type":"text/html; charset=utf-8",
   "X-Frame-Options":"DENY",
   "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"}});
}
function unavailablePage(){
 const visible=GEO_HTML.replace('<section id="prompt">','<section id="prompt" hidden>')
  .replace('<section id="blocked" hidden>','<section id="blocked">')
  .replace('<p class="notice-error" id="reason" role="alert">Location permission unavailable</p>',
    '<p class="notice-error" id="reason" role="alert">Location verification is temporarily unavailable. Protected content cannot be accessed until service is restored.</p>');
 return new Response(visible,{status:503,headers:{...head,
   "Content-Type":"text/html; charset=utf-8",
   "X-Frame-Options":"DENY",
   "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"}});
}
function script(){return new Response(GEO_CLIENT,{status:200,headers:{...head,"Content-Type":"application/javascript; charset=utf-8"}})}
// The personal /jingxin story is public. GPS gating applies to protected
// photo resources, never the HTML story itself or its public text.
function jingxinPublicPage(path){
 return path==="/jingxin"||path==="/jingxin/"||path==="/jingxin.html";
}
// Vite emits immutable, content-fingerprinted CSS/JS/font files. They are
// public build artifacts, not authorization-bearing pages or private data.
// Protect all documents, APIs and media even if names look like hashes.
function publicBuildAsset(request,path){
 return (request.method==="GET"||request.method==="HEAD")&&
  /^\/assets\/[A-Za-z0-9][A-Za-z0-9._-]*-[A-Za-z0-9_-]{8,}\.(?:css|js|mjs|woff|woff2|ttf|otf)$/.test(path);
}
// Only published, anonymous informational pages on the Vynalth AI main
// origin are exempt from this website's interactive GPS consent challenge.
// This does NOT bypass Cloudflare WAF, signed sessions, School IP Policy,
// temporary IP denies, or any authenticated/private endpoint.
const PUBLIC_APEX_INFORMATION_ROUTES = new Set([
  '', 'legal', 'product', 'security/trust-center',
  'legal/privacy', 'legal/biometric-data-notice', 'legal/terms',
  'legal/cookies', 'legal/medical-disclaimer', 'legal/data-handling',
  'legal/sub-processors', 'legal/dpa', 'legal/contact',
  'legal/security', 'legal/acceptable-use', 'legal/ai-disclaimer',
  'legal/abuse-policy', 'legal/account-blocking', 'legal/policy-framework',
  'legal/vulnerability-disclosure', 'legal/bug-bounty',
  'legal/appeals-and-complaints', 'legal/intellectual-property',
  'legal/children-privacy', 'legal/open-source', 'legal/transparency'
]);
const PUBLIC_APEX_INFORMATION_PATHS = new Set(['/']);
for (const route of PUBLIC_APEX_INFORMATION_ROUTES) {
  if (route) PUBLIC_APEX_INFORMATION_PATHS.add('/' + route);
  for (const lang of ['en', 'cn', 'ms']) {
    const fullPath = '/' + lang + (route ? '/' + route : '');
    PUBLIC_APEX_INFORMATION_PATHS.add(fullPath);
    if (!route) PUBLIC_APEX_INFORMATION_PATHS.add(fullPath + '/');
  }
}
function publicBrandingPage(path,request,hostname){
  if (!['vynalthai.com','www.vynalthai.com'].includes(hostname.toLowerCase()))
    return false;
  if (request.method !== 'GET' && request.method !== 'HEAD') return false;
  return PUBLIC_APEX_INFORMATION_PATHS.has(path);
}
function skip(path,request,hostname){return publicBrandingPage(path,request,hostname)||publicBuildAsset(request,path)||jingxinPublicPage(path)||path.startsWith("/.well-known/")||path.startsWith("/api/auth/")||path.startsWith("/auth/")||path.startsWith("/api/oauth/")||path.startsWith("/api/webhooks/")||path==="/robots.txt"||path==="/favicon.ico"||path==="/sitemap.xml"||
 path==="/en/legal/privacy"||path==="/legal/privacy"||path==="/__shield/campus-beacon"}
export async function guestGpsGate(request,env,url,ctx=null,requestId=null,verifiedCountry=null){
 if(url.pathname==="/__shield/gps/disclaimer"&&request.method==="GET")return disclaimerPage();
 if(url.pathname==="/__shield/gps/verify-info"&&request.method==="GET"){
  return reply(200,{purpose:"campus geofence validation",locationPermission:"visitor-controlled",
    exemptAccountStatuses:["trust","contact","status"],preciseCoordinatesStoredInCookie:false,
    crossDomainCookieReading:false,defaultEnabled:false});
 }

 if(env?.GPS_GATE_ENABLED!=="true")return null;
 const cfg=config(env);
 // An explicitly enabled GPS gate must never quietly become permissive
 // because a signing key or geofence config was missing or malformed.
 if(!cfg&&!skip(url.pathname,request,url.hostname)){
  // Do not allow origin traffic when the GPS signing secret or boundary
  // configuration is invalid. All optional legal/recovery routes remain open.
  console.error("GPS_GATE_CONFIGURATION_UNAVAILABLE: protected access denied");
  if(url.pathname==="/__shield/gps/status")
   return reply(503,{enabled:true,configurationAvailable:false,
     enforcing:false,policyRevision:GPS_POLICY_REVISION,error:"GPS_GATE_CONFIGURATION_UNAVAILABLE"});
  if(isBrowserDocument(request)&&!url.pathname.startsWith("/__shield/gps/"))
   return unavailablePage();
  return reply(503,{error:"GPS_GATE_CONFIGURATION_UNAVAILABLE",blocked:true});
 }
 if(!cfg)return null;
 if(url.pathname==="/__shield/gps/region-check"||
    url.pathname==="/__shield/gps/region-client.js"){
  const region=await gpsRegionalDecision(request,env,url,verifiedCountry);
  return region.response||reply(404,{error:"REGIONAL_CHECK_NOT_NEEDED"});
 }
 if(url.pathname==="/__shield/gps/recheck"){
  if(request.method!=="GET"||url.hostname!==GPS_BRIDGE_HUB)
   return reply(404,{error:"NOT_FOUND"});
  const targetHost=url.searchParams.get("host");
  const returnPath=url.searchParams.get("return"),state=url.searchParams.get("state");
  if(!allowedTarget(targetHost)||!safeRelativePath(returnPath)||!validState(state))
   return reply(400,{error:"INVALID_RECHECK_DESTINATION"});
  return page(); // Always offer a new explicit geolocation attempt.
 }
 if(url.pathname==="/__shield/gps/link"){
  if(request.method!=="GET"||!allowedTarget(url.hostname))return reply(404,{error:"NOT_FOUND"});
  const returnPath=url.searchParams.get("return");
  if(!safeRelativePath(returnPath))return reply(400,{error:"INVALID_RETURN_PATH"});
  const next=new URL(url.toString());next.pathname=returnPath;
  return beginHandoff(next,env?.GPS_RECHECK_EVERY_DOCUMENT==="true"||url.searchParams.get("recheck")==="1");
 }
 if(url.pathname==="/__shield/gps/bridge")return bridge(request,url,cfg,env);
 if(url.pathname==="/__shield/gps/import")return importHandoff(request,url,cfg,env);
 if(url.pathname==="/__shield/gps/client.js"&&request.method==="GET")return script();
 if(url.pathname==="/__shield/gps/verify")return verify(request,url,cfg,env,ctx,requestId);
 if(url.pathname==="/__shield/gps/status"&&request.method==="GET")
  return reply(200,{enabled:true,configurationAvailable:true,enforcing:true,
   telegramAlerts:telegramGpsStatus(env),
   gpsServiceBinding:{configured:typeof env?.GPS_SERVICE_AUTH_SECRET==="string"&&
    env.GPS_SERVICE_AUTH_SECRET.length>=32},
   regionalPolicy:{enabled:env?.GPS_REGION_TIMEZONE_ENABLED==="true",
    malaysiaIpOrTimezone:true,vpnDetection:"not-guaranteed"},
   policyRevision:GPS_POLICY_REVISION,
   verified:await permitted(request,cfg,url.hostname),
   exempt:await exempt(request,cfg,url.hostname)});
 if(skip(url.pathname,request,url.hostname))return null;
 // Existing trusted server-verified account states bypass this GPS policy.
 if(await exempt(request,cfg,url.hostname))return null;
 if(await hasBlockVerdict(request,cfg,url.hostname))return blockedPage();
 // Foreign IP: signed short-lived browser-timezone preflight.
 // A MY/unknown IP never qualifies for a GPS bypass.
 const region=await gpsRegionalDecision(request,env,url,verifiedCountry);
 if(region.response)return region.response;
 if(region.skipGPS)return null;
 // A genuinely OUTSIDE verdict is backed by a host-bound HMAC cookie that
 // expires within 15 minutes. Reuse it for HTML documents only when the site
 // operator explicitly enables fast-pass. IP city/country alone never grants
 // this exemption; near-boundary, inside, expired and forged cookies do not.
 // The independent school-IP policy and WAF still run in src/index.js.
 if(env?.GPS_OUTSIDE_SESSION_FASTPASS==="true"&&
    await sessionVerdict(request,cfg,url.hostname)==="outside")return null;
 // Without a verified outside session, full document navigation requires
 // a fresh browser GPS read. One-visit navigation proofs remain enforced.
 if(env?.GPS_RECHECK_EVERY_DOCUMENT==="true"&&isBrowserDocument(request)){
  if(await consumeVisitProof(request,env,cfg,url))return null;
  if(url.hostname!==GPS_BRIDGE_HUB&&allowedTarget(url.hostname))
   return beginHandoff(url,true);
  return page();
 }
 if(await permitted(request,cfg,url.hostname))return null;

 // Anonymous visitors also synchronize. Browser visits other registrable
 // domains via a top-level redirect to the consented first-party hub. The
 // browser does not read vynalthai.com cookies from the target origin.
 // A missing hub verdict shows its normal GPS challenge or 403 denial.
 if(url.hostname!==GPS_BRIDGE_HUB&&allowedTarget(url.hostname)&&isBrowserDocument(request)){
  return beginHandoff(url);
 }
 const accept=request.headers.get("Accept")||"";
 if(request.method!=="GET"||(!accept.includes("text/html")&&accept.includes("application/json")))
  return reply(403,{error:"PRECISE_GPS_REQUIRED",blocked:true});
 return page();
}
