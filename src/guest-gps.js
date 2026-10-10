const GEO_HTML="<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>Vynalth Shield · Location Verification</title><style>:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#04060a;color:#eef5ff}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:20px;box-sizing:border-box;background:radial-gradient(circle at 15% 15%,#1a2c4b,#04060a 60%)}main{max-width:540px;background:#0d1626;border:1px solid #33455f;border-radius:22px;padding:32px;box-shadow:0 25px 60px #0009}.brand{font-size:13px;font-weight:850;letter-spacing:.1em;color:#a1ceff}h1{font-size:clamp(29px,5vw,39px);line-height:1.15}p{line-height:1.65;color:#becfe7;font-size:14px}button{background:#94c9ff;border:0;border-radius:10px;padding:15px 20px;width:100%;font-weight:800;cursor:pointer;margin-top:16px}button:disabled{opacity:.5}.warning{border:1px solid #496b90;background:#14283f;padding:14px;border-radius:12px;color:#c8dcf4;font-size:13px;line-height:1.7}.error{border-color:#9b5062;background:#351b28;color:#ffcad8}.meta{color:#90a7c5;font-size:12px}#status{margin-top:12px}a{color:#a1ceff}[hidden]{display:none!important}</style><script src=\"/__shield/gps/client.js\" defer></script></head><body><main><div class=\"brand\">✦ VYNALTH SHIELD</div><section id=\"prompt\"><h1>位置验证 · Location required</h1><p>访客必须主动允许浏览器请求精确位置，才可继续访问。拒绝授权则无法继续使用本站，但不会永久封锁账号。</p><p lang=\"ms\">Pelawat perlu memberi kebenaran lokasi tepat untuk meneruskan. Jika ditolak, akses laman tidak tersedia.</p><p lang=\"en\">Guests must explicitly grant precise location access to proceed. Refusing keeps this site unavailable, without banning an account.</p><div class=\"warning\">仅在你点击后请求浏览器权限。位置坐标通过 HTTPS 发给本站，仅用于这一次位置判断；不写入 Cookie、KV 或永久日志。定位不保证一定准确。已由服务器验证为 trust、contact 或 status 的账号不需要此验证。</div><button id=\"start\">允许位置并验证 · Verify location</button></section><section id=\"blocked\" hidden><h1>访问已限制 · Access blocked</h1><p class=\"warning error\" id=\"reason\">Location permission unavailable</p><p>可在浏览器网站权限中允许定位后重新尝试。也可以选择不提供位置并离开网站。</p><p lang=\"en\">Change the site's location permission in your browser settings to retry, or leave without sharing your position.</p><button id=\"retry\">重新尝试 · Retry</button></section><p class=\"meta\" id=\"status\" role=\"status\" aria-live=\"polite\"></p><p class=\"meta\"><p class=\"meta\" id=\"syncHint\" hidden>如果你已经在 Vynalth AI 主站完成验证，可手动同步签名状态（不会传送精确 GPS 坐标）。</p><p class=\"meta\"><a id=\"syncLink\" href=\"#\" hidden>🔗 使用其他 Vynalth AI 网站的验证结果</a></p><a href=\"/__shield/gps/disclaimer\" id=\"disclaimerLink\">声明 / Penafian / Disclaimer 🔗</a> · <a href=\"https://vynalthai.com/en/legal/privacy\" rel=\"noopener noreferrer\" referrerpolicy=\"no-referrer\">Privacy Policy</a></p><p class=\"meta\">Independent Vynalth AI policy · Not an official POWIIS service.</p></main></body></html>";
const GEO_CLIENT="\"use strict\";const $=id=>document.getElementById(id);function blocked(text){$(\"prompt\").hidden=true;$(\"blocked\").hidden=false;$(\"reason\").textContent=text;$(\"status\").textContent=\"\";$(\"start\").disabled=false}function run(){\n const currentHost=location.hostname.toLowerCase();\n const isOutsideHub=currentHost!==\"vynalthai.com\" &&\n [\"vynalthai.com\",\"vyncuslim.com\",\"vynalthai.si\",\"vyncuslim.si\",\n \"vitamindai.online\",\"sleepsomno.com\",\"powiismunc.com\"]\n .some(root=>currentHost===root||currentHost.endsWith(\".\"+root));\n if(isOutsideHub){\n  const path=location.pathname.startsWith(\"/__shield/gps/\")?\"/\":location.pathname;\n  location.assign(\"/__shield/gps/link?recheck=1&return=\"+encodeURIComponent(path));\n  return;\n }\n $(\"blocked\").hidden=true;$(\"prompt\").hidden=false;const b=$(\"start\");b.disabled=true;$(\"status\").textContent=\"请求浏览器位置授权…\";if(!navigator.geolocation){blocked(\"此设备或浏览器不提供定位服务。\");return}navigator.geolocation.getCurrentPosition(async p=>{const c=p.coords;if(!(Number.isFinite(c.accuracy)&&c.accuracy<=100)){blocked(\"位置精度不足（要求 100 米以内）。\");return}$(\"status\").textContent=\"正在验证位置…\";try{const res=await fetch(\"/__shield/gps/verify\",{method:\"POST\",credentials:\"same-origin\",cache:\"no-store\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({lat:c.latitude,lon:c.longitude,accuracy:c.accuracy})});const data=await res.json();if(!res.ok){blocked(data.error===\"CAMPUS_RESTRICTED\"?\"当前位置位于配置的校园限制区域内，访问已限制。\":\"位置验证失败：\"+(data.error||res.status));return}if(location.pathname===\"/__shield/gps/recheck\"){\n  const dest=new URL(location.href);dest.pathname=\"/__shield/gps/bridge\";\n  location.replace(dest.toString());\n }else location.reload()}catch{blocked(\"无法连接位置验证服务。\")}},err=>{blocked(err.code===1?\"GPS 授权被拒绝：无法继续使用本站。\":err.code===2?\"无法取得位置：无法继续使用本站。\":\"GPS 定位超时或不准确。\")},{enableHighAccuracy:true,timeout:15000,maximumAge:0})}$(\"start\").onclick=run;$(\"retry\").onclick=run;\n(function(){\n const validHosts=new Set([\"vyncuslim.com\",\"vynalthai.si\",\"vyncuslim.si\",\n  \"vitamindai.online\",\"sleepsomno.com\",\"powiismunc.com\"]);\n if(!validHosts.has(location.hostname))return;\n const hint=document.getElementById(\"syncHint\"),link=document.getElementById(\"syncLink\");\n if(!hint||!link)return;\n link.href=\"/__shield/gps/link?return=\"+encodeURIComponent(location.pathname);\n hint.hidden=false;link.hidden=false;\n})();\n";
const DISCLAIMER_HTML="<!doctype html>\n<html lang=\"zh-CN\">\n<head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<meta name=\"robots\" content=\"noindex,nofollow\"><meta name=\"referrer\" content=\"no-referrer\">\n<title>GPS Verification Disclaimer · Vynalth Shield</title>\n<style>\n:root{color-scheme:dark;font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:#eaf1fc;background:#05070e}\nbody{padding:28px 17px;margin:0;background:radial-gradient(circle at 20% 0,#172840,transparent 60%),#05070e}\nmain{margin:auto;max-width:780px;background:#101827;border:1px solid #364563;border-radius:21px;padding:clamp(24px,4vw,42px)}\nheader{color:#98c8ff;font-size:12px;font-weight:800;letter-spacing:.1em}\nh1{font-size:clamp(30px,5vw,42px);margin:16px 0}\nh2{font-size:18px;color:#d6e7ff;margin:26px 0 10px}\np,li{color:#bbcbdf;line-height:1.8;font-size:14px}\na{color:#9cceff}aside{padding:14px;border:1px solid #465b81;border-radius:12px;background:#192b44}\n</style></head>\n<body><main><header>✦ VYNALTH SHIELD · LOCATION POLICY</header>\n<h1>声明 · Penafian · Disclaimer</h1>\n<aside>\n<strong>独立网站政策 / Dasar laman bebas / Independent website policy</strong>\n<p>此功能由 Vynalth AI 网站运营者提供，不属于 POWIIS 校方官方定位或访问系统。</p>\n<p>Fungsi ini bukan perkhidmatan rasmi POWIIS.</p>\n<p>This location requirement is not operated or endorsed by POWIIS.</p>\n</aside>\n<h2>1. 为什么请求位置 / Tujuan / Purpose</h2>\n<p>网页仅在访客点击授权按钮、并同意浏览器的位置权限后才请求地理位置，用于判断设备报告的位置是否位于网站运营者设置的校园地理围栏之内。精确位置并不能可靠证明某人的学校身份、账号身份或当前网络。</p>\n<p>Lokasi hanya diminta selepas persetujuan melalui pelayar, bagi semakan kawasan geografi. Lokasi bukan bukti identiti.</p>\n<p>After browser permission, the reported position is checked against an operator-defined campus area. Browser location can be inaccurate or spoofed.</p>\n<h2>2. 不提供位置 / Jika menolak / If you decline</h2>\n<p>访客可以拒绝授权，但启用此功能的网站可能因此不允许继续访问并展示访问限制页面。拒绝授权本身不会导致永久账号封锁。你可以修改浏览器权限后重新尝试。</p>\n<p>Anda boleh menolak; akses tetamu mungkin dihadkan, tetapi akaun tidak diharamkan secara kekal hanya kerana penolakan.</p>\n<p>You may refuse location access. When the gate is enabled, guest access may be restricted, but refusing does not permanently ban your account.</p>\n<h2>3. Cookie 与数据 / Kuki dan data / Cookies and data</h2>\n<p>验证时通过 HTTPS 将报告的经纬度及精度传送至本站 Worker，本功能不主动将精确 GPS 坐标写入 Cookie 或 KV。成功通过验证或处于限制区域时，本站可设置最长约 15 分钟、仅对本站有效的签名状态 Cookie。浏览器可在设置中删除 Cookie；各独立根域名无法直接读取其他域的 Cookie。</p>\n<p>Koordinat digunakan untuk keputusan permintaan sahaja dan tidak disimpan dalam kuki. Kuki status sementara terikat pada domain sendiri.</p>\n<p>Precise coordinates are used for the current verification and are not intentionally stored in persistent application data by this feature. Short-lived signed status cookies do not contain GPS coordinates. Standard server/network logs and browser behavior are governed by their own policies.</p>\n<h2>4. 豁免和错误 / Pengecualian dan ralat / Exemptions and mistakes</h2>\n<p>由服务器身份验证并确认状态为 <strong>trust</strong> 或 <strong>contact</strong> 的账号可豁免此项 GPS 检查。浏览器自身声明并不构成有效凭证。如判断有误、设备无法定位、位于边界或需要访问帮助，请联系网站管理员；可要求人工复核与删除相关记录。</p>\n<p>Status akaun trust/contact mesti disahkan oleh pelayan. Untuk semakan atau pemadaman, hubungi pentadbir laman.</p>\n<p>Authenticated trust/contact accounts are exempt once the website validates their status server-side. Contact the website operator to dispute a decision or request applicable data deletion.</p>\n<h2>5. 儿童及未成年人 / Pengguna bawah umur / Minors</h2>\n<p>学校访客可能包括未成年人。请勿在未经适当授权的情况下提交他人位置，亦不要通过其他设备代替他人授权。网站不会因为一次位置报告而永久封锁账号。</p>\n<p>Jangan kongsi lokasi orang lain tanpa persetujuan yang sewajarnya.</p>\n<p>Do not submit someone else's location without appropriate permission. This feature must be reviewed for applicable privacy requirements before production activation.</p>\n<p><a href=\"https://vynalthai.com/en/legal/privacy\" rel=\"noopener noreferrer\" referrerpolicy=\"no-referrer\">Vynalth AI Privacy Policy</a></p>\n<p><a href=\"/__shield/gps/verify-info\">查看位置验证信息 / View verification information</a></p>\n</main></body></html>";
const SESSION_COOKIE="__Host-vynalth-geo";
const STATUS_COOKIE="__Host-vynalth-status";
const BLOCK_COOKIE="__Host-vynalth-geo-block";
const HANDOFF_STATE_COOKIE="__Host-vynalth-geo-handoff";
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
const enc=new TextEncoder();
const head={"Cache-Control":"private, no-store, max-age=0","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Robots-Tag":"noindex,nofollow","Vary":"Cookie","Permissions-Policy":"geolocation=(self)"};
const reply=(status,data,extra={})=>new Response(JSON.stringify(data),{status,headers:{...head,"Content-Type":"application/json; charset=utf-8",...extra}});
function b64(bytes){let s="";for(const b of bytes)s+=String.fromCharCode(b);return btoa(s).replaceAll("+","-").replaceAll("/","_").replace(/=+$/g,"");}
function ub64(s){if(!/^[a-zA-Z0-9_-]{40,90}$/.test(s||""))return null;try{let x=s.replace(/-/g,"+").replace(/_/g,"/");return Uint8Array.from(atob(x+"=".repeat((4-x.length%4)%4)),v=>v.charCodeAt(0));}catch{return null}}
async function hkey(key){return crypto.subtle.importKey("raw",enc.encode(key),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"])}
async function sign(key,msg){return b64(new Uint8Array(await crypto.subtle.sign("HMAC",await hkey(key),enc.encode(msg))))}
async function valid(key,msg,tag){const signature=ub64(tag);return !!signature&&signature.length===32&&await crypto.subtle.verify("HMAC",await hkey(key),signature,enc.encode(msg))}
function getCookie(req,name){const x=(req.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(name+"="));return x?x.slice(name.length+1):null}
function config(env){
 if(env?.GPS_GATE_ENABLED!=="true")return null;
 const {GPS_GATE_SESSION_SECRET:s,GPS_ACCOUNT_STATUS_SECRET:a}=env||{};
 const lat=Number(env?.GPS_CAMPUS_LAT),lon=Number(env?.GPS_CAMPUS_LON),radius=Number(env?.GPS_CAMPUS_RADIUS_METERS);
 if(typeof s!=="string"||s.length<32||typeof a!=="string"||a.length<32||!Number.isFinite(lat)||!Number.isFinite(lon)||!Number.isFinite(radius)||Math.abs(lat)>90||Math.abs(lon)>180||radius<50||radius>1000)return null;
 return {s,a,lat,lon,radius}
}
async function exempt(req,cfg,host){
 // Only the trusted application's server can mint a valid signed status cookie.
 // Format: exp.status.nonce.signature. Signature covers the originating host.
 const value=getCookie(req,STATUS_COOKIE);if(!value||value.length>320)return false;
 const parts=value.split(".");if(parts.length!==4)return false;
 const [exp,status,nonce,tag]=parts;
 if(status!=="trust"&&status!=="contact"&&status!=="status")return false;
 if(!/^\d{10,12}$/.test(exp)||!/^[a-zA-Z0-9_-]{22}$/.test(nonce))return false;
 const now=Math.floor(Date.now()/1000),ttl=Number(exp);
 if(ttl<=now||ttl>now+3600)return false;
 return valid(cfg.a,[exp,status,nonce,host].join("|"),tag);
}
async function permitted(req,cfg,host){
 const value=getCookie(req,SESSION_COOKIE);if(!value||value.length>320)return false;
 const parts=value.split(".");if(parts.length!==3)return false;
 const [exp,nonce,tag]=parts;
 if(!/^\d{10,12}$/.test(exp)||!/^[a-zA-Z0-9_-]{22}$/.test(nonce))return false;
 const now=Math.floor(Date.now()/1000),time=Number(exp);
 if(time<=now||time>now+SESSION_TTL)return false;
 return valid(cfg.s,[exp,nonce,host,"outside"].join("|"),tag);
}

function policyCookie(name,value,age=SESSION_TTL){
 return name+"="+value+"; Secure; HttpOnly; SameSite=Lax; Path=/; Max-Age="+age;
}
async function verdictToken(cfg,host,verdict){
 if(verdict!=="inside"&&verdict!=="outside")throw Error("Invalid verdict");
 const expiry=Math.floor(Date.now()/1000)+SESSION_TTL;
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
function safeRelativePath(path){
 return typeof path==="string"&&path.length<=300&&path.startsWith("/")&&
   !path.startsWith("//")&&!path.includes("\\")&&!/[\r\n]/.test(path)&&
   !path.startsWith("/__shield/gps/");
}
function validState(v){return typeof v==="string"&&/^[A-Za-z0-9_-]{32}$/.test(v)}
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
 if(verdict!=="inside"&&verdict!=="outside")return null;
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
async function bridge(request,url,cfg){
 if(request.method!=="GET"||url.hostname!==GPS_BRIDGE_HUB)
   return reply(404,{error:"NOT_FOUND"});
 const target=url.searchParams.get("host");
 const path=url.searchParams.get("return"),state=url.searchParams.get("state");
 if(!allowedTarget(target)||!safeRelativePath(path)||!validState(state))
   return reply(400,{error:"INVALID_BRIDGE_DESTINATION"});
 let verdict=null;
 if(await hasBlockVerdict(request,cfg,url.hostname))verdict="inside";
 else if(await permitted(request,cfg,url.hostname))verdict="outside";
 if(!verdict)return page(); // First-party hub asks for browser GPS; NO login needed.
 const ticket=await handoffToken(cfg,target,path,state,verdict);
 const destination=new URL("https://"+target+"/__shield/gps/import");
 destination.searchParams.set("ticket",ticket);
 destination.searchParams.set("return",path);
 destination.searchParams.set("state",state);
 return redirect(destination.toString(),{"Referrer-Policy":"no-referrer"});
}
async function importHandoff(request,url,cfg){
 if(request.method!=="GET"||!allowedTarget(url.hostname))
   return reply(404,{error:"NOT_FOUND"});
 const path=url.searchParams.get("return"),state=url.searchParams.get("state");
 if(!safeRelativePath(path)||!validState(state))return reply(400,{error:"INVALID_RETURN_PATH"});
 if(getCookie(request,HANDOFF_STATE_COOKIE)!==state)return reply(403,{error:"HANDOFF_STATE_MISMATCH"});
 const verdict=await validateHandoff(cfg,url.hostname,path,state,url.searchParams.get("ticket"));
 if(!verdict)return reply(403,{error:"INVALID_OR_EXPIRED_HANDOFF"});
 const name=verdict==="inside"?BLOCK_COOKIE:SESSION_COOKIE;
 const old=verdict==="inside"?SESSION_COOKIE:BLOCK_COOKIE;
 const value=await verdictToken(cfg,url.hostname,verdict);
 const headers=new Headers(head);
 headers.set("Location",path);
 headers.append("Set-Cookie",policyCookie(name,value));
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
async function verify(req,url,cfg){
 if(req.method!=="POST")return reply(405,{error:"METHOD_NOT_ALLOWED"});
 if(!sameOrigin(req,url))return reply(403,{error:"ORIGIN_NOT_ALLOWED"});
 if(!req.headers.get("Content-Type")?.toLowerCase().startsWith("application/json"))return reply(415,{error:"JSON_REQUIRED"});
 if(Number(req.headers.get("Content-Length")||0)>256)return reply(413,{error:"REQUEST_TOO_LARGE"});
 let data;try{const raw=await req.text();if(raw.length>256)return reply(413,{error:"REQUEST_TOO_LARGE"});data=JSON.parse(raw)}catch{return reply(400,{error:"INVALID_JSON"})}
 const {lat,lon,accuracy}=data||{};
 if([lat,lon,accuracy].some(x=>typeof x!=="number"||!Number.isFinite(x))||Math.abs(lat)>90||Math.abs(lon)>180||accuracy<=0||accuracy>100)return reply(422,{error:"PRECISE_LOCATION_UNAVAILABLE"});
 const d=distance(lat,lon,cfg.lat,cfg.lon);
 if(Math.abs(d-cfg.radius)<=accuracy)return reply(403,{error:"LOCATION_UNCERTAIN"});
 if(d<=cfg.radius){
  const headers=new Headers(head);
  headers.set("Content-Type","application/json; charset=utf-8");
  headers.append("Set-Cookie",policyCookie(BLOCK_COOKIE,await verdictToken(cfg,url.hostname,"inside")));
  headers.append("Set-Cookie",policyCookie(SESSION_COOKIE,"",0));
  return new Response(JSON.stringify({error:"CAMPUS_RESTRICTED"}),{status:403,headers});
 }
 const headers=new Headers(head);
 headers.set("Content-Type","application/json; charset=utf-8");
 headers.append("Set-Cookie",policyCookie(SESSION_COOKIE,await verdictToken(cfg,url.hostname,"outside")));
 headers.append("Set-Cookie",policyCookie(BLOCK_COOKIE,"",0));
 return new Response(JSON.stringify({verified:true,expiresInSeconds:SESSION_TTL}),{
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
  .replace('<p class="warning error" id="reason">Location permission unavailable</p>',
    '<p class="warning error" id="reason">此连接最近报告的位置在校园限制区域内。访问暂时受限制。你可以重试定位。</p>');
 return new Response(visible,{status:403,headers:{...head,"Content-Type":"text/html; charset=utf-8",
   "X-Frame-Options":"DENY",
   "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"}});
}
function script(){return new Response(GEO_CLIENT,{status:200,headers:{...head,"Content-Type":"application/javascript; charset=utf-8"}})}
function skip(path){return path.startsWith("/.well-known/")||path.startsWith("/api/auth/")||path.startsWith("/auth/")||path.startsWith("/api/oauth/")||path.startsWith("/api/webhooks/")||path==="/robots.txt"||path==="/favicon.ico"||path==="/sitemap.xml"||
 path==="/en/legal/privacy"||path==="/legal/privacy"||path==="/__shield/campus-beacon"}
export async function guestGpsGate(request,env,url){
 if(url.pathname==="/__shield/gps/disclaimer"&&request.method==="GET")return disclaimerPage();
 if(url.pathname==="/__shield/gps/verify-info"&&request.method==="GET"){
  return reply(200,{purpose:"campus geofence validation",locationPermission:"visitor-controlled",
    exemptAccountStatuses:["trust","contact","status"],preciseCoordinatesStoredInCookie:false,
    crossDomainCookieReading:false,defaultEnabled:false});
 }

 const cfg=config(env);
 if(!cfg)return null; // disabled or misconfigured -> site works normally
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
  return beginHandoff(next,url.searchParams.get("recheck")==="1");
 }
 if(url.pathname==="/__shield/gps/bridge")return bridge(request,url,cfg);
 if(url.pathname==="/__shield/gps/import")return importHandoff(request,url,cfg);
 if(url.pathname==="/__shield/gps/client.js"&&request.method==="GET")return script();
 if(url.pathname==="/__shield/gps/verify")return verify(request,url,cfg);
 if(url.pathname==="/__shield/gps/status"&&request.method==="GET")
  return reply(200,{enabled:true,verified:await permitted(request,cfg,url.hostname),
   exempt:await exempt(request,cfg,url.hostname)});
 if(skip(url.pathname))return null;
 // Existing trusted server-verified account states bypass this GPS policy.
 if(await exempt(request,cfg,url.hostname))return null;
 if(await hasBlockVerdict(request,cfg,url.hostname))return blockedPage();
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
