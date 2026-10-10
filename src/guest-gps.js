const GEO_HTML="<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex,nofollow\"><title>Vynalth Shield · Location Verification</title><style>:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#04060a;color:#eef5ff}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:20px;box-sizing:border-box;background:radial-gradient(circle at 15% 15%,#1a2c4b,#04060a 60%)}main{max-width:540px;background:#0d1626;border:1px solid #33455f;border-radius:22px;padding:32px;box-shadow:0 25px 60px #0009}.brand{font-size:13px;font-weight:850;letter-spacing:.1em;color:#a1ceff}h1{font-size:clamp(29px,5vw,39px);line-height:1.15}p{line-height:1.65;color:#becfe7;font-size:14px}button{background:#94c9ff;border:0;border-radius:10px;padding:15px 20px;width:100%;font-weight:800;cursor:pointer;margin-top:16px}button:disabled{opacity:.5}.warning{border:1px solid #496b90;background:#14283f;padding:14px;border-radius:12px;color:#c8dcf4;font-size:13px;line-height:1.7}.error{border-color:#9b5062;background:#351b28;color:#ffcad8}.meta{color:#90a7c5;font-size:12px}#status{margin-top:12px}a{color:#a1ceff}[hidden]{display:none!important}</style><script src=\"/__shield/gps/client.js\" defer></script></head><body><main><div class=\"brand\">✦ VYNALTH SHIELD</div><section id=\"prompt\"><h1>位置验证 · Location required</h1><p>访客必须主动允许浏览器请求精确位置，才可继续访问。拒绝授权则无法继续使用本站，但不会永久封锁账号。</p><p lang=\"ms\">Pelawat perlu memberi kebenaran lokasi tepat untuk meneruskan. Jika ditolak, akses laman tidak tersedia.</p><p lang=\"en\">Guests must explicitly grant precise location access to proceed. Refusing keeps this site unavailable, without banning an account.</p><div class=\"warning\">仅在你点击后请求浏览器权限。位置坐标通过 HTTPS 发给本站，仅用于这一次位置判断；不写入 Cookie、KV 或永久日志。定位不保证一定准确。已由服务器验证为 trust 或 contact 的账号不需要此验证。</div><button id=\"start\">允许位置并验证 · Verify location</button></section><section id=\"blocked\" hidden><h1>访问已限制 · Access blocked</h1><p class=\"warning error\" id=\"reason\">Location permission unavailable</p><p>可在浏览器网站权限中允许定位后重新尝试。也可以选择不提供位置并离开网站。</p><p lang=\"en\">Change the site's location permission in your browser settings to retry, or leave without sharing your position.</p><button id=\"retry\">重新尝试 · Retry</button></section><p class=\"meta\" id=\"status\" role=\"status\" aria-live=\"polite\"></p><p class=\"meta\">Independent Vynalth AI policy · Not an official POWIIS service.</p></main></body></html>";
const GEO_CLIENT="\"use strict\";const $=id=>document.getElementById(id);function blocked(text){$(\"prompt\").hidden=true;$(\"blocked\").hidden=false;$(\"reason\").textContent=text;$(\"status\").textContent=\"\";$(\"start\").disabled=false}function run(){$(\"blocked\").hidden=true;$(\"prompt\").hidden=false;const b=$(\"start\");b.disabled=true;$(\"status\").textContent=\"请求浏览器位置授权…\";if(!navigator.geolocation){blocked(\"此设备或浏览器不提供定位服务。\");return}navigator.geolocation.getCurrentPosition(async p=>{const c=p.coords;if(!(Number.isFinite(c.accuracy)&&c.accuracy<=100)){blocked(\"位置精度不足（要求 100 米以内）。\");return}$(\"status\").textContent=\"正在验证位置…\";try{const res=await fetch(\"/__shield/gps/verify\",{method:\"POST\",credentials:\"same-origin\",cache:\"no-store\",headers:{\"Content-Type\":\"application/json\"},body:JSON.stringify({lat:c.latitude,lon:c.longitude,accuracy:c.accuracy})});const data=await res.json();if(!res.ok){blocked(data.error===\"CAMPUS_RESTRICTED\"?\"当前位置位于配置的校园限制区域内，访问已限制。\":\"位置验证失败：\"+(data.error||res.status));return}location.reload()}catch{blocked(\"无法连接位置验证服务。\")}},err=>{blocked(err.code===1?\"GPS 授权被拒绝：无法继续使用本站。\":err.code===2?\"无法取得位置：无法继续使用本站。\":\"GPS 定位超时或不准确。\")},{enableHighAccuracy:true,timeout:15000,maximumAge:0})}$(\"start\").onclick=run;$(\"retry\").onclick=run;";
const SESSION_COOKIE="__Host-vynalth-geo";
const STATUS_COOKIE="__Host-vynalth-status";
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
 if(status!=="trust"&&status!=="contact")return false;
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
 if(d<=cfg.radius)return reply(403,{error:"CAMPUS_RESTRICTED"});
 return reply(200,{verified:true,expiresInSeconds:SESSION_TTL},{
  "Set-Cookie":SESSION_COOKIE+"="+await createSession(cfg,url.hostname)+"; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age="+SESSION_TTL
 })
}
function page(){return new Response(GEO_HTML,{status:403,headers:{...head,"Content-Type":"text/html; charset=utf-8","X-Frame-Options":"DENY","Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"}})}
function script(){return new Response(GEO_CLIENT,{status:200,headers:{...head,"Content-Type":"application/javascript; charset=utf-8"}})}
function skip(path){return path.startsWith("/.well-known/")||path.startsWith("/api/auth/")||path.startsWith("/auth/")||path.startsWith("/api/oauth/")||path.startsWith("/api/webhooks/")||path==="/robots.txt"||path==="/favicon.ico"||path==="/sitemap.xml"||path==="/__shield/campus-beacon"}
export async function guestGpsGate(request,env,url){
 const cfg=config(env);
 if(!cfg)return null; // disabled or misconfigured -> site works normally
 if(url.pathname==="/__shield/gps/client.js"&&request.method==="GET")return script();
 if(url.pathname==="/__shield/gps/verify")return verify(request,url,cfg);
 if(url.pathname==="/__shield/gps/status"&&request.method==="GET")
  return reply(200,{enabled:true,verified:await permitted(request,cfg,url.hostname),
   exempt:await exempt(request,cfg,url.hostname)});
 if(skip(url.pathname))return null;
 if(await exempt(request,cfg,url.hostname))return null;
 if(await permitted(request,cfg,url.hostname))return null;
 const accept=request.headers.get("Accept")||"";
 if(request.method!=="GET"||(!accept.includes("text/html")&&accept.includes("application/json")))
  return reply(403,{error:"PRECISE_GPS_REQUIRED",blocked:true});
 return page();
}
