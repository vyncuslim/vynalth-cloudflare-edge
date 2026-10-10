import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { guestGpsGate } from "./guest-gps.js";

const cryptoApi=globalThis.crypto || webcrypto;
if(!globalThis.crypto)globalThis.crypto=cryptoApi;
const HOST="https://vyncuslim.com";
const SESSION_SECRET="demo-session-secret-unique-for-tests-only-00000000000000";
const STATUS_SECRET="demo-status-secret-unique-for-tests-only-00000000000000";
const cfg={GPS_GATE_ENABLED:"true",GPS_GATE_SESSION_SECRET:SESSION_SECRET,
 GPS_ACCOUNT_STATUS_SECRET:STATUS_SECRET,
 GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",
 GPS_CAMPUS_RADIUS_METERS:"120"};
const url=()=>new URL(HOST+"/");
function req(path="/",method="GET",headers={},body){
 return new Request(HOST+path,{method,headers,body});
}
const invoke=(request,env=cfg)=>guestGpsGate(request,env,new URL(request.url));
const b64=(x)=>Buffer.from(x).toString("base64url");
async function mac(secret,data){
 const k=await cryptoApi.subtle.importKey("raw",new TextEncoder().encode(secret),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 return b64(new Uint8Array(await cryptoApi.subtle.sign("HMAC",k,new TextEncoder().encode(data))));
}
async function statusCookie(status,host="vyncuslim.com"){
 const exp=Math.floor(Date.now()/1000)+600;
 const nonce=b64(new Uint8Array(16).fill(9));
 const payload=[exp,status,nonce,host].join("|");
 return "__Host-vynalth-status="+exp+"."+status+"."+nonce+"."+(await mac(STATUS_SECRET,payload));
}
async function verifyCoords(lat,lon,accuracy=15,custom=cfg) {
 return invoke(req("/__shield/gps/verify","POST",{
   "Origin":HOST,"Sec-Fetch-Site":"same-origin",
   "Content-Type":"application/json"
 },JSON.stringify({lat,lon,accuracy})),custom);
}

test("GPS guest gate stays OFF without explicit configuration",async()=>{
 assert.equal(await invoke(req(),{...cfg,GPS_GATE_ENABLED:"false"}),null);
 assert.equal(await invoke(req(),{...cfg,GPS_CAMPUS_LAT:"invalid"}),null);
 assert.equal(await invoke(req(),{...cfg,GPS_ACCOUNT_STATUS_SECRET:undefined}),null);
});
test("visitor with no signed status sees 403 GPS verification page",async()=>{
 const result=await invoke(req("/"));
 assert.equal(result.status,403);
 const html=await result.text();
 assert.match(html,/精确位置/);
 assert.match(html,/拒绝授权/);
 assert.match(html,/contact/);
 assert.doesNotMatch(html,/GPS_CAMPUS_LAT/);
});
test("client script serves before GPS grant and includes denial state",async()=>{
 const response=await invoke(req("/__shield/gps/client.js"));
 assert.equal(response.status,200);
 const script=await response.text();
 assert.match(script,/enableHighAccuracy:true/);
 assert.match(script,/授权被拒绝/);
 assert.match(script,/location\.reload/);
});
test("forged status cannot bypass, valid signed trust and contact can",async()=>{
 const fake=await invoke(req("/", "GET",{
  Cookie:"__Host-vynalth-status="+Math.floor(Date.now()/1000+600)+".trust.fake.untrusted"
 }));
 assert.equal(fake.status,403);
 for(const state of ["trust","contact","status"]){
  const valid=await invoke(req("/","GET",{Cookie:await statusCookie(state)}));
  assert.equal(valid,null,state);
 }
 const normal=await invoke(req("/","GET",{Cookie:await statusCookie("normal")}));
 assert.equal(normal.status,403);
});
test("status exemption is bound to exact hostname, not another domain",async()=>{
 const cookie=await statusCookie("trust","powiismunc.com");
 const result=await invoke(req("/","GET",{Cookie:cookie}));
 assert.equal(result.status,403);
});
test("proven guest outside campus gets short-lived signed Cookie",async()=>{
 const response=await verifyCoords(5.40,100.25,10);
 assert.equal(response.status,200);
 const header=response.headers.get("set-cookie");
 assert.match(header,/__Host-vynalth-geo=/);
 assert.match(header,/HttpOnly/);
 assert.match(header,/Secure/);
 assert.match(header,/Max-Age=900/);
 const session=header.split(";")[0];
 assert.equal(await invoke(req("/","GET",{Cookie:session})),null);
 assert.equal((await invoke(req("/","GET",{
   Cookie:session.replace(/.$/,"x")
 })).status),403);
});
test("verified campus coordinates return 403 and emit only a short-lived restriction cookie",async()=>{
 const response=await verifyCoords(5.3677,100.21995,10);
 assert.equal(response.status,403);
 assert.equal((await response.json()).error,"CAMPUS_RESTRICTED");
 assert.ok(response.headers.getSetCookie().some(v=>v.startsWith("__Host-vynalth-geo-block=")));
 assert.equal(response.headers.getSetCookie().some(v=>v.includes("lat=")||v.includes("lon=")),false);
});
test("boundary uncertainty and insufficient precision are rejected",async()=>{
 const ambiguous=await verifyCoords(5.3688,100.21995,100);
 assert.equal(ambiguous.status,403);
 assert.equal((await ambiguous.json()).error,"LOCATION_UNCERTAIN");
 const poor=await verifyCoords(5.3677,100.21995,600);
 assert.equal(poor.status,422);
});
test("cross-origin attempts and unsupported body content are rejected",async()=>{
 const wrong=await invoke(req("/__shield/gps/verify","POST",{
   "Content-Type":"application/json","Origin":"https://attacker.example"
 },JSON.stringify({lat:5,lon:100,accuracy:10})));
 assert.equal(wrong.status,403);
 const text=await invoke(req("/__shield/gps/verify","POST",{
   "Content-Type":"text/plain","Origin":HOST
 },"test"));
 assert.equal(text.status,415);
});
test("JSON APIs receive JSON 403; exempt auth routes remain accessible",async()=>{
 const api=await invoke(req("/api/v1/items","GET",{Accept:"application/json"}));
 assert.equal(api.status,403);
 assert.equal((await api.json()).error,"PRECISE_GPS_REQUIRED");
 for(const path of ["/api/auth/callback","/auth/login","/.well-known/acme-challenge/test","/robots.txt"]){
  assert.equal(await invoke(req(path)),null,path);
 }
});
test("geolocation gate has no KV, analytics or account status writes",async()=>{
 const text=await (await invoke(req("/"))).text();
 assert.doesNotMatch(text,/blocked:|school-ip-kv|localStorage/i);
});


test("GPS declaration is readable without location consent and contains three languages",async()=>{
 const response=await invoke(req("/__shield/gps/disclaimer"));
 assert.equal(response.status,200);
 assert.match(response.headers.get("Content-Type"),/text\/html/);
 const html=await response.text();
 assert.match(html,/声明/);
 assert.match(html,/Penafian/);
 assert.match(html,/Disclaimer/);
 assert.match(html,/trust/);
 assert.match(html,/contact/);
 assert.doesNotMatch(html,/getCurrentPosition/);
 const original=await (await invoke(req("/"))).text();
 assert.match(original,/href="\/__shield\/gps\/disclaimer"/);
});

test("a confirmed campus coordinate creates a short-lived block Cookie and shows blocked page",async()=>{
 const denied=await verifyCoords(5.3677,100.21995,15);
 assert.equal(denied.status,403);
 assert.equal((await denied.json()).error,"CAMPUS_RESTRICTED");
 const cookies=denied.headers.getSetCookie();
 assert.ok(cookies.some(v=>v.includes("__Host-vynalth-geo-block=")));
 assert.ok(cookies.some(v=>v.includes("Max-Age=900")));
 const first=cookies.find(v=>v.startsWith("__Host-vynalth-geo-block=")).split(";")[0];
 const page=await invoke(req("/","GET",{Cookie:first}));
 assert.equal(page.status,403);
 assert.match(await page.text(),/id="blocked"/);
});

test("signed hub-to-target handoff sets each host's own Cookie but no GPS coordinates",async()=>{
 const origin=await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
   method:"POST",
   headers:{"Origin":"https://vynalthai.com","Sec-Fetch-Site":"same-origin",
    "Content-Type":"application/json"},
   body:JSON.stringify({lat:5.4,lon:100.25,accuracy:15})
 }));
 assert.equal(origin.status,200);
 const sourceCookie=origin.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const hubRequest=new Request("https://vynalthai.com/__shield/gps/bridge?host=vyncuslim.com&return=%2Fhello",{
   headers:{Cookie:sourceCookie}
 });
 const hubResponse=await invoke(hubRequest);
 assert.equal(hubResponse.status,302);
 const dest=hubResponse.headers.get("Location");
 assert.match(dest,/https:\/\/vyncuslim\.com\/__shield\/gps\/import/);
 assert.doesNotMatch(dest,/5\.4|100\.25/);
 const destReply=await invoke(new Request(dest));
 assert.equal(destReply.status,302);
 assert.equal(destReply.headers.get("Location"),"/hello");
 const targetCookie=destReply.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const allowed=await invoke(req("/hello","GET",{Cookie:targetCookie}));
 assert.equal(allowed,null);
 // A cookie signed for one root domain never authorizes another root domain.
 const other=await invoke(new Request("https://vyncuslim.si/hello",{headers:{Cookie:targetCookie}}));
 assert.equal(other.status,403);
});

test("handoff is not an open redirect or a browser-provided authorization",async()=>{
 for(const invalid of [
  "/__shield/gps/bridge?host=attacker.example&return=%2F",
  "/__shield/gps/bridge?host=vyncuslim.com&return=https%3A%2F%2Fevil.example",
  "/__shield/gps/bridge?host=vyncuslim.com&return=%2F%2Fevil.example"
 ]){
  const r=await invoke(new Request("https://vynalthai.com"+invalid));
  assert.equal(r.status,400);
 }
 const fake=await invoke(req("/__shield/gps/import?ticket=not-signed&return=%2Fhello"));
 assert.equal(fake.status,403);
});

test("privacy declaration and privacy policy can be read even if location gate is enabled",async()=>{
 assert.equal((await invoke(req("/__shield/gps/disclaimer"))).status,200);
 assert.equal(await invoke(req("/en/legal/privacy")),null);
 assert.equal(await invoke(req("/legal/privacy")),null);
});



test("anonymous HTML visitor is redirected to first-party vynalthai.com GPS authority without login",async()=>{
 const all=["vyncuslim.com","vynalthai.si","vyncuslim.si",
   "vitamindai.online","sleepsomno.com","powiismunc.com",
   "app.vyncuslim.com","dashboard.vynalthai.si"];
 for(const host of all){
  const response=await invoke(new Request("https://"+host+"/my-page?private=123",{
    headers:{Accept:"text/html,application/xhtml+xml","Sec-Fetch-Dest":"document",
     "Sec-Fetch-Mode":"navigate"}
  }));
  assert.equal(response.status,302,host);
  const target=new URL(response.headers.get("Location"));
  assert.equal(target.hostname,"vynalthai.com",host);
  assert.equal(target.pathname,"/__shield/gps/bridge",host);
  assert.equal(target.searchParams.get("host"),host,host);
  assert.equal(target.searchParams.get("return"),"/my-page",host);
  assert.equal(target.searchParams.has("private"),false,host);
 }
});

test("guest can accept once on primary site and synchronize across all domains using first-party redirects",async()=>{
 const primary=await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
  method:"POST",
  headers:{"Origin":"https://vynalthai.com","Content-Type":"application/json",
    "Sec-Fetch-Site":"same-origin"},
  body:JSON.stringify({lat:5.4,lon:100.25,accuracy:15})
 }));
 assert.equal(primary.status,200);
 const primaryCookie=primary.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 for(const domain of ["vyncuslim.com","vynalthai.si","vyncuslim.si",
  "vitamindai.online","sleepsomno.com","powiismunc.com"]){
  const start=await invoke(new Request("https://"+domain+"/about",{
   headers:{"Accept":"text/html","Sec-Fetch-Dest":"document"}
  }));
  assert.equal(start.status,302,domain);
  const hub=await invoke(new Request(start.headers.get("Location"),{
    headers:{Cookie:primaryCookie}
  }));
  assert.equal(hub.status,302,domain);
  const imported=await invoke(new Request(hub.headers.get("Location")));
  assert.equal(imported.status,302,domain);
  assert.equal(imported.headers.get("Location"),"/about");
  const siteCookie=imported.headers.getSetCookie()
    .find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
  assert.equal(await invoke(new Request("https://"+domain+"/about",{
    headers:{Cookie:siteCookie,Accept:"text/html","Sec-Fetch-Dest":"document"}
  })),null,domain);
 }
});

test("campus-inside guest block also synchronizes to other sites without user login",async()=>{
 const primary=await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
  method:"POST",headers:{"Origin":"https://vynalthai.com",
   "Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
  body:JSON.stringify({lat:5.3677,lon:100.21995,accuracy:10})
 }));
 assert.equal(primary.status,403);
 const hubCookie=primary.headers.getSetCookie()
   .find(x=>x.startsWith("__Host-vynalth-geo-block=")).split(";")[0];
 const initial=await invoke(new Request("https://vyncuslim.si/",{
  headers:{Accept:"text/html","Sec-Fetch-Dest":"document"}
 }));
 assert.equal(initial.status,302);
 const bridge=await invoke(new Request(initial.headers.get("Location"),{
  headers:{Cookie:hubCookie}
 }));
 assert.equal(bridge.status,302);
 const imported=await invoke(new Request(bridge.headers.get("Location")));
 assert.equal(imported.status,302);
 const siteCookie=imported.headers.getSetCookie()
   .find(x=>x.startsWith("__Host-vynalth-geo-block=")).split(";")[0];
 const siteBlocked=await invoke(new Request("https://vyncuslim.si/",{
  headers:{Cookie:siteCookie,Accept:"text/html","Sec-Fetch-Dest":"document"}
 }));
 assert.equal(siteBlocked.status,403);
 assert.match(await siteBlocked.text(),/id="blocked"/);
});

test("declined GPS and inaccurate GPS cannot obtain a cookie or handoff",async()=>{
 const noGPS=await invoke(new Request("https://vynalthai.com/__shield/gps/bridge?host=vyncuslim.com&return=%2F"));
 assert.equal(noGPS.status,403);
 assert.match(await noGPS.text(),/getCurrentPosition|Location required/);
 assert.equal(noGPS.headers.get("Set-Cookie"),null);
 const poor=await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
  method:"POST",headers:{"Origin":"https://vynalthai.com",
   "Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
  body:JSON.stringify({lat:5.4,lon:100.25,accuracy:400})
 }));
 assert.equal(poor.status,422);
 assert.equal(poor.headers.get("Set-Cookie"),null);
});

test("JSON APIs never trigger cross-domain navigation and deny with 403",async()=>{
 const r=await invoke(new Request("https://api.vyncuslim.com/v1/profile",{
  headers:{Accept:"application/json","Sec-Fetch-Dest":"empty"}
 }));
 assert.equal(r.status,403);
 assert.equal(r.headers.get("Location"),null);
 assert.equal((await r.json()).error,"PRECISE_GPS_REQUIRED");
});

test("forged trusted roles are never an anonymous GPS bypass",async()=>{
 for(const name of ["trust","contact","status"]){
  const spoofed=await invoke(new Request("https://vyncuslim.com/",{
   headers:{Cookie:"__Host-vynalth-status="+name,
    Accept:"application/json"}
  }));
  assert.equal(spoofed.status,403);
 }
});
