import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { Script } from "node:vm";
import { readFileSync } from "node:fs";
import { guestGpsGate,gpsOutsideOrLegacyExempt } from "./guest-gps.js";

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


async function initialGuestRedirect(host,path="/about"){
 const response=await invoke(new Request("https://"+host+path,{
   headers:{Accept:"text/html","Sec-Fetch-Dest":"document",
    "Sec-Fetch-Mode":"navigate"}
 }));
 assert.equal(response.status,302,host);
 const stateCookie=response.headers.getSetCookie()
   .find(x=>x.startsWith("__Host-vynalth-geo-handoff="));
 assert.ok(stateCookie,host);
 return {response,stateCookie:stateCookie.split(";")[0],
  hubUrl:response.headers.get("Location")};
}

test("GPS guest gate stays OFF without explicit configuration",async()=>{
 assert.equal(await invoke(req(),{...cfg,GPS_GATE_ENABLED:"false"}),null);
 const invalid=await invoke(req(),{...cfg,GPS_CAMPUS_LAT:"invalid"});
 assert.equal(invalid.status,503);
 const guest=await invoke(req(),{...cfg,GPS_ACCOUNT_STATUS_SECRET:undefined});
 assert.equal(guest.status,403);
});
test("visitor with no signed status sees 403 GPS verification page",async()=>{
 const result=await invoke(req("/"));
 assert.equal(result.status,403);
 const html=await result.text();
 assert.match(html,/Precise location required/);
 assert.match(html,/Location|permission/);
 assert.match(html,/contact/);
 assert.doesNotMatch(html,/GPS_CAMPUS_LAT/);
});
test("client script serves before GPS grant and includes denial state",async()=>{
 const response=await invoke(req("/__shield/gps/client.js"));
 assert.equal(response.status,200);
 const script=await response.text();
 assert.match(script,/enableHighAccuracy:true/);
 assert.match(script,/navigator\.geolocation\.getCurrentPosition/);
 assert.match(script,/autoRequest\(\)/);
 assert.match(script,/navigator\.permissions\.query/);
 assert.match(script,/Location permission denied/);
 assert.match(script,/navigationTicket/);
 assert.match(script,/location\.replace/);
 assert.doesNotMatch(script,/location\.reload/);
 assert.doesNotThrow(()=>new Script(script),"GPS browser challenge client must parse as valid JavaScript");
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
 const forged=session.replace(/\.([A-Za-z0-9_-])/,(_,c)=>"."+ (c==="A"?"B":"A"));
 const rejected=await invoke(req("/","GET",{Cookie:forged}));
 assert.equal(rejected.status,403);
});
test("confirmed campus returns 403 and only expires stale credentials",async()=>{
 const result=await verifyCoords(5.3677,100.21995,10);
 assert.equal(result.status,403);
 assert.equal((await result.json()).error,"CAMPUS_RESTRICTED");
 const cookies=result.headers.getSetCookie();
 assert.equal(cookies.length,0,"New INSIDE denials send no Set-Cookie");
 assert.ok(cookies.every(v=>v.includes("Max-Age=0")));
 assert.equal(cookies.some(v=>v.includes("Max-Age=900")||v.includes("Max-Age=300")),false);
 assert.equal(cookies.some(v=>v.includes("lat=")||v.includes("lon=")),false);
});

test("boundary uncertainty and insufficient precision are rejected",async()=>{
 const ambiguous=await verifyCoords(5.3688,100.21995,100);
 assert.equal(ambiguous.status,403);
 assert.equal((await ambiguous.json()).error,"LOCATION_UNCERTAIN");
 const poor=await verifyCoords(5.3677,100.21995,10001);
 assert.equal(poor.status,422);
});
test("both POWIIS campuses are separate provisional GPS test circles",async()=>{
 const twoCampuses={...cfg,GPS_CAMPUS_GEOFENCES_JSON:JSON.stringify([
  {id:"tanjung-bungah",lat:5.46113,lon:100.28420,radius:180},
  {id:"balik-pulau",lat:5.36770,lon:100.21995,radius:180}
 ])};
 for(const [lat,lon] of [[5.46113,100.28420],[5.36770,100.21995]]){
  const r=await verifyCoords(lat,lon,10,twoCampuses);
  assert.equal(r.status,403);
  assert.equal((await r.json()).error,"CAMPUS_RESTRICTED");
  assert.equal(r.headers.getSetCookie().some(v=>v.includes(String(lat))||v.includes(String(lon))),false);
 }
 const exterior=await verifyCoords(5.42,100.25,10,twoCampuses);
 assert.equal(exterior.status,200);
 const overlap=await verifyCoords(5.46275,100.28420,25,twoCampuses);
 assert.equal(overlap.status,403);
 assert.equal((await overlap.json()).error,"LOCATION_UNCERTAIN");
});

test("invalid provisional geofences do not silently disable an enabled gate",async()=>{
 for(const value of ["{oops", "[]",JSON.stringify([{id:"tanjung-bungah",lat:5.46113,lon:100.28420,radius:180},
 {id:"balik-pulau",lat:5.36770,lon:100.21995}]),
 JSON.stringify([{id:"tanjung-bungah",lat:5.46113,lon:100.28420,radius:180},
 {id:"tanjung-bungah",lat:5.36770,lon:100.21995,radius:180}])]){
  assert.equal((await invoke(req("/"),{...cfg,GPS_CAMPUS_GEOFENCES_JSON:value})).status,503);
 }
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
test("Jingxin story text stays public while its protected photos require verification",async()=>{
 for(const path of ["/jingxin","/jingxin/","/jingxin.html"]){
  assert.equal(await invoke(req(path)),null,path);
 }
 for(const photoPath of ["/media/jingxin/shared-memory.jpg","/media/jingxin/mce-kuala-lumpur-real.webp"]){
  const response=await invoke(req(photoPath,"GET",{Accept:"image/avif,image/webp,image/*,*/*"}));
  assert.equal(response.status,403,photoPath);
  assert.equal(response.headers.get("Cache-Control").includes("no-store"),true);
 }
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

test("in-campus GPS 403 clears any existing outside cookie without minting a block cookie",async()=>{
 const allowed=await verifyCoords(5.40,100.25,10);
 assert.equal(allowed.status,200);
 const cookie=allowed.headers.getSetCookie().find(v=>v.startsWith("__Host-vynalth-geo=")).split(";")[0];
 assert.equal(await invoke(req("/","GET",{Cookie:cookie})),null);
 const denied=await invoke(req("/__shield/gps/verify","POST",{
   Origin:HOST,"Sec-Fetch-Site":"same-origin","Content-Type":"application/json",Cookie:cookie
 },JSON.stringify({lat:5.3677,lon:100.21995,accuracy:15})));
 assert.equal(denied.status,403);
 assert.equal((await denied.json()).error,"CAMPUS_RESTRICTED");
 assert.ok(denied.headers.getSetCookie().every(v=>v.includes("Max-Age=0")));
 assert.equal((await invoke(req("/"))).status,403);
});

test("signed anonymous hub transfer is bound to recipient first-party state Cookie",async()=>{
 const outside=await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
   method:"POST",headers:{"Origin":"https://vynalthai.com",
     "Sec-Fetch-Site":"same-origin","Content-Type":"application/json"},
   body:JSON.stringify({lat:5.4,lon:100.25,accuracy:15})
 }));
 assert.equal(outside.status,200);
 const hubCookie=outside.headers.getSetCookie()
   .find(v=>v.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const first=await initialGuestRedirect("vyncuslim.com","/hello");
 const bridge=await invoke(new Request(first.hubUrl,{headers:{Cookie:hubCookie}}));
 assert.equal(bridge.status,302);
 const target=bridge.headers.get("Location");
 assert.match(target,/https:\/\/vyncuslim\.com\/__shield\/gps\/import/);
 assert.doesNotMatch(target,/5\.4|100\.25/);
 assert.equal((await invoke(new Request(target))).status,403);
 const imported=await invoke(new Request(target,{
   headers:{Cookie:first.stateCookie}
 }));
 assert.equal(imported.status,302);
 assert.equal(imported.headers.get("Location"),"/hello");
 assert.ok(imported.headers.getSetCookie().some(c=>c.startsWith("__Host-vynalth-geo-handoff=")&&c.includes("Max-Age=0")));
 const siteCookie=imported.headers.getSetCookie()
   .find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 assert.equal(await invoke(req("/hello","GET",{Cookie:siteCookie})),null);
 const wrongDomain=await invoke(new Request("https://vyncuslim.si/hello",{
  headers:{Cookie:siteCookie}
 }));
 assert.equal(wrongDomain.status,403);
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
 const missingState=await invoke(req("/__shield/gps/import?ticket=not-signed&return=%2Fhello"));
 assert.equal(missingState.status,400);
 const fake=await invoke(req("/__shield/gps/import?ticket=not-signed&return=%2Fhello&state="+ "a".repeat(32)));
 assert.equal(fake.status,403);
});

test("privacy declaration and privacy policy can be read even if location gate is enabled",async()=>{
 assert.equal((await invoke(req("/__shield/gps/disclaimer"))).status,200);
 assert.equal(await invoke(req("/en/legal/privacy")),null);
 assert.equal(await invoke(req("/legal/privacy")),null);
});




test("anonymous HTML visitors on six sibling domains and subdomains redirect via first-party hub",async()=>{
 const all=["vyncuslim.com","vynalthai.si","vyncuslim.si",
   "vitamindai.online","sleepsomno.com","powiismunc.com",
   "app.vyncuslim.com","dashboard.vynalthai.si"];
 for(const host of all){
  const first=await initialGuestRedirect(host,"/my-page?private=123");
  const target=new URL(first.hubUrl);
  assert.equal(target.hostname,"vynalthai.com",host);
  assert.equal(target.pathname,"/__shield/gps/bridge",host);
  assert.equal(target.searchParams.get("host"),host,host);
  assert.equal(target.searchParams.get("return"),"/my-page",host);
  assert.match(target.searchParams.get("state"),/^[A-Za-z0-9_-]{32}$/,host);
  assert.equal(target.searchParams.has("private"),false,host);
 }
});



test("anonymous guest approved at hub gets per-domain 15-minute Cookies on six sites",async()=>{
 const verified=await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
  method:"POST",headers:{"Origin":"https://vynalthai.com",
    "Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
  body:JSON.stringify({lat:5.4,lon:100.25,accuracy:15})
 }));
 assert.equal(verified.status,200);
 const hubCookie=verified.headers.getSetCookie()
   .find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 for(const host of ["vyncuslim.com","vynalthai.si","vyncuslim.si",
  "vitamindai.online","sleepsomno.com","powiismunc.com"]){
  const first=await initialGuestRedirect(host);
  const hub=await invoke(new Request(first.hubUrl,{headers:{Cookie:hubCookie}}));
  assert.equal(hub.status,302,host);
  const imported=await invoke(new Request(hub.headers.get("Location"),{
   headers:{Cookie:first.stateCookie}
  }));
  assert.equal(imported.status,302,host);
  const siteCookie=imported.headers.getSetCookie()
    .find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
  const accepted=await invoke(new Request("https://"+host+"/about",{
   headers:{Cookie:siteCookie,Accept:"text/html","Sec-Fetch-Dest":"document"}
  }));
  assert.equal(accepted,null,host);
 }
});



test("an inside-campus denial never generates cross-domain transferable block cookies",async()=>{
 const denied=await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
  method:"POST",headers:{"Origin":"https://vynalthai.com",
    "Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
  body:JSON.stringify({lat:5.3677,lon:100.21995,accuracy:10})
 }));
 assert.equal(denied.status,403);
 assert.ok(denied.headers.getSetCookie().every(v=>v.includes("Max-Age=0")));
 const first=await initialGuestRedirect("vyncuslim.si","/");
 const hub=await invoke(new Request(first.hubUrl));
 assert.equal(hub.status,403);
 assert.match(await hub.text(),/id="prompt"/);
});

test("guest without GPS grant and with inadequate accuracy cannot obtain signed verdict",async()=>{
 const first=await initialGuestRedirect("vyncuslim.com","/");
 const prompt=await invoke(new Request(first.hubUrl));
 assert.equal(prompt.status,403);
 assert.match(await prompt.text(),/Precise location required/);
 assert.equal(prompt.headers.get("Set-Cookie"),null);
 const inaccurate=await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
  method:"POST",headers:{"Origin":"https://vynalthai.com",
    "Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
  body:JSON.stringify({lat:5.4,lon:100.25,accuracy:10001})
 }));
 assert.equal(inaccurate.status,422);
 assert.equal(inaccurate.headers.get("Set-Cookie"),null);
 const fake=await invoke(new Request("https://vyncuslim.com/__shield/gps/import?"+
   "return=%2F&ticket=forged&state="+encodeURIComponent(new URL(first.hubUrl).searchParams.get("state")),{
   headers:{Cookie:first.stateCookie}
 }));
 assert.equal(fake.status,403);
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


test("explicit re-verification is accessible after a previous inside verdict",async()=>{
 const link=await invoke(new Request("https://vyncuslim.com/__shield/gps/link?recheck=1&return=%2F"));
 assert.equal(link.status,302);
 const dest=new URL(link.headers.get("Location"));
 assert.equal(dest.pathname,"/__shield/gps/recheck");
 const content=await invoke(new Request(dest.toString()));
 assert.equal(content.status,403);
 assert.match(await content.text(),/Precise location required|Location verification/);
});

test("CSRF-linked handoff cannot be injected into a different visitor session",async()=>{
 const one=await initialGuestRedirect("vyncuslim.com","/one");
 const another=await initialGuestRedirect("vyncuslim.com","/one");
 const hubCookie=(await invoke(new Request("https://vynalthai.com/__shield/gps/verify",{
   method:"POST",headers:{Origin:"https://vynalthai.com",
    "Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
   body:JSON.stringify({lat:5.4,lon:100.25,accuracy:10})
 }))).headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const ticket=await invoke(new Request(one.hubUrl,{headers:{Cookie:hubCookie}}));
 assert.equal(ticket.status,302);
 const injected=await invoke(new Request(ticket.headers.get("Location"),{
  headers:{Cookie:another.stateCookie}
 }));
 assert.equal(injected.status,403);
 assert.equal((await injected.json()).error,"HANDOFF_STATE_MISMATCH");
});

const researchOSM=readFileSync(new URL("../test/fixtures/powiis-osm-candidates.RESEARCH_ONLY.geojson",import.meta.url),"utf8");
test("GPS polygon shadow mode never changes legacy circle outcomes or publishes shadow results",async()=>{
 const env={...cfg,GPS_POLYGON_MODE:"shadow",GPS_CAMPUS_POLYGONS_JSON:researchOSM};
 for(const [lat,lon,acc] of [[5.3677,100.21995,5],[5.4,100.25,5],
  [5.3687259,100.2204351,1]]){
  const original=await verifyCoords(lat,lon,acc,cfg);
  const shadow=await verifyCoords(lat,lon,acc,env);
  assert.equal(shadow.status,original.status);
  const originalBody=await original.json(),shadowBody=await shadow.json();
  assert.equal(shadowBody.error,originalBody.error);
  assert.equal(shadowBody.verified,originalBody.verified);
  assert.ok(!("shadowDecision" in shadowBody));
  assert.ok(!("lat" in shadowBody)&&!("lon" in shadowBody));
 }
});
test("GPS research OSM polygons cannot be promoted to hard enforcement",async()=>{
 const env={...cfg,GPS_POLYGON_MODE:"enforce",GPS_POLYGON_ENFORCEMENT_APPROVED:"true",
  GPS_CAMPUS_POLYGONS_JSON:researchOSM};
 const response=await verifyCoords(5.367711,100.219932,5,env);
 assert.equal(response.status,503);
 assert.equal((await response.json()).error,"GPS_GATE_CONFIGURATION_UNAVAILABLE");
 const absentApproval=await invoke(req("/"),{...env,GPS_POLYGON_ENFORCEMENT_APPROVED:"false"});
 assert.equal(absentApproval.status,503);
 assert.equal(await invoke(req("/"),{...env,GPS_GATE_ENABLED:"false"}),null);
});
test("GPS polygon shadow requires valid GeoJSON and HMAC secret when gate enabled",async()=>{
 for(const value of ["{broken","[]",undefined]){
  const r=await invoke(req("/"),{...cfg,GPS_POLYGON_MODE:"shadow",
   GPS_CAMPUS_POLYGONS_JSON:value});
  assert.equal(r.status,503);
 }
 const noSecret=await invoke(req("/"),{...cfg,GPS_POLYGON_MODE:"shadow",
  GPS_CAMPUS_POLYGONS_JSON:researchOSM,GPS_GATE_SESSION_SECRET:undefined});
 assert.equal(noSecret.status,503);
});
test("approved synthetic polygon mode has INSIDE/OUTSIDE/UNCERTAIN outcomes without exposing position",async()=>{
 // Synthetic approval is used only to exercise the code path; no production
 // authoritative survey is asserted by these test-only feature attributes.
 const data=JSON.parse(researchOSM);
 data.features.forEach(f=>{f.properties.official_boundary_verified=true;});
 const env={...cfg,GPS_POLYGON_MODE:"enforce",GPS_POLYGON_ENFORCEMENT_APPROVED:"true",
  GPS_CAMPUS_POLYGONS_JSON:JSON.stringify(data)};
 const inside=await verifyCoords(5.367711,100.219932,3,env);
 assert.equal(inside.status,403);
 assert.equal((await inside.json()).error,"CAMPUS_RESTRICTED");
 const outside=await verifyCoords(5.4,100.25,5,env);
 assert.equal(outside.status,200);
 assert.equal((await outside.json()).verified,true);
 const edge=await verifyCoords(5.36875,100.22045,3,env);
 assert.equal(edge.status,200);
 const near=await edge.json();
 assert.equal(near.nearBoundary,true);
 assert.equal(near.verified,false);
 const nearCookie=edge.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo="));
 assert.match(nearCookie,/Max-Age=300/);
 assert.equal(await invoke(req("/","GET",{Cookie:nearCookie.split(";")[0]}),env),null);
});


test("operator-approved uncertified OSM polygons use temporary near-border permissions",async()=>{
 const env={...cfg,GPS_POLYGON_MODE:"enforce",GPS_POLYGON_ENFORCEMENT_APPROVED:"true",
   GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED:"true",GPS_BOUNDARY_BUFFER_METERS:"30",
   GPS_CAMPUS_POLYGONS_JSON:researchOSM};
 const inside=await verifyCoords(5.367711,100.219932,5,env);
 assert.equal(inside.status,403);
 assert.equal((await inside.json()).error,"CAMPUS_RESTRICTED");
 const outside=await verifyCoords(5.4,100.25,5,env);
 assert.equal(outside.status,200);
 const near=await verifyCoords(5.36875,100.22045,5,env);
 assert.equal(near.status,200);
 assert.equal((await near.json()).nearBoundary,true);
 // No location consent means no signed status, hence HTML and APIs are denied.
 const sibling=await invoke(req("/","GET",{Accept:"text/html"}),env);
 assert.equal(sibling.status,302);
 assert.match(sibling.headers.get("Location"),/^https:\/\/vynalthai\.com\/__shield\/gps\/bridge/);
 const api=await invoke(req("/api/protected","GET",{Accept:"application/json"}),env);
 assert.equal(api.status,403);
 const noConsentPage=await invoke(new Request("https://vynalthai.com/",{headers:{Accept:"text/html"}}),env);
 assert.equal(noConsentPage.status,403);
 assert.match(await noConsentPage.text(),/Request location again|Allow location/);
});

test("inside point within 30m buffer is retryable 403, no permit Cookie issued",async()=>{
 const env={...cfg,GPS_POLYGON_MODE:"enforce",GPS_POLYGON_ENFORCEMENT_APPROVED:"true",
  GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED:"true",GPS_BOUNDARY_BUFFER_METERS:"30",
  GPS_CAMPUS_POLYGONS_JSON:researchOSM};
 const nearInside=await verifyCoords(5.36870,100.220435,5,env);
 assert.equal(nearInside.status,403);
 const result=await nearInside.json();
 assert.equal(result.error,"CAMPUS_BOUNDARY_UNCERTAIN");
 assert.equal(result.retryable,true);
 assert.equal(result.blocked,true);
 assert.equal(nearInside.headers.getSetCookie().length,0,"No Cookie may be granted");
 const nearOutside=await verifyCoords(5.36875,100.22045,5,env);
 assert.equal(nearOutside.status,200);
 assert.equal((await nearOutside.json()).classification,"near_outside");
 const outside=await verifyCoords(5.40,100.25,5,env);
 assert.equal((await outside.json()).classification,"outside");
 const signed=outside.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const revoked=await invoke(req("/__shield/gps/verify","POST",{
   Origin:HOST,"Content-Type":"application/json","Sec-Fetch-Site":"same-origin",Cookie:signed
 },JSON.stringify({lat:5.36870,lon:100.220435,accuracy:5})),env);
 assert.equal(revoked.status,403);
 assert.ok(revoked.headers.getSetCookie().some(x=>x.includes("Max-Age=0")));
 assert.equal(revoked.headers.getSetCookie().some(x=>x.includes("Max-Age=900")),false);
});

test("invalid config never grants protected access, including legacy bypass setting",async()=>{
 const env={...cfg,GPS_CAMPUS_LAT:"broken",GPS_CONFIG_ERROR_ACTION:"bypass"};
 const status=await invoke(req("/__shield/gps/status"),env);
 assert.equal(status.status,503);
 const state=await status.json();
 assert.equal(state.configurationAvailable,false);
 assert.equal(state.enforcing,false);
 const api=await invoke(req("/api/protected","GET",{Accept:"application/json"}),env);
 assert.equal(api.status,503);
 assert.equal((await api.json()).error,"GPS_GATE_CONFIGURATION_UNAVAILABLE");
 const page=await invoke(req("/","GET",{Accept:"text/html","Sec-Fetch-Dest":"document"}),env);
 assert.equal(page.status,503);
 assert.match(page.headers.get("Content-Type"),/text\/html/);
 assert.match(await page.text(),/Location verification is temporarily unavailable/);
 assert.equal(page.headers.get("Set-Cookie"),null);
 assert.equal(await invoke(req("/en/legal/privacy"),env),null);
 assert.equal(await invoke(req("/api/auth/session"),env),null);
});

test("proximity cookie cannot unlock private photo data",async()=>{
 const env={...cfg,GPS_POLYGON_MODE:"enforce",GPS_POLYGON_ENFORCEMENT_APPROVED:"true",
   GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED:"true",GPS_BOUNDARY_BUFFER_METERS:"30",
   GPS_CAMPUS_POLYGONS_JSON:researchOSM};
 const near=await verifyCoords(5.36875,100.22045,5,env);
 assert.equal(near.status,200);
 const nearCookie=near.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const rq=req("/private/picture.webp","GET",{Cookie:nearCookie});
 assert.equal(await gpsOutsideOrLegacyExempt(rq,env,"vyncuslim.com"),false);
 const outside=await verifyCoords(5.40,100.25,5,env);
 const outsideCookie=outside.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 assert.equal(await gpsOutsideOrLegacyExempt(req("/private/picture.webp","GET",{Cookie:outsideCookie}),env,"vyncuslim.com"),true);
});


test("new GPS UI matches Vynalth AI site branding and offers browser permission controls",async()=>{
 const resp=await invoke(new Request("https://vynalthai.com/",{headers:{Accept:"text/html"}}));
 const html=await resp.text();
 assert.match(html,/Vynalth AI/);
 assert.doesNotMatch(html,/VYNALTH SHIELD/i);
 assert.match(html,/<html lang="en">/);
 assert.match(html,/English/);
 assert.doesNotMatch(html,/data-lang="zh"|data-lang="ms"/);
 assert.match(html,/id="start"/);
 assert.match(html,/id="retry"/);
 assert.match(html,/#0b0c0f/);
});

test("each document refresh requires fresh GPS even with a signed 15-minute cookie",async()=>{
 const seen=new Map();
 const kv={get:async key=>seen.get(key)||null,put:async(key,value)=>{seen.set(key,value);}};
 const env={...cfg,GPS_RECHECK_EVERY_DOCUMENT:"true",CONSENT_KV:kv};
 const hub="https://vynalthai.com";
 const html=(path="/")=>new Request(hub+path,{headers:{Accept:"text/html","Sec-Fetch-Dest":"document"}});
 const challenge=await invoke(html("/dashboard"));
 assert.equal(challenge.status,403);
 const verify=await invoke(new Request(hub+"/__shield/gps/verify",{
   method:"POST",headers:{Origin:hub,"Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
   body:JSON.stringify({lat:5.4,lon:100.25,accuracy:5,returnPath:"/dashboard"})
 }),env);
 assert.equal(verify.status,200);
 const data=await verify.json();
 assert.match(data.navigationTicket,/^[^.]+\.[^.]+\.[^.]+$/);
 const geo=verify.headers.getSetCookie().find(v=>v.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const headers={Accept:"text/html","Sec-Fetch-Dest":"document",Cookie:geo};
 const reqDoc=(path)=>new Request(hub+path,{headers});
 // A cookie from an earlier visit MUST NOT bypass a new page navigation.
 assert.equal((await invoke(reqDoc("/dashboard"),env)).status,403);
 const url="/dashboard?__vynalth_gps_visit="+encodeURIComponent(data.navigationTicket);
 assert.equal(await invoke(reqDoc(url),env),null,"single freshly-verified document is allowed");
 assert.equal((await invoke(reqDoc(url),env)).status,403,"F5/replay of same URL is challenged");
 assert.equal((await invoke(reqDoc("/dashboard"),env)).status,403,"refresh after clean URL is challenged");
 assert.equal((await invoke(reqDoc("/another?__vynalth_gps_visit="+data.navigationTicket),env)).status,403,"proof is path bound");
 assert.equal(await invoke(new Request(hub+"/api/protected",{
   headers:{Cookie:geo,Accept:"application/json"}
 }),env),null,"authenticated resource/API traffic keeps the signed session");
});
test("navigation proof is only issued when one-visit replay storage is bound",async()=>{
 const env={...cfg,GPS_RECHECK_EVERY_DOCUMENT:"true",CONSENT_KV:undefined};
 const res=await verifyCoords(5.4,100.25,5,env);
 assert.equal(res.status,503);
 assert.equal((await res.json()).error,"GPS_NAVIGATION_STATE_UNAVAILABLE");
 assert.equal(res.headers.get("Set-Cookie"),null);
});
test("refresh on sibling domain forces new hub location check even with existing signed cookie",async()=>{
 const seen=new Map();
 const kv={get:async key=>seen.get(key)||null,put:async(key,value)=>{seen.set(key,value);}};
 const env={...cfg,GPS_RECHECK_EVERY_DOCUMENT:"true",CONSENT_KV:kv};
 const outside=await verifyCoords(5.4,100.25,5,env);
 assert.equal(outside.status,200);
 const cookie=outside.headers.getSetCookie().find(v=>v.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const refresh=await invoke(req("/dashboard","GET",{Cookie:cookie,Accept:"text/html","Sec-Fetch-Dest":"document"}),env);
 assert.equal(refresh.status,302);
 const destination=new URL(refresh.headers.get("Location"));
 assert.equal(destination.pathname,"/__shield/gps/recheck");
 const challenge=await invoke(new Request(destination.toString()),env);
 assert.equal(challenge.status,403);
 assert.match(await challenge.text(),/Precise location required/);
});

test("sibling domain completes fresh cross-domain GPS recheck with exactly one target navigation",async()=>{
 const seen=new Map();
 const kv={get:async key=>seen.get(key)||null,put:async(key,value)=>{seen.set(key,value);}};
 const env={...cfg,GPS_RECHECK_EVERY_DOCUMENT:"true",CONSENT_KV:kv};
 const sibling="https://vyncuslim.si";
 const root="https://vynalthai.com";
 const reqHtml=(url,cookie="")=>new Request(url,{headers:{Accept:"text/html","Sec-Fetch-Dest":"document",Cookie:cookie}});
 const first=await invoke(reqHtml(sibling+"/c/session-123?tab=chat"),env);
 assert.equal(first.status,302);
 const challengeUrl=new URL(first.headers.get("Location"));
 assert.equal(challengeUrl.pathname,"/__shield/gps/recheck");
 assert.equal(challengeUrl.searchParams.get("return"),"/c/session-123");
 assert.equal((await invoke(new Request(challengeUrl),env)).status,403);
 const fresh=await invoke(new Request(root+"/__shield/gps/verify",{
  method:"POST",headers:{Origin:root,"Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
  body:JSON.stringify({lat:5.4,lon:100.25,accuracy:8,returnPath:"/"})
 }),env);
 assert.equal(fresh.status,200);
 const hubCookies=fresh.headers.getSetCookie();
 const hubCookie=hubCookies.filter(x=>x.startsWith("__Host-vynalth-geo=")||
   x.startsWith("__Host-vynalth-gps-fresh=")).map(x=>x.split(";")[0]).join("; ");
 assert.match(hubCookie,/__Host-vynalth-gps-fresh=/);
 const bridge=new URL(challengeUrl);
 bridge.pathname="/__shield/gps/bridge";
 const oldOnly=hubCookie.split("; ").find(x=>x.startsWith("__Host-vynalth-geo="));
 const staleBridge=await invoke(new Request(bridge.toString(),{headers:{Cookie:oldOnly}}),env);
 assert.equal(staleBridge.status,403,"Old location cookie cannot bypass new GPS check");
 assert.equal((await staleBridge.json()).error,"FRESH_GPS_REQUIRED");
 const bridgeResponse=await invoke(new Request(bridge.toString(),{headers:{Cookie:hubCookie}}),env);
 assert.equal(bridgeResponse.status,302);
 assert.equal((await invoke(new Request(bridge.toString(),{headers:{Cookie:hubCookie}}),env)).status,403,
   "Fresh bridge grant can only be used once");
 const targetState=first.headers.getSetCookie().find(v=>v.startsWith("__Host-vynalth-geo-handoff=")).split(";")[0];
 const imported=await invoke(new Request(bridgeResponse.headers.get("Location"),{headers:{Cookie:targetState}}),env);
 assert.equal(imported.status,302);
 const destination=imported.headers.get("Location");
 const redirected=new URL(sibling+destination);
 assert.ok(redirected.searchParams.has("__vynalth_gps_visit"));
 assert.equal(redirected.searchParams.get("tab"),null,"Never forward sensitive query through GPS hub");
 const targetCookie=imported.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 assert.equal(await invoke(reqHtml(redirected.toString(),targetCookie),env),null);
 const onReload=await invoke(reqHtml(redirected.toString(),targetCookie),env);
 assert.equal(onReload.status,302);
 assert.equal(new URL(onReload.headers.get("Location")).pathname,"/__shield/gps/recheck");
});


test("GPS challenge and error screens are English without a language toggle",async()=>{
 const resp=await invoke(new Request("https://vynalthai.com/",{headers:{Accept:"text/html"}}));
 assert.equal(resp.status,403);
 const html=await resp.text();
 assert.match(html,/<html lang="en">/);
 assert.match(html,/Verify your location/);
 assert.match(html,/Allow location & verify/);
 assert.match(html,/Location verification/);
 assert.doesNotMatch(html,/data-lang="zh"/);
 assert.doesNotMatch(html,/需要精确位置权限|位置验证|✦ VYNALTH SHIELD/i);
 const js=(await (await invoke(req("/__shield/gps/client.js"))).text());
 assert.match(js,/updateLanguage\("en"\)/);
 assert.doesNotMatch(js,/navigator\.language/);
});


test("GPS status advertises active boundary-side policy revision without coordinates",async()=>{
 const healthy=await invoke(req("/__shield/gps/status"));
 assert.equal(healthy.status,200);
 const data=await healthy.json();
 assert.equal(data.enabled,true);
 assert.equal(data.configurationAvailable,true);
 assert.equal(data.enforcing,true);
 assert.equal(data.policyRevision,"gps-outside-coarse-accuracy-v3");
 assert.equal(JSON.stringify(data).includes("latitude"),false);
 const invalid=await invoke(req("/__shield/gps/status"),{...cfg,GPS_GATE_SESSION_SECRET:undefined});
 assert.equal(invalid.status,503);
 const bad=await invalid.json();
 assert.equal(bad.policyRevision,"gps-outside-coarse-accuracy-v3");
 assert.equal(bad.configurationAvailable,false);
});

test("actual GPS boundary 403 hands Telegram notification to waitUntil without coordinates",async()=>{
 const kvMap=new Map(),pending=[],messages=[];
 const kv={async get(key){return kvMap.get(key)||null;},async put(key,val){kvMap.set(key,val);}};
 const env={...cfg,GPS_POLYGON_MODE:"enforce",
  GPS_POLYGON_ENFORCEMENT_APPROVED:"true",
  GPS_OSM_APPROXIMATE_ENFORCEMENT_APPROVED:"true",
  GPS_BOUNDARY_BUFFER_METERS:"30",
  GPS_CAMPUS_POLYGONS_JSON:researchOSM,
  GPS_TELEGRAM_ALERTS_ENABLED:"true",
  TELEGRAM_BOT_TOKEN:"123456789:"+ "A".repeat(35),
  TELEGRAM_CHAT_ID:"-1001234567890",CONSENT_KV:kv};
 const request=req("/__shield/gps/verify","POST",{
  "Origin":HOST,"Sec-Fetch-Site":"same-origin",
  "Content-Type":"application/json","CF-Connecting-IP":"198.51.100.18"
 },JSON.stringify({lat:5.36870,lon:100.220435,accuracy:5}));
 const priorFetch=globalThis.fetch;
 globalThis.fetch=async (url,options)=>{
  messages.push(JSON.parse(options.body).text);
  return new Response(JSON.stringify({ok:true}),{status:200});
 };
 try{
  const denied=await guestGpsGate(request,env,new URL(request.url),
   {waitUntil:p=>pending.push(p)},"33333333-4444-5555-6666-777777777777");
  assert.equal(denied.status,403);
  assert.equal((await denied.json()).error,"CAMPUS_BOUNDARY_UNCERTAIN");
  assert.equal(denied.headers.get("Set-Cookie"),null);
  await Promise.all(pending);
  assert.equal(messages.length,1);
  assert.match(messages[0],/CAMPUS_BOUNDARY_UNCERTAIN/);
  assert.match(messages[0],/33333333-4444-5555-6666-777777777777/);
  assert.equal(messages[0].includes("5.36870"),false);
  assert.equal(messages[0].includes("100.220435"),false);
  assert.equal(messages[0].includes("198.51.100.18"),false);
 }finally{globalThis.fetch=priorFetch;}
});

test("public fingerprinted Vite CSS, JS, fonts are served without GPS cookies",async()=>{
 const paths=[
  "/assets/DynamicPage-CqJImg6h.css",
  "/assets/main-BeRavZsA.js",
  "/assets/index-AbCd1234.woff2",
  "/assets/page-12345678.mjs",
 ];
 for(const p of paths){
  for(const method of ["GET","HEAD"]){
   const response=await invoke(req(p,method,{Accept:p.endsWith(".css")?"text/css":"*/*"}));
   assert.equal(response,null,`${p} ${method} should pass through to origin`);
  }
 }
 // Public build styles must still load if GPS configuration becomes unavailable.
 const unavailable={...cfg,GPS_GATE_SESSION_SECRET:"bad"};
 assert.equal(await invoke(req("/assets/DynamicPage-CqJImg6h.css","GET",{Accept:"text/css"}),unavailable),null);
});
test("GPS asset bypass never applies to private photos, APIs, unhashed assets or writes",async()=>{
 for(const p of [
  "/assets/jingxin-memory-hq.avif",
  "/media/jingxin/shared-memory.jpg",
  "/assets/logo.css",
  "/assets/DynamicPage-CqJImg6h.css/map",
  "/assets/DynamicPage-CqJImg6h.css/../admin",
  "/api/ai/chat",
  "/assets/DynamicPage-CqJImg6h.html",
  "/assets/protected-AbCd1234.json"
 ]){
  const response=await invoke(req(p,"GET",{Accept:"application/json"}));
  assert.ok(response&&response.status===403,`${p} must remain gated`);
 }
 for(const method of ["POST","PUT","DELETE"]){
  const response=await invoke(req("/assets/DynamicPage-CqJImg6h.css",method,
    {"Content-Type":"text/plain",Accept:"application/json"},"test-body"));
  assert.equal(response.status,403,method);
 }
});

test("confirmed outside campus fast-pass skips repeated HTML GPS prompts for 15 minutes",async()=>{
 const seen=new Map();
 const kv={get:async key=>seen.get(key)||null,put:async(key,value)=>{seen.set(key,value);}};
 const env={...cfg,GPS_RECHECK_EVERY_DOCUMENT:"true",
  GPS_OUTSIDE_SESSION_FASTPASS:"true",CONSENT_KV:kv};
 const hub="https://vynalthai.com";
 const first=await invoke(new Request(hub+"/dashboard",{
  headers:{Accept:"text/html","Sec-Fetch-Dest":"document"}
 }),env);
 assert.equal(first.status,403,"first document requires browser location");
 const verified=await invoke(new Request(hub+"/__shield/gps/verify",{
  method:"POST",headers:{Origin:hub,"Content-Type":"application/json",
    "Sec-Fetch-Site":"same-origin"},
  body:JSON.stringify({lat:5.4,lon:100.25,accuracy:25,returnPath:"/dashboard"})
 }),env);
 assert.equal(verified.status,200);
 const signed=verified.headers.getSetCookie()
  .find(x=>x.startsWith("__Host-vynalth-geo=")).split(";")[0];
 const html=path=>new Request(hub+path,{
  headers:{Accept:"text/html","Sec-Fetch-Dest":"document",Cookie:signed}});
 assert.equal(await invoke(html("/dashboard"),env),null,
  "outside verdict must directly allow first document");
 assert.equal(await invoke(html("/another-page"),env),null,
  "outside verdict must allow navigation without fresh location prompts");
 assert.equal(await invoke(html("/dashboard?refresh=1"),env),null,
  "outside verdict must allow F5 refresh");
 assert.equal((await invoke(new Request("https://vyncuslim.com/dashboard",{
  headers:{Cookie:signed,Accept:"text/html","Sec-Fetch-Dest":"document"}
 }),env)).status,302,"outside signature remains host-bound");
 const old=await invoke(html("/dashboard"),{...env,GPS_OUTSIDE_SESSION_FASTPASS:"false"});
 assert.equal(old.status,403,"disabling fast-pass restores strict per-page GPS");
});

test("outside fast-pass rejects forged, expired, near-boundary and blocked cookies",async()=>{
 const env={...cfg,GPS_RECHECK_EVERY_DOCUMENT:"true",
  GPS_OUTSIDE_SESSION_FASTPASS:"true"};
 const hub="https://vynalthai.com";
 const request=cookie=>new Request(hub+"/dashboard",{
  headers:{Accept:"text/html","Sec-Fetch-Dest":"document",Cookie:cookie}});
 for(const cookie of [
  "",
  "__Host-vynalth-geo=123.fake.signature",
  "__Host-vynalth-geo=invalid"
 ]){
  assert.equal((await invoke(request(cookie),env)).status,403);
 }
 const expiry=Math.floor(Date.now()/1000)-5;
 const nonce=b64(new Uint8Array(16).fill(7));
 const expired=expiry+"."+nonce+"."+
  await mac(SESSION_SECRET,[expiry,nonce,"vynalthai.com","outside"].join("|"));
 assert.equal((await invoke(request("__Host-vynalth-geo="+expired),env)).status,403,
  "expired outside verdict must be challenged");
 const nearExpiry=Math.floor(Date.now()/1000)+180;
 const near=nearExpiry+"."+nonce+"."+
  await mac(SESSION_SECRET,[nearExpiry,nonce,"vynalthai.com","nearby"].join("|"));
 assert.equal((await invoke(request("__Host-vynalth-geo="+near),env)).status,403,
  "nearby verdict must still recheck on every document");
 const blocked=expiry+450+"."+nonce+"."+
  await mac(SESSION_SECRET,[String(expiry+450),nonce,"vynalthai.com","inside"].join("|"));
 const response=await invoke(request("__Host-vynalth-geo="+near+
  "; __Host-vynalth-geo-block="+blocked),env);
 assert.equal(response.status,403,"a signed campus block takes priority");
});
