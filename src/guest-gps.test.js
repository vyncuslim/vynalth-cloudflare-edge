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
 for(const state of ["trust","contact"]){
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
test("verified campus coordinates return 403 and do not emit signed cookie",async()=>{
 const response=await verifyCoords(5.3677,100.21995,10);
 assert.equal(response.status,403);
 assert.equal((await response.json()).error,"CAMPUS_RESTRICTED");
 assert.equal(response.headers.get("Set-Cookie"),null);
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
