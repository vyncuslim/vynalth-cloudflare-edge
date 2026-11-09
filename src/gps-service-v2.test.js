import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import edge from "./index.js";
import { createSignedGpsPolicyRequest } from "./gps-service-client.js";
import { verifyGpsServiceCall, serviceSigningPayload } from "./gps-service-policy.js";
import { gpsPenangOnlyDecision } from "./gps-penang-only.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const SECRET="gps-region-signed-policy-test-key-is-over-32-characters";
const ENV={
 GPS_SERVICE_AUTH_SECRET:SECRET,
 GPS_GATE_ENABLED:"true",
 GPS_PENANG_ONLY_ENABLED:"true",
 GPS_REGION_TIMEZONE_ENABLED:"true",
 GPS_GATE_SESSION_SECRET:"gps-geofence-test-session-secret-is-long-enough",
 GPS_CAMPUS_LAT:"5.3677",
 GPS_CAMPUS_LON:"100.21995",
 GPS_CAMPUS_RADIUS_METERS:"120",
};
function source(region, code, country="MY", city=""){
 const req=new Request("https://vyncuslim.com/private",{headers:{
   "Accept":"text/html",
   "CF-Connecting-IP":"198.51.100.7",
   "x-vynalth-gps-service-v":"2",
   "x-vynalth-gps-service-sig":"attacker-supplied"
 }});
 Object.defineProperty(req,"cf",{value:{country,region,regionCode:code,city}});
 return req;
}
test("v3 signed Penang STATE requires GPS when city is unknown",async()=>{
 const r=await createSignedGpsPolicyRequest(source("Penang","07"),ENV);
 const a=await verifyGpsServiceCall(r,ENV,new URL(r.url));
 assert.equal(a.authenticated,true);
 assert.equal(a.country,"MY");
 assert.equal(a.regionCode,"07");
 assert.equal(a.region,"Penang");
 assert.equal(r.headers.get("x-vynalth-gps-service-v"),"3");
 const decision=await edge.fetch(r,ENV,{});
 assert.equal(decision.status,302); // cross-domain request is sent to first-party GPS consent hub
 assert.match(decision.headers.get("location")||"",/^https:\/\/vynalthai\.com\/__shield\/gps\//);
});
test("v3 signed Johor state returns authorized 204 to the same policy-only route",async()=>{
 const req=await createSignedGpsPolicyRequest(source("Johor","01"),ENV);
 const result=await edge.fetch(req,ENV,{});
 assert.equal(result.status,204);
 assert.equal(result.headers.get("X-Vynalth-GPS-Policy"),"allow");
});
test("v3 service signature binds state and city; tampering rejects",async()=>{
 const base=await createSignedGpsPolicyRequest(source("Penang","07"),ENV);
 for(const [name,value] of [
  ["x-vynalth-gps-service-region-code","01"],
  ["x-vynalth-gps-service-region","Johor"],
  ["x-vynalth-gps-service-country","SG"],
  ["x-vynalth-gps-service-city","Butterworth"],
  ["x-vynalth-gps-service-v","1"],
 ]){
  const headers=new Headers(base.headers);headers.set(name,value);
  const forged=new Request(base,{headers});
  const verdict=await verifyGpsServiceCall(forged,ENV,new URL(base.url));
  assert.equal(verdict.authenticated,false,name);
 }
});
test("caller does not trust spoofed visitor service headers",async()=>{
 const a=await createSignedGpsPolicyRequest(source("Johor","01"),ENV);
 const verified=await verifyGpsServiceCall(a,ENV,new URL(a.url));
 assert.equal(verified.authenticated,true);
 assert.equal(verified.regionCode,"01");
});
test("overseas caller country is exempt even with misleading Penang region",async()=>{
 const a=await createSignedGpsPolicyRequest(source("Penang","07","SG"),ENV);
 const verified=await verifyGpsServiceCall(a,ENV,new URL(a.url));
 assert.equal(verified.country,"SG");
 assert.equal(verified.regionCode,"");
 assert.equal(gpsPenangOnlyDecision(verified.request,ENV,verified.country,
   verified.regionCode,verified.region).requireGPS,false);
});
test("v1 signed-country only is never treated as proof of Penang",async()=>{
 const req=source("Penang","07");
 assert.equal(gpsPenangOnlyDecision(req,ENV,"MY").requireGPS,false);
});
test("conflicting trusted state code/name does not force inaccurate GPS prompt",async()=>{
 const req=source("Johor","07");
 assert.equal(gpsPenangOnlyDecision(req,ENV).requireGPS,false);
 assert.equal(gpsPenangOnlyDecision(req,ENV,"MY","07","Johor").requireGPS,false);
});

test("v3 service-bound Butterworth is allowed without location prompt",async()=>{
 const orig=source("Penang","07","MY","Butterworth");
 const signed=await createSignedGpsPolicyRequest(orig,ENV);
 const verified=await verifyGpsServiceCall(signed,ENV,new URL(signed.url));
 assert.equal(verified.authenticated,true);
 assert.equal(verified.version,"3");
 assert.equal(verified.city,"Butterworth");
 assert.equal(gpsPenangOnlyDecision(verified.request,ENV,verified.country,
   verified.regionCode,verified.region,verified.city).reason,"butterworth-ip-city-exempt");
 const response=await edge.fetch(signed,ENV,{});
 assert.equal(response.status,204);
 assert.equal(response.headers.get("X-Vynalth-GPS-Policy"),"allow");
});

test("v3 service input ignores browser-supplied fake city headers",async()=>{
 const orig=source("Penang","07","MY","George Town");
 orig.headers.set("X-City","Butterworth");
 orig.headers.set("x-vynalth-gps-service-city","Butterworth");
 const signed=await createSignedGpsPolicyRequest(orig,ENV);
 assert.equal(signed.headers.get("x-vynalth-gps-service-city"),"George Town");
 assert.equal((await edge.fetch(signed,ENV,{})).status,302);
});

test("signed v2 requests remain accepted but cannot assert a Butterworth exemption",async()=>{
 const orig=source("Penang","07","MY","Butterworth");
 const headers=new Headers(orig.headers);
 for(const key of [...headers.keys()])
   if(key.startsWith("x-vynalth-gps-service-"))headers.delete(key);
 const ts=String(Math.floor(Date.now()/1000));
 const ip=headers.get("CF-Connecting-IP"),country="MY",code="07",region="Penang";
 const payload=serviceSigningPayload(orig,ts,ip,country,code,region,"2");
 const key=await webcrypto.subtle.importKey("raw",new TextEncoder().encode(SECRET),
   {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const bytes=new Uint8Array(await webcrypto.subtle.sign("HMAC",key,new TextEncoder().encode(payload)));
 const sig=Buffer.from(bytes).toString("hex");
 for(const [name,value] of Object.entries({"v":"2","ts":ts,"sig":sig,
   "ip":ip,"country":country,"region-code":code,"region":region}))
   headers.set("x-vynalth-gps-service-"+name,value);
 const v2=new Request(orig,{headers});
 const verified=await verifyGpsServiceCall(v2,ENV,new URL(v2.url));
 assert.equal(verified.authenticated,true);
 assert.equal(verified.city,null);
 assert.equal((await edge.fetch(v2,ENV,{})).status,302);
 const forgedHeaders=new Headers(headers);
 forgedHeaders.set("x-vynalth-gps-service-city","Butterworth");
 const forged=new Request(orig,{headers:forgedHeaders});
 assert.equal((await verifyGpsServiceCall(forged,ENV,new URL(forged.url))).authenticated,false);
});
