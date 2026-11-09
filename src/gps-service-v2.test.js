import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import edge from "./index.js";
import { createSignedGpsPolicyRequest } from "./gps-service-client.js";
import { verifyGpsServiceCall } from "./gps-service-policy.js";
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
function source(region, code, country="MY"){
 const req=new Request("https://vyncuslim.com/private",{headers:{
   "Accept":"text/html",
   "CF-Connecting-IP":"198.51.100.7",
   "x-vynalth-gps-service-v":"2",
   "x-vynalth-gps-service-sig":"attacker-supplied"
 }});
 Object.defineProperty(req,"cf",{value:{country,region,regionCode:code}});
 return req;
}
test("v2 signed Penang STATE requires GPS even without island city evidence",async()=>{
 const r=await createSignedGpsPolicyRequest(source("Penang","07"),ENV);
 const a=await verifyGpsServiceCall(r,ENV,new URL(r.url));
 assert.equal(a.authenticated,true);
 assert.equal(a.country,"MY");
 assert.equal(a.regionCode,"07");
 assert.equal(a.region,"Penang");
 assert.equal(r.headers.get("x-vynalth-gps-service-v"),"2");
 const decision=await edge.fetch(r,ENV,{});
 assert.equal(decision.status,403); // signed state requires campus geofence consent
 assert.match(await decision.text(),/Precise location required/);
});
test("v2 signed Johor state returns authorized 204 to the same policy-only route",async()=>{
 const req=await createSignedGpsPolicyRequest(source("Johor","01"),ENV);
 const result=await edge.fetch(req,ENV,{});
 assert.equal(result.status,204);
 assert.equal(result.headers.get("X-Vynalth-GPS-Policy"),"allow");
});
test("v2 service signature binds both state code and name; tampering rejects",async()=>{
 const base=await createSignedGpsPolicyRequest(source("Penang","07"),ENV);
 for(const [name,value] of [
  ["x-vynalth-gps-service-region-code","01"],
  ["x-vynalth-gps-service-region","Johor"],
  ["x-vynalth-gps-service-country","SG"],
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
