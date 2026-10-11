import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { guestGpsGate } from "./guest-gps.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const secret="gps-test-region-binding-secret-000000000000000000000000000";
const env={GPS_GATE_ENABLED:"true",GPS_REGION_TIMEZONE_ENABLED:"true",
 GPS_GATE_SESSION_SECRET:secret,GPS_CAMPUS_LAT:"5.3677",
 GPS_CAMPUS_LON:"100.21995",GPS_CAMPUS_RADIUS_METERS:"120"};
const site="https://vynalthai.com";
function req(path="/",country="US",ip="198.51.100.45",method="GET",body,headers={}){
 const request=new Request(site+path,{method,body,headers:{
  Accept:method==="GET"?"text/html":"application/json",
  "CF-Connecting-IP":ip,...headers}});
 if(country!==null)Object.defineProperty(request,"cf",{value:{country}});
 return request;
}
const gate=(r,e=env)=>guestGpsGate(r,e,new URL(r.url));
async function check(country,timezone,ip="198.51.100.45",hostEnv=env){
 const request=req("/__shield/gps/region-check",country,ip,"POST",
  JSON.stringify({timezone}),
  {Origin:site,"Content-Type":"application/json","Sec-Fetch-Site":"same-origin"});
 const response=await gate(request,hostEnv);
 return response;
}
test("Malaysia IP always displays original GPS page regardless of timezone header",async()=>{
 const r=req("/", "MY");
 r.headers.set("CF-IPCountry","US"); // user-supplied country is never authoritative
 const decision=await gate(r);
 assert.equal(decision.status,403);
 assert.match(await decision.text(),/Precise location required/);
});
test("unknown location and Tor IP never bypass the GPS gate",async()=>{
 for(const country of [null,"XX","T1"]){
  const decision=await gate(req("/",country));
  assert.equal(decision.status,403);
  assert.match(await decision.text(),/Precise location required/);
 }
});
test("overseas IP starts with quiet region check, without GPS permission",async()=>{
 const page=await gate(req("/"));
 assert.equal(page.status,200);
 const html=await page.text();
 assert.match(html,/Checking regional access/);
 assert.doesNotMatch(html,/getCurrentPosition/);
 const client=await gate(req("/__shield/gps/region-client.js"));
 assert.equal(client.status,200);
 const script=await client.text();
 assert.match(script,/Intl.DateTimeFormat/);
 assert.doesNotMatch(script,/geolocation|GPS_CAMPUS_LAT/);
});
test("overseas IP plus Malaysia timezone forces GPS even through VPN egress",async()=>{
 for(const tz of ["Asia/Kuala_Lumpur","Asia/Kuching"]){
  const response=await check("US",tz);
  assert.equal(response.status,200);
  const result=await response.json();
  assert.equal(result.gpsRequired,true);
  const cookie=response.headers.get("Set-Cookie").split(";")[0];
  const visit=await gate(req("/","US","198.51.100.45","GET",undefined,{Cookie:cookie}));
  assert.equal(visit.status,403);
  assert.match(await visit.text(),/Precise location required/);
 }
});
test("overseas IP and valid overseas timezone can access without GPS",async()=>{
 const response=await check("GB","Europe/London");
 assert.equal(response.status,200);
 assert.equal((await response.json()).gpsRequired,false);
 const signed=response.headers.get("Set-Cookie");
 assert.match(signed,/HttpOnly/);
 assert.match(signed,/Max-Age=120/);
 const cookie=signed.split(";")[0];
 assert.equal(await gate(req("/","GB","198.51.100.45","GET",undefined,{Cookie:cookie})),null);
 const spoofed=await gate(req("/","GB","203.0.113.44","GET",undefined,{Cookie:cookie}));
 assert.equal(spoofed.status,200,"Changed IP must require a new regional check");
 const changedCountry=await gate(req("/","US","198.51.100.45","GET",undefined,{Cookie:cookie}));
 assert.equal(changedCountry.status,200);
 const malaysian=await gate(req("/","MY","198.51.100.45","GET",undefined,{Cookie:cookie}));
 assert.equal(malaysian.status,403,"Malaysia IP always requires GPS");
});
test("invalid, missing or fabricated timezones cannot create overseas bypass",async()=>{
 for(const tz of ["","Mars/Olympus","Asia/Kuala_Lumpur\u000aFake"]){
  const response=await check("US",tz);
  assert.equal(response.status,200);
  assert.equal((await response.json()).gpsRequired,true);
 }
 const bad=req("/__shield/gps/region-check","US","198.51.100.45","POST",
  JSON.stringify({timezone:"Europe/London"}),
  {Origin:"https://attacker.example","Content-Type":"application/json"});
 const rejected=await gate(bad);
 assert.equal(rejected.status,403);
 assert.equal((await rejected.json()).error,"ORIGIN_INVALID");
});
test("trusted signed status exemptions and old default behavior remain unchanged",async()=>{
 const standard={...env,GPS_REGION_TIMEZONE_ENABLED:"false"};
 const response=await gate(req("/","GB"),standard);
 assert.equal(response.status,403);
 assert.match(await response.text(),/Precise location required/);
 const checkResult=await gate(req("/__shield/gps/status","GB"));
 assert.equal(checkResult.status,200);
 const status=await checkResult.json();
 assert.equal(status.regionalPolicy.enabled,true);
 assert.equal(status.regionalPolicy.vpnDetection,"not-guaranteed");
});
