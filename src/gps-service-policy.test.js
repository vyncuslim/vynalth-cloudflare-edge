import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import edge from "./index.js";
import {serviceSigningPayload,verifyGpsServiceCall} from "./gps-service-policy.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const AUTH="test-service-auth-shared-secret-only-for-ci-012345678901";
const ENV={GPS_SERVICE_AUTH_SECRET:AUTH,GPS_GATE_ENABLED:"true",
 GPS_GATE_SESSION_SECRET:"test-gps-verdict-hmac-secret-for-ci-12345678901234567890",
 GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",GPS_CAMPUS_RADIUS_METERS:"120"};
async function sign(request,ip="203.0.113.72",country="MY",secret=AUTH){
 const ts=String(Math.floor(Date.now()/1000));
 const key=await webcrypto.subtle.importKey("raw",new TextEncoder().encode(secret),
  {name:"HMAC",hash:"SHA-256"},false,["sign"]);
 const output=new Uint8Array(await webcrypto.subtle.sign("HMAC",key,
  new TextEncoder().encode(serviceSigningPayload(request,ts,ip,country))));
 const headers=new Headers(request.headers);
 for(const name of [...headers.keys()])
  if(name.startsWith("x-vynalth-gps-service-"))headers.delete(name);
 headers.set("CF-Connecting-IP",ip);
 headers.set("x-vynalth-gps-service-v","1");
 headers.set("x-vynalth-gps-service-ts",ts);
 headers.set("x-vynalth-gps-service-ip",ip);
 headers.set("x-vynalth-gps-service-country",country);
 headers.set("x-vynalth-gps-service-sig",Buffer.from(output).toString("hex"));
 return new Request(request,{headers});
}
test("signed Service Binding call redirects to GPS hub and never calls origin",async()=>{
 const base=new Request("https://vyncuslim.com/",{headers:{Accept:"text/html"}});
 const req=await sign(base);
 const originalFetch=globalThis.fetch;let origins=0;
 globalThis.fetch=async()=>{origins++;throw Error("must not proxy an internal policy request")};
 try{
  const response=await edge.fetch(req,ENV,{});
  assert.equal(response.status,302);
  assert.match(response.headers.get("location"),/^https:\/\/vynalthai\.com\/__shield\/gps\/bridge/);
  assert.equal(origins,0);
  assert.equal(response.headers.get("x-vynalth-edge"),"cloudflare-worker");
 }finally{globalThis.fetch=originalFetch;}
});
test("authenticated policy-only request explicitly authorizes recovery/skip with 204",async()=>{
 const base=new Request("https://vyncuslim.com/en/legal/privacy");
 const response=await edge.fetch(await sign(base),ENV,{});
 assert.equal(response.status,204);
 assert.equal(response.headers.get("x-vynalth-gps-policy"),"allow");
});
test("missing or forged internal HMAC never becomes an allow decision",async()=>{
 const base=new Request("https://vyncuslim.com/",{headers:{Accept:"text/html"}});
 let fake=await sign(base,"203.0.113.72","MY","another-not-matching-signing-secret-1234567890");
 const denied=await edge.fetch(fake,ENV,{});
 assert.equal(denied.status,403);
 assert.equal(denied.headers.get("x-vynalth-gps-policy"),"invalid-service-auth");
 const config=await edge.fetch(await sign(base),{...ENV,GPS_SERVICE_AUTH_SECRET:undefined},{});
 assert.equal(config.status,403);
});
test("signature binds request URL, method, source IP and Cloudflare country",async()=>{
 const orig=new Request("https://vyncuslim.com/a?query=1");
 const signed=await sign(orig);
 for(const field of [
  ["url","https://vyncuslim.com/b?query=1"],
  ["ip","198.51.100.56"],
  ["country","US"]
 ]){
  let request;
  if(field[0]==="url")request=new Request(field[1],signed);
  else {const h=new Headers(signed.headers);
    h.set(field[0]==="ip"?"x-vynalth-gps-service-ip":"x-vynalth-gps-service-country",field[1]);
    request=new Request(signed,{headers:h});}
  const result=await verifyGpsServiceCall(request,ENV,new URL(request.url));
  assert.equal(result.authenticated,false,field[0]);
 }
});
test("a signed MY source always enters GPS even if the internal edge sees a foreign source",async()=>{
 const env={...ENV,GPS_REGION_TIMEZONE_ENABLED:"true"};
 const request=new Request("https://vyncuslim.com/",{headers:{Accept:"text/html"}});
 const r=await edge.fetch(await sign(request,"203.0.113.72","MY"),env,{});
 assert.equal(r.status,302);
 assert.match(r.headers.get("location"),/^https:\/\/vynalthai\.com\/__shield\/gps\/bridge/);
});
test("trusted public GPS status is handled by policy-only service without origin access",async()=>{
 const base=new Request("https://vyncuslim.com/__shield/gps/status");
 const result=await edge.fetch(await sign(base),ENV,{});
 assert.equal(result.status,200);
 const json=await result.json();
 assert.equal(json.enabled,true);
 assert.equal(json.enforcing,true);
});
