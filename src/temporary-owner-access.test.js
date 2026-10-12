import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto} from "node:crypto";
import edge from "./index.js";
import {handleTemporaryOwnerAccess,hasTemporaryOwnerPass,OWNER_PORTAL,OWNER_ACCESS_TTL}
 from "./temporary-owner-access.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const code="unit-test-only-vynalth-owner-code";
const signingSecret="unit-test-only-owner-cookie-signing-secret-for-workers-2026";
const ip="203.0.113.123";
const ua="Vynalth UnitTest Browser";
function kv(){
 const state=new Map();
 return {
  async get(key){return state.get(key)||null},
  async put(key,value,opts){assert.equal(opts.expirationTtl,900);state.set(key,value)},
  async delete(key){state.delete(key)},
  size(){return state.size}
 };
}
function env(extra={}){
 return {
  VYNALTH_TEMP_ACCESS_ENABLED:"true",
  VYNALTH_TEMP_ACCESS_CODE:code,
  VYNALTH_TEMP_ACCESS_SIGNING_SECRET:signingSecret,
  CONSENT_KV:kv(),
  GPS_GATE_ENABLED:"true",
  GPS_GATE_SESSION_SECRET:"unit-test-guest-gps-secret-string-0123456789012345",
  GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",
  GPS_CAMPUS_RADIUS_METERS:"180",
  GPS_RECHECK_EVERY_DOCUMENT:"true",
  ...extra
 };
}
function req(url="https://vynalthai.com"+OWNER_PORTAL,method="GET",headers={},body){
 return new Request(url,{
  method,body,headers:{"CF-Connecting-IP":ip,"User-Agent":ua,
   "Accept":"text/html",...headers}
 });
}
async function login(environment,accessCode=code,opts={}){
 const form=await edge.fetch(req(),environment,{});
 assert.equal(form.status,200);
 const csrf=form.headers.get("Set-Cookie").split(";")[0];
 const token=csrf.split("=")[1];
 assert.match(token,/^[a-f0-9]{40}$/);
 const body=new URLSearchParams({csrf:token,code:accessCode}).toString();
 const request=req(undefined,"POST",{
  Cookie:csrf,Origin:"https://vynalthai.com",
  "Content-Type":"application/x-www-form-urlencoded",
  ...opts.headers
 },body);
 return edge.fetch(request,environment,{});
}
test("code login has anti-CSRF form and sets 10-minute host-only HttpOnly pass",async()=>{
 const e=env();
 const result=await login(e);
 assert.equal(result.status,303);
 assert.equal(result.headers.get("Location"),"https://vynalthai.com/");
 const all=result.headers.getSetCookie();
 const pass=all.find(x=>x.startsWith("__Host-vynalth-owner-pass="));
 assert.ok(pass);
 assert.match(pass,/Max-Age=600/);
 assert.match(pass,/Secure/);
 assert.match(pass,/HttpOnly/);
 assert.match(pass,/SameSite=Strict/);
 assert.doesNotMatch(pass,/Domain=/);
 assert.equal(OWNER_ACCESS_TTL,600);
 assert.ok(all.find(x=>x.startsWith("__Host-vynalth-owner-csrf=")&&x.includes("Max-Age=0")));
 assert.equal(e.CONSENT_KV.size(),0);
});
test("valid temporary owner cookie bypasses GPS challenge but not application auth",async()=>{
 const e=env();
 const success=await login(e);
 const pass=success.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-owner-pass=")).split(";")[0];
 assert.equal(await hasTemporaryOwnerPass(req("https://vynalthai.com/","GET",{Cookie:pass}),e,new URL("https://vynalthai.com/")),true);
 const before=await edge.fetch(req("https://vynalthai.com/"),e,{});
 assert.equal(before.status,403);
 let originCalls=0;const originalFetch=globalThis.fetch;
 globalThis.fetch=async()=>{originCalls++;return new Response("website",{status:200})};
 try{
  const after=await edge.fetch(req("https://vynalthai.com/","GET",{Cookie:pass}),e,{});
  assert.equal(after.status,200);
  assert.equal(await after.text(),"website");
  assert.equal(originCalls,1);
 }finally{globalThis.fetch=originalFetch}
});
test("pass binds to original IP, user agent and exact vynalthai.com host",async()=>{
 const e=env();
 const success=await login(e);
 const pass=success.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-owner-pass=")).split(";")[0];
 const url=new URL("https://vynalthai.com/");
 for(const h of [
  {"CF-Connecting-IP":"198.51.100.1",Cookie:pass},
  {"User-Agent":"Different device",Cookie:pass},
  {Cookie:pass.replace(/.$/,"A")}
 ]){
  const request=req(url.toString(),"GET",h);
  assert.equal(await hasTemporaryOwnerPass(request,e,url),false);
 }
 const otherUrl=new URL("https://vyncuslim.com/");
 assert.equal(await hasTemporaryOwnerPass(req(otherUrl.toString(),"GET",{Cookie:pass}),e,otherUrl),false);
});
test("cookie is rejected after exactly 600 seconds",async()=>{
 const e=env();const success=await login(e);
 const pass=success.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-owner-pass=")).split(";")[0];
 const url=new URL("https://vynalthai.com/");
 const request=req(url.toString(),"GET",{Cookie:pass});
 const actualNow=Date.now,exp=Number(pass.split("=")[1].split(".")[0]);
 try{
  Date.now=()=>exp*1000;
  assert.equal(await hasTemporaryOwnerPass(request,e,url),false);
 }finally{Date.now=actualNow}
});
test("wrong codes lock out after five tries and do not grant access",async()=>{
 const e=env();
 for(let i=0;i<5;i++){
  const response=await login(e,"incorrect-test-code");
  assert.equal(response.status,403);
  assert.equal(response.headers.getSetCookie().some(x=>x.startsWith("__Host-vynalth-owner-pass=")),false);
 }
 const sixth=await login(e,code);
 assert.equal(sixth.status,429);
 assert.equal(sixth.headers.get("Retry-After"),"900");
 assert.equal(e.CONSENT_KV.size(),1);
});
test("CSRF, wrong origin, unconfigured secret and missing KV fail closed",async()=>{
 const e=env();
 const wrongOrigin=await login(e,code,{headers:{Origin:"https://evil.example"}});
 assert.equal(wrongOrigin.status,403);
 const noCookie=await edge.fetch(req(undefined,"POST",{
  Origin:"https://vynalthai.com",
  "Content-Type":"application/x-www-form-urlencoded"
 },"csrf=123&code="+code),e,{});
 assert.equal(noCookie.status,403);
 const missing=await edge.fetch(req(),env({VYNALTH_TEMP_ACCESS_CODE:undefined}),{});
 assert.equal(missing.status,503);
 const noStorage=await edge.fetch(req(),env({CONSENT_KV:undefined}),{});
 assert.equal(noStorage.status,503);
 const disabled=await edge.fetch(req(),env({VYNALTH_TEMP_ACCESS_ENABLED:"false"}),{});
 assert.equal(disabled.status,404);
});
test("portal never uses GPS itself, is exact-path only, and never serves foreign sites",async()=>{
 const e=env();
 const notPortal=await handleTemporaryOwnerAccess(req("https://vyncuslim.com"+OWNER_PORTAL),e,new URL("https://vyncuslim.com"+OWNER_PORTAL));
 assert.equal(notPortal,null);
 const wrongPath=await handleTemporaryOwnerAccess(req("https://vynalthai.com/admin/other"),e,new URL("https://vynalthai.com/admin/other"));
 assert.equal(wrongPath,null);
});
test("an owner GPS pass does not bypass independent School IP policy",async()=>{
 const e=env({SCHOOL_POLICY:{async fetch(){
  return new Response("school restriction",{status:403,headers:{"X-School-Policy":"blocked"}});
 }}});
 const success=await login(e);
 const pass=success.headers.getSetCookie().find(x=>x.startsWith("__Host-vynalth-owner-pass=")).split(";")[0];
 const after=await edge.fetch(req("https://vynalthai.com/","GET",{Cookie:pass}),e,{});
 assert.equal(after.status,403);
 assert.equal(after.headers.get("X-School-Policy"),"blocked");
});
