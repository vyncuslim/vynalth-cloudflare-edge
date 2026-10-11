import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { handleConsentSsoBridge } from "./consent-sso-bridge.js";
import { signedSSO } from "./universal-consent.js";
const secret="test-only-strong-secret-should-never-be-production-123456789";
const SSO_URL="https://vynalthai.com/__vynalth/sso/session";
const env={CONSENT_SSO_BRIDGE_ENABLED:"true",CONSENT_SSO_SIGNING_SECRET:secret};
function token(status="user",expiry=600,host="vynalthai.com",verified=true){
 const claim={sub:"00000000-0000-0000-0000-000000000012",sid:"abcdef12345678",
  status,host,exp:Math.floor(Date.now()/1000)+expiry,
  email:"verified@example.org",email_verified:verified};
 const p=Buffer.from(JSON.stringify(claim)).toString("base64url");
 return p+"."+createHmac("sha256",secret).update(p).digest("base64url");
}
function request(assertion,host="vynalthai.com",origin="https://vynalthai.com"){
 return new Request("https://"+host+"/__vynalth/sso/session",{
 method:"POST",headers:{Origin:origin,"Content-Type":"application/json","Sec-Fetch-Site":"same-origin"},
 body:JSON.stringify({assertion})});
}
const run=(r,e=env)=>handleConsentSsoBridge(r,e,new URL(r.url));
test("SSO bridge stays disabled by default, independent of Cookie Consent",async()=>{
 const r=await run(request(token()),{...env,CONSENT_SSO_BRIDGE_ENABLED:"false"});
 assert.equal(r.status,503);
 assert.equal(r.headers.get("Set-Cookie"),null);
});
test("verified signed canonical SSO is bound as Secure HttpOnly first-party Cookie",async()=>{
 const result=await run(request(token()));
 assert.equal(result.status,200);
 const cookie=result.headers.get("Set-Cookie");
 assert.match(cookie,/^__Secure-vynalth-sso=/);
 assert.match(cookie,/Domain=vynalthai\.com/);
 assert.match(cookie,/Secure; HttpOnly; SameSite=Lax/);
 assert.match(cookie,/Max-Age=/);
 const check=new Request("https://vynalthai.com/__vynalth/consent/session",{
 headers:{Cookie:cookie.split(";")[0]}});
 assert.equal((await signedSSO(check,env,"vynalthai.com")).status,"user");
});
test("tampered, expired, wrong host, unverified email or privileged assertion is rejected",async()=>{
 const valid=token();
 const denied=[valid.slice(0,-1)+(valid.endsWith("A")?"B":"A"),token("user",-2),
  token("user",600,"vyncuslim.com"),token("user",600,"vynalthai.com",false),
  token("trust")];
 for(const claim of denied){
  const r=await run(request(claim));
  assert.equal(r.status,403);
  assert.equal(r.headers.get("Set-Cookie"),null);
 }
});
test("request cannot bind cross-site or on an unauthorized hostname",async()=>{
 const cross=await run(request(token(),"vynalthai.com","https://attacker.example"));
 assert.equal(cross.status,403);
 const other=await run(request(token(),"vyncuslim.com"));
 assert.equal(other,null);
 const noBody=await run(new Request(SSO_URL,{method:"POST",headers:{Origin:"https://vynalthai.com","Content-Type":"application/json"}}));
 assert.equal(noBody.status,400);
});
test("explicit same-origin logout clears the first-party cookie",async()=>{
 const req=new Request(SSO_URL+"/clear",{method:"POST",headers:{Origin:"https://vynalthai.com","Sec-Fetch-Site":"same-origin"}});
 const r=await run(req);
 assert.equal(r.status,200);
 assert.match(r.headers.get("Set-Cookie"),/Max-Age=0/);
 const denied=await run(new Request(SSO_URL+"/clear",{method:"POST",headers:{Origin:"https://evil.example"}}));
 assert.equal(denied.status,403);
});

test("SSO status probe verifies HttpOnly cookie without enabling Consent or leaking PII",async()=>{
 const validToken=token();
 const req=new Request(SSO_URL+"/status",{method:"GET",headers:{
  Cookie:"__Secure-vynalth-sso="+validToken
 }});
 const active=await run(req,{...env,CONSENT_CMP_ENABLED:"false"});
 assert.equal(active.status,200);
 assert.deepEqual(await active.json(),{authenticated:true});
 assert.equal(active.headers.get("Cache-Control"),"private, no-store");
 assert.equal(active.headers.get("Vary"),"Cookie");
 assert.equal(active.headers.get("Set-Cookie"),null);
 const anonymous=await run(new Request(SSO_URL+"/status"),env);
 assert.equal(anonymous.status,200);
 assert.deepEqual(await anonymous.json(),{authenticated:false});
 const expired=await run(new Request(SSO_URL+"/status",{
  headers:{Cookie:"__Secure-vynalth-sso="+token("user",-1)}
 }));
 assert.deepEqual(await expired.json(),{authenticated:false});
 const invalidMethod=await run(new Request(SSO_URL+"/status",{method:"POST"}));
 assert.equal(invalidMethod.status,405);
 const disabled=await run(new Request(SSO_URL+"/status"),{...env,CONSENT_SSO_BRIDGE_ENABLED:"false"});
 assert.equal(disabled.status,503);
});

test("emergency rollback disables new SSO binding but still allows first-party cookie clearing",async()=>{
 const off={...env,CONSENT_SSO_BRIDGE_ENABLED:"false"};
 const rejected=await run(request(token()),off);
 assert.equal(rejected.status,503);
 const clear=new Request(SSO_URL+"/clear",{method:"POST",headers:{
  Origin:"https://vynalthai.com","Sec-Fetch-Site":"same-origin"
 }});
 const result=await run(clear,off);
 assert.equal(result.status,200);
 assert.deepEqual(await result.json(),{cleared:true});
 assert.match(result.headers.get("Set-Cookie"),/__Secure-vynalth-sso=;.*Max-Age=0/);
 const forbidden=await run(new Request(SSO_URL+"/clear",{method:"POST",headers:{
  Origin:"https://evil.example","Sec-Fetch-Site":"cross-site"
 }}),off);
 assert.equal(forbidden.status,403);
});
