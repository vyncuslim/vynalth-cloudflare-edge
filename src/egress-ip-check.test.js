import test from "node:test";
import assert from "node:assert/strict";
import {webcrypto,createHmac} from "node:crypto";
import {handleEgressIpCheck,checkSchoolEgressRestriction} from "./egress-ip-check.js";
if(!globalThis.crypto)globalThis.crypto=webcrypto;
const SECRET="school-egress-test-secret-do-not-use-production-123456";
const BASE="https://vynalthai.com/__shield/network/egress-ip";
const now=()=>Math.floor(Date.now()/1000);
const hmac=msg=>createHmac("sha256",SECRET).update(msg).digest("base64url");
function memoryKV(){
 const data=new Map();
 return {data,
  async get(key){return data.get(key)||null;},
  async put(key,value,options){data.set(key,value);data.set("ttl",options.expirationTtl);},
  async delete(key){data.delete(key);}
 };
}
const env=(kv,enabled="true")=>({
 SCHOOL_EGRESS_BLOCK_ENABLED:enabled,SCHOOL_EGRESS_SIGNING_SECRET:SECRET,SCHOOL_EGRESS_KV:kv
});
const request=(url,ip,init={})=>new Request(url,{
 ...init,headers:{"CF-Connecting-IP":ip,...(init.headers||{})}
});
const invoke=(r,e)=>handleEgressIpCheck(r,e,new URL(r.url));
async function observe(ip,e){
 let response=await invoke(request(BASE,ip),e);return [response,await response.json()];
}
const post=(url,ip,body,origin="https://vynalthai.com")=>
 request(url,ip,{method:"POST",headers:{Origin:origin,"Sec-Fetch-Site":"same-origin",
 "Content-Type":"application/json"},body:JSON.stringify(body)});
test("edge observer reports only CF observed address, no forged browser field",async()=>{
 const [r,j]=await observe("198.51.100.22",env(memoryKV(),"false"));
 assert.equal(r.status,200);
 assert.equal(j.ip,"198.51.100.22");
 assert.equal(j.source,"cloudflare-edge-request");
 assert.equal(j.proof,hmac("egress-v1|observed|198.51.100.22|"+j.observedAt));
 assert.equal(j.networkIdentityVerified,false);
 assert.equal(r.headers.get("Cache-Control").includes("no-store"),true);
 const missing=await invoke(new Request(BASE),env(memoryKV()));assert.equal(missing.status,503);
});
test("missing feature flag cannot create a block or deny traffic",async()=>{
 const store=memoryKV(),e=env(store,"false");
 const [,j]=await observe("198.51.100.42",e);
 const result=await invoke(post(BASE+"/block",j.ip,{
  ...j,confirmedSchoolNetwork:true,expiresAt:now()+60,
  authorization:hmac("egress-v1|approved|"+j.ip+"|"+j.observedAt+"|"+(now()+60))
 }),e);
 assert.equal(result.status,503);
 assert.equal(store.data.size,0);
 assert.equal(await checkSchoolEgressRestriction(request("https://vynalthai.com/",j.ip),e,
  new URL("https://vynalthai.com/")),null);
});
test("requires a recent signed observation AND owner-approved, same-IP authorization",async()=>{
 const store=memoryKV(),e=env(store);
 const [,j]=await observe("198.51.100.12",e);
 const expiry=now()+60;
 const candidate={ip:j.ip,observedAt:j.observedAt,proof:j.proof,
  expiresAt:expiry,confirmedSchoolNetwork:true,
  authorization:hmac("egress-v1|approved|"+j.ip+"|"+j.observedAt+"|"+expiry)};
 const forged=await invoke(post(BASE+"/block",j.ip,{...candidate,authorization:"A".repeat(43)}),e);
 assert.equal(forged.status,403);
 const cross=await invoke(post(BASE+"/block",j.ip,candidate,"https://evil.example"),e);
 assert.equal(cross.status,403);
 const changed=await invoke(post(BASE+"/block","203.0.113.9",candidate),e);
 assert.equal(changed.status,403);
 const consentMissing=await invoke(post(BASE+"/block",j.ip,{...candidate,confirmedSchoolNetwork:false}),e);
 assert.equal(consentMissing.status,403);
 assert.equal(store.data.size,0);
 const good=await invoke(post(BASE+"/block",j.ip,candidate),e);
 assert.equal(good.status,200);
 const payload=await good.json();assert.equal(payload.expiresInSeconds,10800);
 assert.equal(store.data.get("ttl"),10800);
 const raw=store.data.get("school-egress:current-v1");
 assert.ok(raw);assert.equal(raw.includes(j.ip),false,"KV must never retain raw source IP");
 const denied=await checkSchoolEgressRestriction(request("https://vynalthai.com/home",j.ip),e,
  new URL("https://vynalthai.com/home"));
 assert.equal(denied.status,403);
 assert.equal((await denied.json()).error,"SCHOOL_NETWORK_RESTRICTED");
 const other=await checkSchoolEgressRestriction(request("https://vynalthai.com/home","203.0.113.2"),e,
  new URL("https://vynalthai.com/home"));assert.equal(other,null);
 const secondRoot=await checkSchoolEgressRestriction(request("https://vyncuslim.com/safe",j.ip),e,
  new URL("https://vyncuslim.com/safe"));assert.equal(secondRoot.status,403);
 const management=await checkSchoolEgressRestriction(request("https://vynalthai.com/en/network-egress",j.ip),e,
  new URL("https://vynalthai.com/en/network-egress"));assert.equal(management,null);
 const auth=await checkSchoolEgressRestriction(request("https://vynalthai.com/en/auth/login",j.ip),e,
  new URL("https://vynalthai.com/en/auth/login"));assert.equal(auth,null);
});
test("restriction expiry is checked even if a KV key remains cached",async()=>{
 const store=memoryKV(),e=env(store),ip="198.51.100.7";
 store.data.set("school-egress:current-v1",JSON.stringify({
  ipDigest:hmac("egress-v1|address|"+ip),expiresAt:now()-1}));
 assert.equal(await checkSchoolEgressRestriction(request("https://vynalthai.com/",ip),e,
  new URL("https://vynalthai.com/")),null);
});
test("revocation remains possible with flag OFF but requires owner HMAC",async()=>{
 const store=memoryKV(),e=env(store,"false");
 store.data.set("school-egress:current-v1",JSON.stringify({ipDigest:"x",expiresAt:now()+1000}));
 const at=now();
 const rejected=await invoke(post(BASE+"/clear","203.0.113.7",{
  at,authorization:"B".repeat(43)}),e);
 assert.equal(rejected.status,403);
 const ok=await invoke(post(BASE+"/clear","203.0.113.7",{
  at,authorization:hmac("egress-v1|revoke|"+at)}),e);
 assert.equal(ok.status,200);
 assert.equal(store.data.has("school-egress:current-v1"),false);
});
