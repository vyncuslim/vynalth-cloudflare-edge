import test from "node:test";
import assert from "node:assert/strict";
import {applyVynalthWaf,inspectWafRequest,CORE_HOSTS} from "./vynalth-waf-core.js";
import {verifyEdgeDevice,verifyExistingEdgeDevice,buildEdgeDeviceCookie} from "./domain-device-id.js";
import {enforceVynalthWaf,verifiedActors} from "./vwaf-runtime.js";
import {sanitizeEvent,reserveRestrictionDelivery,nextActorWake,actorTransition} from "./vwaf-policy.js";
import {isWafContentCandidate} from "./vwaf-content.js";
const id="00000000-0000-4000-8000-000000000001";
const env={VYNALTH_WAF_MODE:"enforce",VYNALTH_WAF_HOSTS:CORE_HOSTS.join(","),VYNALTH_WAF_STATE_MODE:"enforce"};
const req=(host,path,init={})=>new Request("https://"+host+path,init);
test("core expands to ten reviewed non-PHP hosts without enrolling actor state",async()=>{
 assert.equal(CORE_HOSTS.length,10);
 for(const host of CORE_HOSTS){
  const r=req(host,"/.netrc");assert.equal(applyVynalthWaf(r,env,id,()=>{}).status,403);
  assert.equal(applyVynalthWaf(req(host,"/robots.txt"),env,id,()=>{}),null);
 }
 for(const host of ["shield.vynalthai.com","cf-test.vynalthai.com","other.vynalthai.com","vyncuslim.com"])
  assert.equal(applyVynalthWaf(req(host,"/.netrc"),env,id,()=>{}),null);
 const r=await enforceVynalthWaf(req("trust.vynalthai.com","/.netrc"),{...env,SECURITY_DEVICE_RISK:{idFromName:()=>{throw Error("must not allocate actor")}}},{},id);
 assert.equal(r.status,403);
 assert.ok(sanitizeEvent({host:"trust.vynalthai.com",mode:"enforce",action:"block",request_id:id,rule_ids:["VWAF-102"],score:100}));
});
test("new deterministic credentials and diagnostic categories preserve normal public files",()=>{
 for(const path of ["/.vault-token","/.config/rclone/rclone.conf","/debug/pprof/heap","/a%2f..%2fetc%2fpasswd"]){
  assert.equal(inspectWafRequest(req("vynalthai.com",path)).block,true);
 }
 for(const path of ["/status","/api/health","/docs/debug/pprof/heap","/firebase.json","/env.js","/openapi.json","/.well-known/security.txt"])
  assert.equal(inspectWafRequest(req("vynalthai.com",path)).block,false);
});
test("duplicate metadata and local destination remain advisory",()=>{
 const v=inspectWafRequest(req("vynalthai.com","/api/example?id=1&id=2&url=http%3A%2F%2Flocalhost"));
 assert.ok(v.signals.some(s=>s.id==="VWAF-209"));assert.ok(v.signals.some(s=>s.id==="VWAF-210"));assert.equal(v.block,false);
});
test("real Search signed credential verifies without minting, apex scope stays disabled",async()=>{
 const e={EDGE_DEVICE_ID_ENABLED:"true",EDGE_DEVICE_ID_SIGNING_SECRET:"fixture-only-secret-material-0123456789"};
 const search=req("search.vynalthai.com","/");
 const issued=await verifyEdgeDevice(search,e);assert.equal(issued.state,"issued");
 const cookie=buildEdgeDeviceCookie(issued.token).split(";")[0];
 const valid=req("search.vynalthai.com","/",{headers:{Cookie:cookie}});
 assert.equal((await verifyExistingEdgeDevice(valid,e)).state,"valid");
 const actors=await verifiedActors(valid,e);assert.equal(actors.length,1);assert.equal(actors[0].kind,"device");
 const fake=req("search.vynalthai.com","/",{headers:{Cookie:"__Host-vyn_edge_device=invalid"}});
 const invalid=await verifyExistingEdgeDevice(fake,e);assert.equal(invalid.state,"invalid");assert.equal(invalid.token,null);
 assert.deepEqual(await verifiedActors(fake,e),[]);
 assert.equal((await verifyExistingEdgeDevice(req("vynalthai.com","/",{headers:{Cookie:cookie}}),e)).state,"disabled");
});
test("device actor outage cannot suppress network rate denial",async()=>{
 const e={...env,EDGE_DEVICE_ID_ENABLED:"true",EDGE_DEVICE_ID_SIGNING_SECRET:"fixture-only-secret-material-0123456789",VWAF_STATE_BUDGET:{limit:async()=>({success:true})}};
 const issued=await verifyEdgeDevice(req("search.vynalthai.com","/"),e);
 const r=req("search.vynalthai.com","/api/search",{headers:{Cookie:buildEdgeDeviceCookie(issued.token).split(";")[0],"CF-Connecting-IP":"198.51.100.10"}});
 Object.defineProperty(r,"cf",{value:{country:"MY"}});
 let calls=0;e.SECURITY_DEVICE_RISK={idFromName:n=>n,get:()=>({fetch:async(url,init)=>{
  calls++;const x=JSON.parse(init.body);if(x.kind==="device")throw Error("fixture timeout");
  return Response.json({rateExceeded:true,retryAfterSeconds:7});
 }})};
 const res=await enforceVynalthWaf(r,e,{},id);assert.equal(calls,2);assert.equal(res.status,429);assert.equal(res.headers.get("Retry-After"),"7");
});
test("rate denial precedes body clone; content admission is independently bounded",async()=>{
 const body=JSON.stringify({id:"fixture"});
 const r=req("vynalthai.com","/api/web-search",{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(body.length),"CF-Connecting-IP":"198.51.100.10"},body});
 Object.defineProperty(r,"cf",{value:{country:"MY"}});
 let cloned=0;Object.defineProperty(r,"clone",{value:()=>{cloned++;throw Error("body should not be read")}});
 assert.equal(isWafContentCandidate(r),true);
 const e={...env,EDGE_DEVICE_ID_SIGNING_SECRET:"fixture-only-secret-material-0123456789",VYNALTH_WAF_CONTENT_ENABLED:"true",
 VWAF_STATE_BUDGET:{limit:async()=>({success:true})},VWAF_EVENT_BUDGET:{limit:async()=>({success:false})},
 SECURITY_DEVICE_RISK:{idFromName:n=>n,get:()=>({fetch:async()=>Response.json({rateExceeded:true,retryAfterSeconds:3})})}};
 assert.equal((await enforceVynalthWaf(r,e,{},id)).status,429);assert.equal(cloned,0);assert.equal(await r.text(),body);
});
