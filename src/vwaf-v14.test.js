import test from "node:test";
import assert from "node:assert/strict";
import {applyVynalthWaf,inspectWafRequest,CORE_HOSTS} from "./vynalth-waf-core.js";
import {canonicalNetworkAddress,isLocalDestination} from "./vwaf-network.js";
import {verifyEdgeDevice,buildEdgeDeviceCookie} from "./domain-device-id.js";
import {enforceVynalthWaf,verifiedActors} from "./vwaf-runtime.js";
import {inspectStructuredContent} from "./vwaf-content.js";
const id="00000000-0000-4000-8000-000000000001";
const env={VYNALTH_WAF_MODE:"enforce",VYNALTH_WAF_HOSTS:CORE_HOSTS.join(","),VYNALTH_WAF_STATE_MODE:"enforce"};
const req=(host,path,options={})=>new Request("https://"+host+path,options);
test("path inspection budget is an explicit protocol limit, not attack attribution",async()=>{
 const r=req("vynalthai.com","/"+"a".repeat(8192));
 const v=inspectWafRequest(r);assert.equal(v.block,true);assert.equal(v.score,0);
 assert.equal(applyVynalthWaf(r,env,id,()=>{}).status,414);
 assert.equal(applyVynalthWaf(r,{...env,VYNALTH_WAF_MODE:"observe"},id,()=>{}),null);
 assert.equal(applyVynalthWaf(req("shield.vynalthai.com","/"+"a".repeat(8192)),env,id,()=>{}),null);
});
test("method override metadata is advisory and no header value is emitted",()=>{
 const r=req("vynalthai.com","/api/example",{headers:{"X-HTTP-Method-Override":"DELETE"}});
 const v=inspectWafRequest(r);assert.ok(v.signals.some(x=>x.id==="VWAF-211"));assert.equal(v.block,false);
});
test("canonical network addresses are strict and equivalent IPv6 forms share counters",async()=>{
 assert.equal(canonicalNetworkAddress("2001:0db8:0:0:0:0:0:1"),"2001:db8::1");
 for(const bad of ["","192.168.001.1","123","256.1.1.1","fe80::1%zone","not-an-ip"])assert.equal(canonicalNetworkAddress(bad),null);
 const e={EDGE_DEVICE_ID_SIGNING_SECRET:"fixture-only-secret-material-0123456789"};
 const actor=async ip=>{const r=req("vynalthai.com","/",{headers:{"CF-Connecting-IP":ip}});Object.defineProperty(r,"cf",{value:{country:"MY"}});return verifiedActors(r,e)};
 assert.deepEqual(await actor("2001:0db8:0:0:0:0:0:1"),await actor("2001:db8::1"));
 assert.deepEqual(await actor("2a06:98c0:3600:0:0:0:0:103"),[]);
});
test("local URL destinations are observation signals; no DNS or URL fetch",()=>{
 for(const v of ["http://localhost/","http://127.0.0.1/","http://[::1]/","http://[fc00::1]/","http://[::ffff:7f00:1]/"]){
  assert.equal(isLocalDestination(v),true);
  assert.ok(inspectStructuredContent({url:v}).some(x=>x.id==="VWAF-306"));
 }
 assert.equal(isLocalDestination("https://example.com/"),false);
 const r=req("vynalthai.com","/api/example?url="+encodeURIComponent("http://[fc00::1]/"));
 assert.ok(inspectWafRequest(r).signals.some(x=>x.id==="VWAF-209"));
 assert.equal(inspectWafRequest(r).block,false);
});
test("signed-device restriction survives routine admission saturation through read-only reserved lane",async()=>{
 const e={...env,EDGE_DEVICE_ID_ENABLED:"true",EDGE_DEVICE_ID_SIGNING_SECRET:"fixture-only-secret-material-0123456789"};
 const issued=await verifyEdgeDevice(req("search.vynalthai.com","/"),e);
 const r=req("search.vynalthai.com","/api/search",{headers:{Cookie:buildEdgeDeviceCookie(issued.token).split(";")[0]}});
 const keys=[],ops=[];
 e.VWAF_STATE_BUDGET={limit:async({key})=>{keys.push(key);return {success:key==="device-status:search.vynalthai.com"}}};
 e.SECURITY_DEVICE_RISK={idFromName:n=>n,get:()=>({fetch:async(url,init)=>{const x=JSON.parse(init.body);ops.push(x.op);return Response.json({blockedUntil:Date.now()+60000})}})};
 const result=await enforceVynalthWaf(r,e,{},id);
 assert.equal(result.status,403);assert.deepEqual(ops,["actor-status"]);assert.deepEqual(keys,["search.vynalthai.com","device-status:search.vynalthai.com"]);
 const fake=req("search.vynalthai.com","/api/search",{headers:{Cookie:"__Host-vyn_edge_device=invalid"}});
 assert.equal(await enforceVynalthWaf(fake,e,{},id),null);assert.equal(ops.length,1);
});
