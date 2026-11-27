import test from "node:test";
import assert from "node:assert/strict";
import {inspectWafRequest,applyVynalthWaf,CORE_HOSTS} from "./vynalth-waf-core.js";
import {inspectApiSchema,schemaResponse} from "./vwaf-schema.js";
import {inspectWafContent} from "./vwaf-content.js";
import {createPortableWaf} from "./vwaf-portable.js";
import {HARD_IDS,sanitizeEvent} from "./vwaf-policy.js";
const id="00000000-0000-4000-8000-000000000001",host="vynalthai.com";
const env={VYNALTH_WAF_MODE:"enforce",VYNALTH_WAF_HOSTS:CORE_HOSTS.join(","),VYNALTH_WAF_STRUCTURED_MODE:"enforce"};
const req=(path,h=host,init={})=>new Request("https://"+h+path,init);
test("explicit identifier contract enforces the same policy on all reviewed hosts, independent of test route",()=>{
 for(const h of CORE_HOSTS)for(const val of ["1 union select fixture","<script>fixture</script>","{{fixture}}"]){
  const r=req("/api/records?id="+encodeURIComponent(val),h);
  assert.equal(inspectWafRequest(r).block,false);
  const result=applyVynalthWaf(r,env,id,()=>{});assert.equal(result.status,403);
  assert.equal(applyVynalthWaf(r,{...env,VYNALTH_WAF_STRUCTURED_MODE:"observe"},id,()=>{}),null);
  assert.equal(applyVynalthWaf(r,{...env,VYNALTH_WAF_MODE:"observe"},id,()=>{}),null);
 }
 assert.ok(!HARD_IDS.includes("VWAF-212"));
});
test("ordinary identifier syntax and free text, callbacks, local URL metadata and other methods are preserved",()=>{
 for(const path of ["/api/records?id=abc-123","/api/records?id=42","/api/records?id=union-station","/api/records?id="+encodeURIComponent("中文标识"),"/api/records?url=http%3A%2F%2Flocalhost","/docs/example?id=%7B%7Bfixture%7D%7D","/api/search?q="+encodeURIComponent("<script> SQL example"),"/api/webhooks/test?id=%7B%7Bfixture%7D%7D","/api/cloud-browser-live?id=%7B%7Bfixture%7D%7D"]){
  assert.equal(applyVynalthWaf(req(path),env,id,()=>{}),null,path);
 }
 assert.equal(applyVynalthWaf(req("/api/records?id=%7B%7Bfixture%7D%7D",host,{method:"POST"}),env,id,()=>{}),null);
 assert.equal(applyVynalthWaf(req("/api/records?id=%7B%7Bfixture%7D%7D","unrelated.example"),env,id,()=>{}),null);
});
test("source-verified browser navigate literal private URL contract; other fields and actions are not read for signals",async()=>{
 for(const url of ["http://localhost/","http://127.0.0.1/","http://[::1]/"]){
  const body=JSON.stringify({action:"navigate",url,other:"SYNTHETIC_PRIVATE_FIXTURE"});
  const r=req("/api/cloud-browser-live",host,{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).length)},body});
  const signals=await inspectWafContent(r);
  assert.deepEqual(signals.map(x=>x.id),["VWAF-606"]);
  assert.equal(schemaResponse(r,signals,"enforce").status,403);
  assert.equal(schemaResponse(r,signals,"observe"),null);
  assert.equal(await r.text(),body);
 }
 assert.deepEqual(inspectApiSchema("/api/cloud-browser-live",{action:"navigate",url:"https://example.com/"}),[]);
 assert.deepEqual(inspectApiSchema("/api/cloud-browser-live",{action:"status",url:"http://localhost/"}),[]);
 assert.equal(inspectApiSchema("/api/web-search",{query:"http://localhost/"}).some(x=>x.blocking),false);
 assert.ok(!HARD_IDS.includes("VWAF-606"));
});
test("new telemetry is redacted and portable profile supports the same identifier policy",async()=>{
 const events=[],guard=createPortableWaf({hosts:[host],structuredMode:"enforce",onEvent:e=>events.push(e)});
 const r=req("/api/records?id="+encodeURIComponent("<script>PRIVATE_FIXTURE</script>"));
 assert.equal((await guard(r,()=>new Response("origin"))).status,403);
 assert.equal(events.length,1);
 assert.ok(events[0].rule_ids.includes("VWAF-212"));
 assert.ok(!JSON.stringify(events).includes("PRIVATE_FIXTURE"));
 assert.ok(sanitizeEvent(events[0]));
});
