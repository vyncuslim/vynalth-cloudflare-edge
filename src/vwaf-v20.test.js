import test from "node:test";
import assert from "node:assert/strict";
import {inspectApiSchema,schemaResponse} from "./vwaf-schema.js";
import {inspectWafContent} from "./vwaf-content.js";
import {createPortableWaf} from "./vwaf-portable.js";
import {verifyIntelEnvelope,advisoryIntelMatch} from "./vwaf-intel.js";
const id="vynalthai.com",base="https://"+id;
function req(path,value){
 if(value===undefined)return new Request(base+path);
 const body=JSON.stringify(value);
 return new Request(base+path,{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).byteLength)},body});
}
test("schema matches actual backend image validation, not prompt keywords",()=>{
 for(const v of ["<script>example</script>","SELECT * FROM table","正常中文","🖼️"]){
  assert.deepEqual(inspectApiSchema("/api/ai/image",{prompt:v,aspectRatio:"16:9"}),[]);
  assert.deepEqual(inspectApiSchema("/api/web-search",{query:v}),[]);
 }
 for(const aspectRatio of ["bad","<script>fixture</script>","1 union select fixture"," "]){
  const s=inspectApiSchema("/api/ai/image",{prompt:"fixture",aspectRatio});assert.ok(s.some(v=>v.id==="VWAF-605"&&v.blocking));
  assert.equal(schemaResponse(req("/api/ai/image",{prompt:"fixture",aspectRatio}),s,"enforce").status,400);
 }
 for(const ratio of ["1:1","16:9","9:16"," 16:9 ",undefined,"",false,0]){
  assert.equal(inspectApiSchema("/api/ai/image",{prompt:"fixture",aspectRatio:ratio}).some(x=>x.blocking),false);
 }
 assert.ok(inspectApiSchema("/api/ai/image",{prompt:" ".repeat(8)}).some(x=>x.blocking));
 assert.ok(inspectApiSchema("/api/ai/image",{prompt:"a".repeat(2001)}).some(x=>x.blocking));
 assert.equal(inspectApiSchema("/api/web-search",{query:"a".repeat(601)}).some(x=>x.blocking),false);
});
test("schema inspection only uses bounded JSON and preserves the body",async()=>{
 const r=req("/api/ai/image",{prompt:"hello",aspectRatio:"invalid"});
 const s=await inspectWafContent(r);assert.ok(s.some(x=>x.id==="VWAF-605"&&x.blocking));
 assert.equal(await r.json().then(x=>x.prompt),"hello");
 const u=req("/api/auth/signup",{prompt:"",password:"fixture"});assert.deepEqual(await inspectWafContent(u),[]);
});
test("portable middleware is provider-independent, fail-closed for unknown host and preserves application authorization",async()=>{
 const events=[];let calls=0;
 const guard=createPortableWaf({hosts:[id],onEvent:e=>events.push(e)});
 const next=async r=>{calls++;return new Response("app",{status:401})};
 assert.equal((await guard(req("/.netrc"),next)).status,403);
 assert.equal((await guard(req("/api/ai/image",{prompt:"fixture",aspectRatio:"bad"}),next)).status,400);
 assert.equal((await guard(req("/api/web-search",{query:"<script> SQL example"}),next)).status,401);
 assert.equal((await guard(new Request("https://unrelated.example/"),next)).status,421);
 assert.equal(calls,1);assert.ok(events.every(x=>!JSON.stringify(x).includes("fixture")));
 const observe=createPortableWaf({hosts:[id],mode:"observe"});
 assert.equal((await observe(req("/.netrc"),next)).status,401);
});
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
test("signed intelligence rejects tampering, expiry, rollback and unapproved scope",async()=>{
 const now=Date.now(),keys=await crypto.subtle.generateKey("Ed25519",true,["sign","verify"]);
 const pub=b64(await crypto.subtle.exportKey("raw",keys.publicKey));
 const make=async x=>{const p=new TextEncoder().encode(JSON.stringify(x));return{payload:b64(p),signature:b64(await crypto.subtle.sign("Ed25519",keys.privateKey,p))}};
 const payload={schema:"vwaf-intel-v1",sequence:7,issuedAt:now-1000,expiresAt:now+60000,indicators:[{host:id,address:"192.0.2.10",category:"observed_scanning"}]};
 const envelope=await make(payload),v=await verifyIntelEnvelope(envelope,pub,6,now);
 assert.equal(v.sequence,7);
 assert.equal(advisoryIntelMatch(v,id,"192.0.2.10",now).blocking,false);
 assert.equal(advisoryIntelMatch(v,id,"192.0.2.10",now+60001),null);
 await assert.rejects(verifyIntelEnvelope(envelope,pub,7,now));
 await assert.rejects(verifyIntelEnvelope({...envelope,payload:b64(new TextEncoder().encode("{}"))},pub,6,now));
 await assert.rejects(verifyIntelEnvelope(await make({...payload,expiresAt:now-1}),pub,6,now));
 await assert.rejects(verifyIntelEnvelope(await make({...payload,indicators:[{host:"*.example",address:"192.0.2.10",category:"observed_scanning"}]}),pub,6,now));
});
