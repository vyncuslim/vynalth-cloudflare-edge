import test from "node:test";
import assert from "node:assert/strict";
import {inspectStructuredContent,inspectWafContent,isWafContentCandidate} from "./vwaf-content.js";
import {createPortableWaf} from "./vwaf-portable.js";
const base="https://vynalthai.com";
const bytes=s=>new TextEncoder().encode(s);
const make=(path,body,headers={})=>new Request(base+path,{method:"POST",headers:{"Content-Type":"application/json",...headers},body,duplex:"half"});
function stream(chunks){return new ReadableStream({start(c){for(const chunk of chunks)c.enqueue(chunk);c.close()}})}
test("global structured-field budget cannot restart after nested object traversal",()=>{
 const x={options:Object.fromEntries(Array.from({length:40},(_,i)=>["unknown"+i,"ordinary"])),id:"<script>fixture</script>"};
 const ids=inspectStructuredContent(x).map(s=>s.id);
 assert.deepEqual(ids,["VWAF-304"]);
});
test("reviewed unframed JSON is opt-in; complete content is inspected without consuming the original",async()=>{
 const body=JSON.stringify({prompt:"ordinary",aspectRatio:"invalid"});
 const r=make("/api/ai/image",stream([bytes(body.slice(0,12)),bytes(body.slice(12))]));
 assert.equal(r.headers.get("content-length"),null);
 assert.equal(isWafContentCandidate(r),false);
 assert.deepEqual(await inspectWafContent(r),[]);
 assert.equal(isWafContentCandidate(r,{allowUnframed:true}),true);
 assert.ok((await inspectWafContent(r,{allowUnframed:true})).some(x=>x.id==="VWAF-605"&&x.blocking));
 assert.equal(await r.text(),body);
});
test("unframed inspection does not admit credentials, other routes, encoding or oversized and malformed bodies",async()=>{
 const option={allowUnframed:true};
 for(const path of ["/api/auth/signup","/api/auth/login","/api/unknown"]){
  const r=make(path,stream([bytes('{"prompt":"fixture"}')]));
  Object.defineProperty(r,"clone",{value:()=>{throw Error("must not clone")}});
  assert.equal(isWafContentCandidate(r,option),false);
  assert.deepEqual(await inspectWafContent(r,option),[]);
 }
 for(const [chunks,headers] of [[[bytes("x".repeat(8193))],{}],[[bytes("{")],{}],[[bytes("{}")],{"Content-Encoding":"gzip"}],[[bytes("{}")],{"Content-Length":"99999"}],[[bytes("{}")],{"Content-Length":"1"}]]){
  const r=make("/api/ai/image",stream(chunks),headers);
  assert.deepEqual(await inspectWafContent(r,option),[]);
 }
});
test("ordinary fragmented framed body remains valid and empty-chunk budget stops inspection",async()=>{
 const body=JSON.stringify({prompt:"ordinary",aspectRatio:"1:1"});
 const r=make("/api/ai/image",stream(Array.from(bytes(body),v=>Uint8Array.of(v))),{"Content-Length":String(bytes(body).length)});
 assert.deepEqual(await inspectWafContent(r),[]);
 assert.equal(await r.text(),body);
 const bad=JSON.stringify({prompt:"ordinary",aspectRatio:"invalid"});
 const empty=make("/api/ai/image",stream([...Array.from({length:33},()=>new Uint8Array(0)),bytes(bad)]));
 assert.deepEqual(await inspectWafContent(empty,{allowUnframed:true}),[]);
 assert.equal(await empty.text(),bad);
});
test("portable enforcement honors the explicit opt-in and retains application authorization",async()=>{
 const opts={hosts:["vynalthai.com"]};
 const req=()=>make("/api/ai/image",stream([bytes('{"prompt":"ordinary","aspectRatio":"invalid"}')]));
 const next=async()=>new Response(null,{status:401});
 assert.equal((await createPortableWaf(opts)(req(),next)).status,401);
 assert.equal((await createPortableWaf({...opts,allowUnframedContent:true})(req(),next)).status,400);
 const normal=make("/api/ai/image",stream([bytes('{"prompt":"ordinary","aspectRatio":"1:1"}')]));
 assert.equal((await createPortableWaf({...opts,allowUnframedContent:true})(normal,next)).status,401);
});
