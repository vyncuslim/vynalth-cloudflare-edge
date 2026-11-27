import test from "node:test";
import assert from "node:assert/strict";
import edge from "../src/index.js";
const env=mode=>({VYNALTH_WAF_MODE:mode,VYNALTH_WAF_HOSTS:"vynalthai.com,search.vynalthai.com"});
test("WAF hard deny is before origin fetch",async()=>{
  let calls=0;const original=globalThis.fetch;
  globalThis.fetch=async()=>{calls++;return new Response("origin");};
  try{
    const res=await edge.fetch(new Request("https://vynalthai.com/.netrc"),env("enforce"),{});
    assert.equal(res.status,403);assert.equal(res.headers.get("x-vynalth-security-action"),"block-vynalth-waf");
    assert.equal(calls,0);
  }finally{globalThis.fetch=original;}
});
test("observe mode and public traffic preserve origin flow",async()=>{
  let calls=0;const original=globalThis.fetch;
  globalThis.fetch=async()=>{calls++;return new Response("origin",{status:200});};
  try{
    const observation=await edge.fetch(new Request("https://vynalthai.com/.netrc"),env("observe"),{});
    const publicResponse=await edge.fetch(new Request("https://vynalthai.com/robots.txt"),env("enforce"),{});
    assert.equal(observation.status,200);assert.equal(publicResponse.status,200);
    assert.equal(calls,2);
  }finally{globalThis.fetch=original;}
});

test("retired VWAF namespace never reaches origin even with old console credentials",async()=>{
 const original=globalThis.fetch;let calls=0;globalThis.fetch=async()=>{calls++;return new Response("origin")};
 try{
  const r=await edge.fetch(new Request("https://vynalthai.com/__ops/vwaf/api/status",{headers:{Authorization:"Bearer "+"A".repeat(43)}}),
   {...env("enforce"),VYNALTH_WAF_HONEYPOT_ENABLED:"true",VYNALTH_WAF_CONSOLE_ENABLED:"true",VWAF_CONSOLE_TOKEN:"A".repeat(43)},{});
  assert.equal(r.status,404);assert.equal(calls,0);assert.equal(await r.text(),"Resource unavailable.");
 }finally{globalThis.fetch=original}
});

test("real edge schema denial precedes origin; valid free text and observe mode flow onward",async()=>{
 const original=globalThis.fetch;let calls=0;
 globalThis.fetch=async request=>{calls++;return new Response("origin",{status:200})};
 const make=(aspectRatio)=>{const body=JSON.stringify({prompt:"<script> example SQL tutorial",aspectRatio});return new Request("https://vynalthai.com/api/ai/image",{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).byteLength)},body})};
 const e={...env("enforce"),VYNALTH_WAF_CONTENT_ENABLED:"true",VYNALTH_WAF_SCHEMA_MODE:"enforce",VWAF_EVENT_BUDGET:{limit:async()=>({success:true})}};
 try{
  const denied=await edge.fetch(make("invalid"),e,{});
  assert.equal(denied.status,400);assert.equal(denied.headers.get("x-vynalth-security-action"),"vwaf-schema-rejected");assert.equal(calls,0);
  assert.equal((await denied.json()).error,"INVALID_ASPECT_RATIO");
  assert.equal((await edge.fetch(make("16:9"),e,{})).status,200);assert.equal(calls,1);
  assert.equal((await edge.fetch(make("invalid"),{...e,VYNALTH_WAF_SCHEMA_MODE:"observe"},{})).status,200);assert.equal(calls,2);
 }finally{globalThis.fetch=original}
});
