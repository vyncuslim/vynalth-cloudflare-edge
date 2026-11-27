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
