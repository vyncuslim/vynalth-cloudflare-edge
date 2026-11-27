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
