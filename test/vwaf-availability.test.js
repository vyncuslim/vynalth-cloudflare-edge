import test from "node:test";
import assert from "node:assert/strict";
import {checkAvailability,CHECKS} from "../scripts/vwaf-availability.mjs";
test("availability probes use fixed destinations, no redirects, verify content not just HTTP 200",async()=>{
 const r=await checkAvailability(async (url,init)=>{
  assert.ok(CHECKS.some(c=>c.url===url));assert.equal(init.redirect,"manual");assert.equal(init.method,"GET");
  return url.endsWith("/health")?Response.json({status:"ok",privateFixture:"DO_NOT_LOG"}):new Response("<html>Vynalth Search</html>",{headers:{"content-type":"text/html"}});
 });
 assert.equal(r.healthy,true);assert.ok(!JSON.stringify(r).includes("DO_NOT_LOG"));
 const bad=await checkAvailability(async url=>url.endsWith("/health")?Response.json({status:"degraded"}):new Response("<html>error</html>",{headers:{"content-type":"text/html"}}));
 assert.equal(bad.healthy,false);assert.ok(bad.results.every(x=>x.reason==="unexpected_body"));
});
test("availability errors are explicitly recorded and no follow-on destination is fetched",async()=>{
 const r=await checkAvailability(async()=>new Response(null,{status:302,headers:{Location:"https://example.com/"}}));
 assert.equal(r.healthy,false);assert.ok(r.results.every(x=>x.httpStatus===302));
});
