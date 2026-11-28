import test from "node:test";
import assert from "node:assert/strict";
import {inspectApiSchema,schemaResponse} from "./vwaf-schema.js";
import {inspectWafContent} from "./vwaf-content.js";
import {sanitizeEvent,HARD_IDS} from "./vwaf-policy.js";
const path="/api/cloud-browser-live";
test("reviewed navigation validation rejects malformed or unsupported destination values",async()=>{
 const cases=[undefined,null,7,{},"","not a URL","ftp://example.com/","https://user:pass@example.com/","https://example.com/"+"a".repeat(2048)];
 for(const url of cases){
  const body=JSON.stringify({action:"navigate",url});
  const req=new Request("https://vynalthai.com"+path,{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).length)},body});
  const signals=await inspectWafContent(req);
  assert.deepEqual(signals.map(s=>s.id),["VWAF-607"]);
  const res=schemaResponse(req,signals,"enforce");
  assert.equal(res.status,400);
  assert.equal((await res.json()).error,"INVALID_BROWSER_URL");
  assert.equal(schemaResponse(req,signals,"observe"),null);
  assert.equal(await req.text(),body);
 }
});
test("reviewed navigation policy preserves public URLs and unrelated operations",()=>{
 for(const url of ["https://example.com/","http://example.com/path","https://example.com/"+"a".repeat(1000)])
  assert.deepEqual(inspectApiSchema(path,{action:"navigate",url}),[]);
 assert.deepEqual(inspectApiSchema(path,{action:"status",url:"not a URL"}),[]);
 assert.deepEqual(inspectApiSchema("/api/web-search",{query:"ftp://example.com/"}),[]);
});
test("new rule emits redacted decision telemetry and is not a device ban signal",()=>{
 assert.ok(!HARD_IDS.includes("VWAF-607"));
 const e=sanitizeEvent({host:"vynalthai.com",mode:"enforce",action:"block",request_id:"00000000-0000-4000-8000-000000000001",rule_ids:["VWAF-607"],score:0});
 assert.ok(e);
 assert.deepEqual(e.rule_ids,["VWAF-607"]);
});
