import test from "node:test";
import assert from "node:assert/strict";
import edge from "../src/index.js";

function fixture() {
  const records = new Map();
  const writes = [];
  const pending = [];
  let originCalls = 0;
  const kv = {
    async get(key) { return records.has(key) ? records.get(key) : null; },
    async put(key, value, options) { records.set(key, value); writes.push({key,value,options}); },
    async delete(key) { records.delete(key); },
    async list() { return {keys:[],list_complete:true,cursor:null}; }
  };
  const env = {
    SCHOOL_POLICY_INLINE_ENABLED: "true",
    SCHOOL_MANAGEMENT_INLINE_ENABLED: "true",
    MODE: "observe",
    SCHOOL_IP_KV: kv
  };
  const ctx = { waitUntil(promise) { pending.push(Promise.resolve(promise)); } };
  const send = async (host="vyncuslim.com", path="/", ip="60.49.64.83", extras={}) => {
    const req = new Request("https://" + host + path, {
      headers: {"CF-Connecting-IP":ip,...extras}
    });
    return edge.fetch(req,env,ctx);
  };
  const stub = async (fn) => {
    const saved = globalThis.fetch;
    globalThis.fetch = async () => { originCalls++; return new Response("origin", {status:200}); };
    try { return await fn(); }
    finally { globalThis.fetch = saved; await Promise.all(pending); }
  };
  return {records,writes,env,ctx,send,stub,originCalls:()=>originCalls};
}

test("inline School Worker preserves candidate observation TTL and never auto-blocks", async()=>{
  const x = fixture();
  await x.stub(async()=>{
    const r=await x.send();
    assert.equal(r.status,200);
  });
  assert.equal(x.records.has("observed:60.49.64.83"),true);
  assert.equal(x.writes.find(x=>x.key==="observed:60.49.64.83")?.options?.expirationTtl,86400);
  assert.equal(x.records.has("blocked:60.49.64.83"),false);
});

test("inline School Worker blocks manually listed IP only with active enforcement",async()=>{
  const x=fixture();
  x.records.set("blocked:60.49.64.83","manual");
  await x.stub(async()=>{
    const observed=await x.send();
    assert.equal(observed.status,200);
    x.records.set("policy:runtime-enforcement-v1",JSON.stringify({
      enabled:true,expiresAtMs:Date.now()+1800000,
      expiresAt:new Date(Date.now()+1800000).toISOString()
    }));
    const blocked=await x.send();
    assert.equal(blocked.status,403);
    assert.equal(blocked.headers.get("X-School-Policy"),"blocked");
    x.records.set("policy:runtime-enforcement-v1",JSON.stringify({enabled:false}));
    const restored=await x.send();
    assert.equal(restored.status,200);
    assert.equal(x.originCalls(),2);
  });
});

test("management endpoints belong only to the canonical host, not to subdomains",async()=>{
  const x=fixture();
  await x.stub(async()=>{
    const source=await x.send("vynalthai.com","/admin/ip");
    assert.equal(source.status,200);
    assert.match(await source.text(),/IP Access Control/);
    const other=await x.send("search.vynalthai.com","/admin/ip");
    assert.equal(other.status,200);
    assert.equal(await other.text(),"origin");
  });
});

test("school health is independent from site /health; reports current feature status",async()=>{
  const x=fixture();
  const r=await x.send("vynalthai.com","/__vynalth/school/health");
  assert.equal(r.status,200);
  const data=await r.json();
  assert.deepEqual(data,{
    ok:true,service:"vynalth-cloudflare-edge",schoolPolicy:"inline-v1",
    mode:"observe",inlineEnabled:true,kvBound:true
  });
  assert.equal(r.headers.get("Cache-Control"),"no-store");
});
