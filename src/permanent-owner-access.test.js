import test from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, webcrypto } from "node:crypto";
import edge from "./index.js";
import { hasPermanentOwnerAccess } from "./permanent-owner-access.js";

if (!globalThis.crypto) globalThis.crypto=webcrypto;
const signingKey="unit-test-sso-signing-secret-123456789012345678901";
const ownerId="owner_test_stable_uuid_2026";
const outsiderId="another_user_stable_uuid_2026";
const fingerprint=createHash("sha256")
  .update("vynalth-owner-subject-v1:"+ownerId).digest("hex");

function cookie(sub=ownerId,host="vynalthai.com",seconds=600,status="normal") {
 const claim={sub,host,status,sid:"session_test_12345678",
  exp:Math.floor(Date.now()/1000)+seconds};
 const payload=Buffer.from(JSON.stringify(claim)).toString("base64url");
 const signature=createHmac("sha256",signingKey).update(payload).digest("base64url");
 return "__Secure-vynalth-sso="+payload+"."+signature;
}
function req(path="/c",ownerCookie="",hostname="vynalthai.com",headers={},method="GET") {
 return new Request("https://"+hostname+path,{method,body:method==="POST"?"{}":undefined,headers:{
   "CF-Connecting-IP":"203.0.113.45","User-Agent":"VynalthTest",
   Accept:"text/html", ...(ownerCookie?{Cookie:ownerCookie}:{}), ...headers
 }});
}
function env(extra={}) {
 const counts={school:0};
 const options={
  VYNALTH_PERMANENT_OWNER_ENABLED:"true",
  VYNALTH_OWNER_SSO_SUBJECT_SHA256:fingerprint,
  CONSENT_SSO_SIGNING_SECRET:signingKey,
  GPS_GATE_ENABLED:"true",
  GPS_GATE_SESSION_SECRET:"unit-test-gps-secret-123456789012345678901",
  GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",
  GPS_CAMPUS_RADIUS_METERS:"180",
  SCHOOL_POLICY:{async fetch(){
    counts.school++;
    return new Response("school restricted",{status:403,
      headers:{"X-School-Policy":"blocked"}});
  }},
  ...extra
 };
 return {options,counts};
}
async function withOrigin(run) {
 const existing=globalThis.fetch;
 let hits=0;
 globalThis.fetch=async()=>{hits++;return new Response("chat origin",{status:200})};
 try{return await run(()=>hits)}finally{globalThis.fetch=existing}
}

test("permanent owner entitlement grants only the configured, signed user on /c",async()=>{
 const {options,counts}=env();
 await withOrigin(async originHits=>{
  const denied=await edge.fetch(req(),options,{});
  assert.equal(denied.status,403);
  assert.equal(originHits(),0);
  const owner=await edge.fetch(req("/c",cookie()),options,{});
  assert.equal(owner.status,200);
  assert.equal(await owner.text(),"chat origin");
  assert.equal(originHits(),1);
  assert.equal(counts.school,0,"ordinary visitor denied by GPS before School IP policy");
 });
});
test("the owner's signed SSO also bypasses the independent school-IP gate",async()=>{
 const {options,counts}=env({GPS_GATE_ENABLED:"false"});
 await withOrigin(async originHits=>{
  const ordinary=await edge.fetch(req("/c"),options,{});
  assert.equal(ordinary.status,403);
  assert.equal(ordinary.headers.get("X-School-Policy"),"blocked");
  const owner=await edge.fetch(req("/c",cookie()),options,{});
  assert.equal(owner.status,200);
  assert.equal(counts.school,1,"owner must not trigger independent school deny");
  assert.equal(originHits(),1);
 });
});
test("unrelated student, even with signed trusted role, stays restricted",async()=>{
 const {options}=env({GPS_GATE_ENABLED:"false"});
 for(const person of [cookie(outsiderId),cookie(outsiderId,"vynalthai.com",600,"trust")]) {
  const response=await edge.fetch(req("/c",person),options,{});
  assert.equal(response.status,403);
  assert.equal(response.headers.get("X-School-Policy"),"blocked");
 }
});
test("host, expired signature and missing owner opt-in all fail closed",async()=>{
 const {options}=env();
 const check=async (request,e=options)=>hasPermanentOwnerAccess(request,e,new URL(request.url));
 assert.equal(await check(req("/c",cookie())) ,true);
 assert.equal(await check(req("/c",cookie(ownerId,"vynalthai.com",-5))),false);
 assert.equal(await check(req("/c",cookie(ownerId,"vyncuslim.com"))),false);
 assert.equal(await check(req("/c",cookie(), "www.vynalthai.com")),false);
 assert.equal(await check(req("/c",cookie().slice(0,-2)+"xx")),false);
 assert.equal(await check(req("/c",cookie(), "vynalthai.com",{
   "X-Vynalth-Owner":"true","X-User-Email":"owner@example.com"
 }),true,"spoofable headers do not affect verified identity");
 assert.equal(await check(req("/c",cookie()),{...options,
   VYNALTH_PERMANENT_OWNER_ENABLED:"false"}),false);
 assert.equal(await check(req("/c",cookie()),{...options,
   VYNALTH_OWNER_SSO_SUBJECT_SHA256:"00".repeat(32)}),false);
 assert.equal(await check(req("/c",cookie()),{...options,
   VYNALTH_OWNER_SSO_SUBJECT_SHA256:"invalid"}),false);
 assert.equal(await check(req("/c",cookie()),{...options,
   CONSENT_SSO_SIGNING_SECRET:undefined}),false);
});
test("indefinite entitlement uses short SSO sessions, never a permanent bypass cookie",async()=>{
 const {options}=env();
 assert.equal(await hasPermanentOwnerAccess(req("/c",cookie(ownerId,"vynalthai.com",600)),
   options,new URL("https://vynalthai.com/c")),true);
 assert.equal(await hasPermanentOwnerAccess(req("/c",cookie(ownerId,"vynalthai.com",-1)),
   options,new URL("https://vynalthai.com/c")),false);
 // Fresh authentication with the SAME stable account reactivates access without
 // any change to the permanent owner allowlist or manual temporary access portal.
 assert.equal(await hasPermanentOwnerAccess(req("/c",cookie(ownerId)),
   options,new URL("https://vynalthai.com/c")),true);
});
test("Chat API POST keeps independent authorization, school filtering for everyone else",async()=>{
 const {options}=env({GPS_GATE_ENABLED:"false"});
 await withOrigin(async hits=>{
  const other=await edge.fetch(req("/api/ai/chat",cookie(outsiderId),"vynalthai.com",{
    "Content-Type":"application/json",Accept:"application/json"
  },"POST"),options,{});
  assert.equal(other.status,403);
  const owner=await edge.fetch(req("/api/ai/chat",cookie(),"vynalthai.com",{
    "Content-Type":"application/json",Accept:"application/json"
  },"POST"),options,{});
  assert.equal(owner.status,200);
  assert.equal(hits(),1);
 });
});
