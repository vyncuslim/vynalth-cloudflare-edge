import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import edge from "../src/index.js";
import { temporaryIpBlockResponse,TEMPORARY_IP_BLOCK } from "../src/temporary-ip-block.js";

// Existing edge behavior is tested with a stub origin and stub Service Binding.
function request(hostname = "vyncuslim.com", path = "/") {
  return new Request("https://" + hostname + path, {
    headers: { "CF-Connecting-IP": "60.49.64.83" }
  });
}

async function withOrigin(run) {
  const original = globalThis.fetch;
  let count = 0;
  globalThis.fetch = async () => {
    count++;
    return new Response("origin-ok", {
      status: 200, headers: { "x-vercel-id": "test" }
    });
  };
  try { return await run(() => count); }
  finally { globalThis.fetch = original; }
}

test("policy allow 204 preserves original homepage and headers", async () => {
  await withOrigin(async getCalls => {
    let called = false;
    const env = {
      SCHOOL_POLICY: {
        async fetch(policyReq) {
          called = true;
          assert.equal(policyReq.headers.get("X-Vynalth-Policy-Client-IP"), "60.49.64.83");
          assert.equal(new URL(policyReq.url).hostname, "vyncuslim.com");
          return new Response(null, { status: 204 });
        }
      }
    };
    const response = await edge.fetch(request(), env, {});
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("x-vynalth-zone"), "vyncuslim.com");
    assert.equal(getCalls(), 1);
    assert.equal(called, true);
  });
});

test("policy 403 tagged as blocked prevents origin fetch", async () => {
  await withOrigin(async getCalls => {
    const env = {
      SCHOOL_POLICY: { async fetch() {
        return new Response("blocked", {
          status: 403, headers: { "X-School-Policy": "blocked" }
        });
      }}
    };
    const response = await edge.fetch(request(), env, {});
    assert.equal(response.status, 403);
    assert.equal(response.headers.get("x-school-policy"), "blocked");
    assert.equal(getCalls(), 0);
  });
});

test("untagged 403 cannot accidentally block a website", async () => {
  await withOrigin(async getCalls => {
    const env = { SCHOOL_POLICY: { async fetch() {
      return new Response("unrelated error", { status: 403 });
    }}};
    const response = await edge.fetch(request(), env, {});
    assert.equal(response.status, 200);
    assert.equal(getCalls(), 1);
  });
});

test("missing or failing service binding fails open", async () => {
  await withOrigin(async getCalls => {
    const first = await edge.fetch(request(), {}, {});
    const second = await edge.fetch(request(), {
      SCHOOL_POLICY: { async fetch() { throw new Error("temporary outage"); } }
    }, {});
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(getCalls(), 2);
  });
});

test("two new SI zones are recognized and routed through policy", async () => {
  await withOrigin(async getCalls => {
    const seen = [];
    const env = { SCHOOL_POLICY: { async fetch(req) {
      seen.push(new URL(req.url).hostname);
      return new Response(null, { status: 204 });
    }}};
    for (const host of ["vynalthai.si", "www.vyncuslim.si"]) {
      const response = await edge.fetch(request(host), env, {});
      assert.equal(response.status, 200);
    }
    assert.deepEqual(seen, ["vynalthai.si", "www.vyncuslim.si"]);
    assert.equal(getCalls(), 2);
  });
});

test("sensitive query strings are not forwarded to policy Worker", async () => {
  await withOrigin(async () => {
    let secretForwarded = false;
    const env = { SCHOOL_POLICY: { async fetch(req) {
      secretForwarded = req.url.includes("secret-token");
      return new Response(null, { status: 204 });
    }}};
    const response = await edge.fetch(request("vyncuslim.com", "/?token=secret-token"), env, {});
    assert.equal(response.status, 200);
    assert.equal(secretForwarded, false);
  });
});

test("ACME validation requests bypass policy to preserve certificates", async () => {
  await withOrigin(async getCalls => {
    const env = { SCHOOL_POLICY: { async fetch() {
      throw new Error("policy should not see ACME challenge");
    }}};
    const response = await edge.fetch(request("vynalthai.com", "/.well-known/acme-challenge/test"), env, {});
    assert.equal(response.status, 200);
    assert.equal(getCalls(), 1);
  });
});

test("unified Worker serves public GPS disclaimer with both feature flags OFF", async()=>{
 const res=await edge.fetch(new Request("https://vyncuslim.com/__shield/gps/disclaimer"),{
  GPS_GATE_ENABLED:"false",CONSENT_CMP_ENABLED:"false"
 },{});
 assert.equal(res.status,200);
 assert.match(await res.text(),/Disclaimer/);
 assert.equal(res.headers.get("x-vynalth-edge"),"cloudflare-worker");
});

test("unified Worker GPS guest challenge and trusted SSO bypass follow independent policies",async()=>{
 const secret="test-canonical-sso-signing-secret-not-for-production-0000";
 const now=Math.floor(Date.now()/1000);
 const cookie=(root,role)=>{
  const payload=Buffer.from(JSON.stringify({
   sub:"person_12345678",sid:"session_12345678",status:role,host:root,exp:now+600
  })).toString("base64url");
  const tag=createHmac("sha256",secret).update(payload).digest("base64url");
  return "__Secure-vynalth-sso="+payload+"."+tag;
 };
 await withOrigin(async count=>{
  let policyCalls=0;
  const env={
   GPS_GATE_ENABLED:"true",GPS_GATE_SESSION_SECRET:"test-gps-signing-secret-0000000000000000000000",
   GPS_ACCOUNT_STATUS_SECRET:"test-status-signing-secret-00000000000000000",
   GPS_CAMPUS_LAT:"5.36770",GPS_CAMPUS_LON:"100.21995",
   GPS_CAMPUS_RADIUS_METERS:"180",
   CONSENT_SSO_SIGNING_SECRET:secret,SCHOOL_TRUSTED_SSO_EXEMPTION_ENABLED:"true",
   SCHOOL_POLICY:{async fetch(){policyCalls++;return new Response("blocked",{
    status:403,headers:{"X-School-Policy":"blocked"}
   });}}
  };
  for(const host of ["vynalthai.com","vyncuslim.si"]){
   for(const role of ["trust","contact","status"]){
    const response=await edge.fetch(new Request("https://"+host+"/private",{
     headers:{"CF-Connecting-IP":"60.49.64.83",Cookie:cookie(host,role)}
    }),env,{});
    assert.equal(response.status,200,host+" "+role);
   }
  }
  assert.equal(policyCalls,0);
  assert.equal(count(),6);
  const guest=await edge.fetch(new Request("https://vynalthai.com/private",{
   headers:{Accept:"text/html"}
  }),env,{});
  assert.equal(guest.status,403);
  const normal=await edge.fetch(new Request("https://vynalthai.com/private",{
   headers:{Accept:"text/html",Cookie:cookie("vynalthai.com","normal")}
  }),env,{});
  assert.equal(normal.status,403);
 });
});

test("signed outside GPS does not bypass School IP Policy on private images",async()=>{
 await withOrigin(async originCalls=>{
  const gpsSecret="test-outside-gps-signing-secret-0123456789";
  const exp=Math.floor(Date.now()/1000)+600;
  const nonce=Buffer.alloc(16,7).toString("base64url");
  const sig=createHmac("sha256",gpsSecret)
    .update([exp,nonce,"vyncuslim.com","outside"].join("|")).digest("base64url");
  let photoReads=0,policyCalls=0;
  const env={
   JINGXIN_PRIVATE_MEDIA_ENABLED:"true",
   JINGXIN_PRIVATE_MEDIA_R2:{async get(){photoReads++;return {body:new Response("private").body}}},
   GPS_GATE_ENABLED:"true",GPS_GATE_SESSION_SECRET:gpsSecret,
   GPS_ACCOUNT_STATUS_SECRET:"test-separate-gps-role-signing-secret-012345",
   GPS_CAMPUS_LAT:"5.36770",GPS_CAMPUS_LON:"100.21995",
   GPS_CAMPUS_RADIUS_METERS:"180",
   SCHOOL_POLICY:{async fetch(){policyCalls++;return new Response("blocked",{
    status:403,headers:{"X-School-Policy":"blocked"}
   });}}
  };
  const response=await edge.fetch(new Request(
   "https://vyncuslim.com/media/jingxin/shared-memory.jpg",{
    headers:{"CF-Connecting-IP":"60.49.64.83",
     Cookie:"__Host-vynalth-geo="+exp+"."+nonce+"."+sig}
   }),env,{});
  assert.equal(response.status,403);
  assert.equal(response.headers.get("X-School-Policy"),"blocked");
  assert.equal(photoReads,0);
  assert.equal(policyCalls,1);
  assert.equal(originCalls(),0);
 });
});

test("server-signed trusted account bypasses only School IP photo feature",async()=>{
 await withOrigin(async originCalls=>{
  const key="test-canonical-sso-signing-secret-987654321012";
  const exp=Math.floor(Date.now()/1000)+600;
  const payload=Buffer.from(JSON.stringify({
   sub:"person_12345678",sid:"session_12345678",status:"contact",
   host:"vyncuslim.com",exp
  })).toString("base64url");
  const tag=createHmac("sha256",key).update(payload).digest("base64url");
  let policyCalls=0,photoReads=0;
  const env={
   CONSENT_SSO_SIGNING_SECRET:key,
   JINGXIN_PRIVATE_MEDIA_ENABLED:"true",
   JINGXIN_PRIVATE_MEDIA_R2:{async get(){photoReads++;return {body:new Response("private").body}}},
   SCHOOL_POLICY:{async fetch(){policyCalls++;return new Response("blocked",{
    status:403,headers:{"X-School-Policy":"blocked"}
   });}}
  };
  const response=await edge.fetch(new Request(
   "https://vyncuslim.com/media/jingxin/shared-memory.jpg",{
    headers:{"CF-Connecting-IP":"60.49.64.83",
     Cookie:"__Secure-vynalth-sso="+payload+"."+tag}
   }),env,{});
  assert.equal(response.status,200);
  assert.equal(await response.text(),"private");
  assert.equal(photoReads,1);
  assert.equal(policyCalls,0);
  assert.equal(originCalls(),0);
 });
});

test("time-limited owner IP restriction returns 403 without a cookie",async()=>{
 const req=new Request("https://vynalthai.com/",{
  headers:{"CF-Connecting-IP":"60.51.219.195"}
 });
 const checkedAt=(TEMPORARY_IP_BLOCK.expiresAtUnix-3600)*1000;
 const r=temporaryIpBlockResponse(req,new URL(req.url),checkedAt);
 assert.equal(r.status,403);
 assert.equal(r.headers.get("X-Vynalth-Temporary-IP-Block"),"12h");
 assert.equal(Number(r.headers.get("Retry-After")),3600);
 assert.equal(r.headers.get("Set-Cookie"),null);
 assert.equal(r.headers.get("Cache-Control"),"no-store");
 assert.equal(temporaryIpBlockResponse(req,new URL(req.url),
  TEMPORARY_IP_BLOCK.expiresAtUnix*1000),null,"Automatic expiry must work without redeploy");
 assert.equal(temporaryIpBlockResponse(req,new URL(req.url),
  (TEMPORARY_IP_BLOCK.expiresAtUnix+100)*1000),null);
});
test("temporary rule matches only Cloudflare's authoritative client IP",()=>{
 const url=new URL("https://vynalthai.com/c");
 const at=(TEMPORARY_IP_BLOCK.expiresAtUnix-60)*1000;
 const spoofed=new Request(url,{headers:{
  "CF-Connecting-IP":"203.0.113.25","X-Forwarded-For":"60.51.219.195"}});
 assert.equal(temporaryIpBlockResponse(spoofed,url,at),null);
 assert.equal(temporaryIpBlockResponse(new Request(url),url,at),null);
});
test("temporary rule preserves trust/contact/status, legal and login recovery paths",()=>{
 const at=(TEMPORARY_IP_BLOCK.expiresAtUnix-60)*1000;
 for(const addr of [
  "https://trust.vynalthai.com/",
  "https://status.vynalthai.com/",
  "https://contact.vynalthai.com/",
  "https://vynalthai.com/auth/login",
  "https://vynalthai.com/en/legal/privacy",
  "https://vynalthai.com/__shield/gps/status",
  "https://vynalthai.com/__shield/gps/disclaimer",
  "https://vynalthai.com/.well-known/acme-challenge/demo",
  "https://vynalthai.com/api/auth/session",
 ]){
  const req=new Request(addr,{headers:{"CF-Connecting-IP":"60.51.219.195"}});
  assert.equal(temporaryIpBlockResponse(req,new URL(req.url),at),null,addr);
 }
});
test("blocked public IPv4 stops origin fetch for main site and covered subdomains",async()=>{
 await withOrigin(async count=>{
  for(const hostname of ["vynalthai.com","search.vynalthai.com","vynova.vynalthai.com"]){
   const req=new Request("https://"+hostname+"/",{
    headers:{"CF-Connecting-IP":"60.51.219.195"}});
   const res=await edge.fetch(req,{},null);
   // This test is run before the block's configured real-world expiry.
   if(Date.now()<TEMPORARY_IP_BLOCK.expiresAtUnix*1000){
    assert.equal(res.status,403,hostname);
    assert.equal(res.headers.get("x-vynalth-edge"),"cloudflare-worker");
    assert.equal(res.headers.get("x-vynalth-temporary-ip-block"),"12h");
   }
  }
  if(Date.now()<TEMPORARY_IP_BLOCK.expiresAtUnix*1000)assert.equal(count(),0);
 });
});
test("server-signed trusted identity remains exempt from temporary network deny",async()=>{
 await withOrigin(async count=>{
  const key="temporary-ip-exemption-signing-key-1234567890";
  const payload=Buffer.from(JSON.stringify({
   sub:"person_12345678",sid:"session_12345678",status:"trust",
   host:"vynalthai.com",exp:Math.floor(Date.now()/1000)+600
  })).toString("base64url");
  const mac=createHmac("sha256",key).update(payload).digest("base64url");
  const r=await edge.fetch(new Request("https://vynalthai.com/c",{
   headers:{"CF-Connecting-IP":"60.51.219.195",
    Cookie:"__Secure-vynalth-sso="+payload+"."+mac}
  }),{CONSENT_SSO_SIGNING_SECRET:key},{});
  assert.equal(r.status,200);
  assert.equal(count(),1);
 });
});

test("full edge proxies fingerprinted CSS with correct MIME and no GPS browser challenge",async()=>{
 const original=globalThis.fetch;let hits=0;
 globalThis.fetch=async request=>{
  hits++;
  assert.equal(new URL(request.url).pathname,"/assets/DynamicPage-CqJImg6h.css");
  return new Response(".dynamic{color:green}",{
   status:200,headers:{"Content-Type":"text/css; charset=utf-8",
    "Cache-Control":"public, max-age=31536000, immutable"}
  });
 };
 try{
  const env={GPS_GATE_ENABLED:"true",GPS_GATE_SESSION_SECRET:
   "test-verdict-signing-secret-0000000000000000",
   GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",
   GPS_CAMPUS_RADIUS_METERS:"180"};
  const request=new Request("https://vynalthai.com/assets/DynamicPage-CqJImg6h.css",{
   headers:{"Accept":"text/css","Sec-Fetch-Dest":"style"}});
  const response=await edge.fetch(request,env,{});
  assert.equal(response.status,200);
  assert.match(response.headers.get("Content-Type"),/^text\/css/);
  assert.equal(await response.text(),".dynamic{color:green}");
  assert.equal(hits,1);
  assert.equal(response.headers.get("x-vynalth-edge"),"cloudflare-worker");
 }finally{globalThis.fetch=original}
});
test("full edge still returns GPS 403 for HTML page without location pass",async()=>{
 const env={GPS_GATE_ENABLED:"true",GPS_GATE_SESSION_SECRET:
  "test-verdict-signing-secret-0000000000000000",
  GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",
  GPS_CAMPUS_RADIUS_METERS:"180"};
 await withOrigin(async hits=>{
  const r=await edge.fetch(new Request("https://vynalthai.com/en/security",{
   headers:{"Accept":"text/html","Sec-Fetch-Dest":"document"}}),env,{});
  assert.equal(r.status,403);
  assert.match(await r.text(),/Verify your location/);
  assert.equal(hits(),0);
 });
});


test("Shield ingest POST skips browser GPS only at the main site; origin still authenticates", async()=>{
 const env={GPS_GATE_ENABLED:"true",GPS_GATE_SESSION_SECRET:
  "test-verdict-signing-secret-0000000000000000",
  GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",
  GPS_CAMPUS_RADIUS_METERS:"180"};
 await withOrigin(async count=>{
  const req=new Request("https://vynalthai.com/api/security/ingest",{
   method:"POST",
   headers:{"Accept":"application/json","Content-Type":"application/json",
    "Authorization":"Bearer must-validate-at-origin"},
   body:JSON.stringify({test:true})
  });
  const resp=await edge.fetch(req,env,{});
  assert.equal(resp.status,200,"Authorized endpoint route must reach the real origin");
  assert.equal(count(),1);
  assert.equal(resp.headers.get("x-vynalth-edge"),"cloudflare-worker");
 });
 await withOrigin(async count=>{
  const req=new Request("https://search.vynalthai.com/api/security/ingest",{
   method:"POST",headers:{"Accept":"application/json"}
  });
  const resp=await edge.fetch(req,env,{});
  assert.equal(resp.status,403,"Do not exempt other hosts");
  assert.equal(count(),0);
 });
});
