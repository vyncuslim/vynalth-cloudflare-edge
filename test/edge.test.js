import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import edge from "../src/index.js";

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
