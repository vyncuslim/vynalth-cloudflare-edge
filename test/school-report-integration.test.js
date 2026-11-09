import test from "node:test";
import assert from "node:assert/strict";
import edge from "../src/index.js";
const worker={fetch(req,env,ctx){return edge.fetch(req,{
 SCHOOL_MANAGEMENT_INLINE_ENABLED:"true",SCHOOL_POLICY_INLINE_ENABLED:"true",...env
},ctx);}};
globalThis.fetch=async()=>new Response("origin-ok",{status:200});

const url = "https://vynalthai.com/block-ip";
const publicIp = "60.49.64.83";
const BODY = JSON.stringify({ consent: true, schoolWifiConfirmed: true });

function kvFixture() {
  const records = new Map();
  const writes = [];
  return {
    records,
    writes,
    async get(key) { return records.has(key) ? records.get(key) : null; },
    async put(key, value, options) {
      writes.push({ key, value, options });
      records.set(key, value);
    }
  };
}
async function invoke({ method = "GET", headers = {}, body, kv = kvFixture(), path = "/block-ip" } = {}) {
  const request = new Request(
    "https://vynalthai.com" + path,
    { method, headers: { "CF-Connecting-IP": publicIp, ...headers }, body }
  );
  return worker.fetch(request, { MODE: "observe", SCHOOL_IP_KV: kv }, {});
}
const post = (kv, overrides = {}) => invoke({
  method: "POST",
  kv,
  headers: {
    "Content-Type": "application/json",
    "Origin": "https://vynalthai.com",
    "Sec-Fetch-Site": "same-origin",
    ...(overrides.headers || {})
  },
  body: overrides.body === undefined ? BODY : overrides.body
});

test("GET / redirects to /block-ip, with no KV write", async () => {
  const kv = kvFixture();
  const response = await invoke({ kv, path: "/__vynalth/school" });
  assert.equal(response.status, 302);
  assert.equal(response.headers.get("Location"), "/block-ip");
  assert.deepEqual(kv.writes, []);
});

test("GET /block-ip renders informed consent page without recording IP", async () => {
  const kv = kvFixture();
  const response = await invoke({ kv });
  const html = await response.text();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type"), /text\/html/);
  assert.match(html, /Submitting does/);
  assert.match(html, /not an official POWIIS school service/i);
  assert.match(html, /72 hours/i);
  assert.match(html, /id="consent"/);
  assert.deepEqual(kv.writes, []);
});

test("POST requires explicit consent", async () => {
  const kv = kvFixture();
  const response = await post(kv, { body: JSON.stringify({ consent: false, schoolWifiConfirmed: true }) });
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error, "CONSENT_REQUIRED");
  assert.deepEqual(kv.writes, []);
});

test("POST consent stores unverified candidate in KV for 72h, never blocked:IP", async () => {
  const kv = kvFixture();
  const response = await post(kv);
  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), {
    received: true, pending: true, alreadyRecorded: false
  });
  assert.equal(kv.writes.length, 1);
  assert.equal(kv.writes[0].key, "student-report:" + publicIp);
  assert.equal(kv.writes[0].options.expirationTtl, 72 * 60 * 60);
  assert.equal(JSON.parse(kv.writes[0].value).reviewStatus, "pending-unverified");
  assert.equal(kv.records.has("blocked:" + publicIp), false);
});

test("repeated submission does not extend retention or duplicate writes", async () => {
  const kv = kvFixture();
  const first = await post(kv);
  const again = await post(kv);
  assert.equal(first.status, 201);
  assert.equal(again.status, 200);
  assert.equal((await again.json()).alreadyRecorded, true);
  assert.equal(kv.writes.length, 1);
});

test("cross-origin submission is rejected", async () => {
  const kv = kvFixture();
  const response = await post(kv, { headers: { Origin: "https://attacker.example" } });
  assert.equal(response.status, 403);
  assert.deepEqual(kv.writes, []);
});

test("requests with private or missing source IP cannot be recorded", async () => {
  const kv = kvFixture();
  const response = await invoke({
    kv, method: "POST", body: BODY,
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "192.168.1.5" }
  });
  assert.equal(response.status, 422);
  assert.deepEqual(kv.writes, []);
});

test("missing KV binding yields 503, not an acknowledged record", async () => {
  const request = new Request(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": publicIp },
    body: BODY
  });
  const response = await worker.fetch(request, { MODE: "observe" }, {});
  assert.equal(response.status, 503);
});

test("health and internal protocol remain unchanged", async () => {
  const kv = kvFixture();
  const health = await invoke({ kv, path: "/__vynalth/school/health" });
  const status = await health.json();
  assert.equal(status.ok, true);
  assert.equal(status.schoolPolicy, "inline-v1");
  assert.equal(status.kvBound, true);
  const internal = await worker.fetch(
    new Request("https://vyncuslim.com/", {
      headers: { "CF-Connecting-IP": publicIp }
    }),
    { MODE: "observe", SCHOOL_IP_KV: kv },
    { waitUntil(p) { return p; } }
  );
  assert.equal(internal.status, 200);
});


test("real public IPv6 addresses are accepted and retained as IPv6", async () => {
  const kv = kvFixture();
  const response = await post(kv, {
    headers: { "CF-Connecting-IP": "2606:4700:4700::1111" }
  });
  assert.equal(response.status, 201);
  assert.equal(kv.writes.length, 1);
  assert.equal(kv.writes[0].key, "student-report:2606:4700:4700::1111");
  const record = JSON.parse(kv.writes[0].value);
  assert.equal(record.ipFamily, "ipv6");
  assert.equal(record.reviewStatus, "pending-unverified");
  assert.equal(kv.records.has("blocked:2606:4700:4700::1111"), false);
});

test("Cloudflare Pseudo IPv4 overwrite uses original IPv6, not synthetic Class E", async () => {
  const kv = kvFixture();
  const response = await post(kv, {
    headers: {
      "CF-Connecting-IP": "240.16.0.1",
      "CF-Connecting-IPv6": "2400:cb00::b"
    }
  });
  assert.equal(response.status, 201);
  assert.equal(kv.writes[0].key, "student-report:2400:cb00::b");
  assert.equal(JSON.parse(kv.writes[0].value).ipFamily, "ipv6");
});

test("do not trust client-supplied IPv6 override when real IPv4 is present", async () => {
  const kv = kvFixture();
  const response = await post(kv, {
    headers: {
      "CF-Connecting-IP": publicIp,
      "CF-Connecting-IPv6": "2606:4700:4700::9999"
    }
  });
  assert.equal(response.status, 201);
  assert.equal(kv.writes[0].key, "student-report:" + publicIp);
});

test("missing real IP never falls back to spoofable X-Forwarded-For", async () => {
  const kv = kvFixture();
  const response = await post(kv, {
    headers: {
      "CF-Connecting-IP": "",
      "X-Forwarded-For": publicIp
    }
  });
  assert.equal(response.status, 422);
  const body = await response.json();
  assert.equal(body.error, "PUBLIC_IP_UNAVAILABLE");
  assert.equal(body.reason, "cf_header_missing");
  assert.equal(kv.writes.length, 0);
});

test("diagnostics never expose the visitor public IP", async () => {
  const kv = kvFixture();
  const response = await invoke({
    path: "/ip-status",
    headers: { "CF-Connecting-IP": "2606:4700:4700::1111" },
    kv
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.deepEqual(body, {
    ok: true, publicIpAvailable: true, family: "ipv6", reason: null
  });
  assert.doesNotMatch(JSON.stringify(body), /2606:4700/);
  assert.equal(kv.writes.length, 0);
});

test("diagnostics flag missing CF header without writing to KV", async () => {
  const kv = kvFixture();
  const response = await invoke({
    path: "/ip-status", headers: { "CF-Connecting-IP": "" }, kv
  });
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), {
    ok: true, publicIpAvailable: false, family: null,
    reason: "cf_header_missing"
  });
  assert.equal(kv.writes.length, 0);
});

test("reserved and cross-zone Worker synthetic IPv6 cannot become candidates", async () => {
  for (const source of [
    "::1", "fe80::1", "fc00::1", "2001:db8::1",
    "2a06:98c0:3600::103", "2606:4700:::1"
  ]) {
    const kv = kvFixture();
    const response = await post(kv, {
      headers: { "CF-Connecting-IP": source }
    });
    assert.equal(response.status, 422, source);
    assert.equal(kv.writes.length, 0, source);
  }
});
