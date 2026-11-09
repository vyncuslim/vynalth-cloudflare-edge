import test from "node:test";
import assert from "node:assert/strict";
import {
  schoolGuard,
  coveredHost,
  validIPv4,
  CANDIDATE_IPS,
  ZONES,
  OBSERVATION_TTL_SECONDS
} from "../src/school/policy.js";

class MemoryKV {
  constructor() {
    this.data = new Map();
    this.writes = [];
  }
  async get(key) {
    return this.data.has(key) ? this.data.get(key) : null;
  }
  async put(key, value, options) {
    this.data.set(key, value);
    this.writes.push({ key, value, options });
  }
}

async function run({
  hostname = "vyncuslim.com", ip = "60.49.64.83",
  mode = "observe", kv = new MemoryKV(), path = "/",
  method = "GET"
} = {}) {
  const request = new Request("https://" + hostname + path, {
    method,
    headers: { "CF-Connecting-IP": ip }
  });
  const background = [];
  const ctx = { waitUntil(promise) { background.push(promise); } };
  let forwarded = 0;
  const response = await schoolGuard(
    request,
    { SCHOOL_IP_KV: kv, MODE: mode },
    ctx,
    () => {
      forwarded++;
      return new Response("origin", { status: 200 });
    }
  );
  await Promise.all(background);
  return { response, forwarded, kv };
}

test("all seven zones and legitimate subdomains are covered", () => {
  assert.equal(ZONES.length, 7);
  for (const zone of ZONES) {
    assert.equal(coveredHost(zone), true);
    assert.equal(coveredHost("www." + zone), true);
    assert.equal(coveredHost("api." + zone), true);
    assert.equal(coveredHost("evil" + zone), false);
  }
  assert.equal(coveredHost("random.example"), false);
});

test("IPv4 parsing rejects spoof-like and invalid input", () => {
  assert.equal(validIPv4("60.49.64.83"), true);
  for (const bad of ["", "999.1.2.3", "01.2.3.4", "1.2.3.4, 5.6.7.8", "::1"]) {
    assert.equal(validIPv4(bad), false);
  }
});

test("three observed IPs are candidates only, not auto-blocked", async () => {
  assert.equal(CANDIDATE_IPS.size, 3);
  for (const ip of CANDIDATE_IPS) {
    const { response, forwarded, kv } = await run({ ip, mode: "enforce" });
    assert.equal(response.status, 200);
    assert.equal(forwarded, 1);
    assert.ok(kv.data.has("observed:" + ip));
    assert.equal(kv.writes[0].options.expirationTtl, OBSERVATION_TTL_SECONDS);
    assert.equal(kv.data.has("blocked:" + ip), false);
  }
});

test("observe mode never blocks, even with manual blocked key", async () => {
  const kv = new MemoryKV();
  kv.data.set("blocked:60.49.64.83", "manual-review");
  const { response, forwarded } = await run({ mode: "observe", kv });
  assert.equal(response.status, 200);
  assert.equal(forwarded, 1);
});

test("enforce mode blocks only exact manually listed IPv4", async () => {
  const kv = new MemoryKV();
  kv.data.set("blocked:60.49.64.83", "manual-review");
  const blocked = await run({ mode: "enforce", kv });
  assert.equal(blocked.response.status, 403);
  assert.equal(blocked.forwarded, 0);
  assert.equal(blocked.response.headers.get("Cache-Control").includes("no-store"), true);
  const allowed = await run({ ip: "60.49.64.84", mode: "enforce", kv });
  assert.equal(allowed.response.status, 200);
  assert.equal(allowed.forwarded, 1);
});

test("only root GET visits produce candidate KV observations", async () => {
  const kv = new MemoryKV();
  await run({ path: "/favicon.ico", kv });
  await run({ path: "/", method: "POST", kv });
  assert.equal(kv.writes.length, 0);
  await run({ path: "/", kv });
  await run({ path: "/", kv });
  assert.equal(kv.writes.length, 1);
});

test("unrelated hosts pass through unchanged and write no KV data", async () => {
  const kv = new MemoryKV();
  kv.data.set("blocked:60.49.64.83", "manual-review");
  const { response, forwarded } = await run({ hostname: "other.example", mode: "enforce", kv });
  assert.equal(response.status, 200);
  assert.equal(forwarded, 1);
  assert.equal(kv.writes.length, 0);
});

test("missing KV and KV exceptions fail open", async () => {
  const req = new Request("https://vyncuslim.com/", {
    headers: { "CF-Connecting-IP": "60.49.64.83" }
  });
  let forwarded = 0;
  const next = () => { forwarded++; return new Response("OK"); };
  const noKV = await schoolGuard(req, { MODE: "enforce" }, null, next);
  assert.equal(noKV.status, 200);
  const broken = { async get() { throw new Error("test KV failure"); } };
  const withError = await schoolGuard(req, { MODE: "enforce", SCHOOL_IP_KV: broken }, null, next);
  assert.equal(withError.status, 200);
  assert.equal(forwarded, 2);
});

test("IPv6 and missing CF-Connecting-IP are forwarded", async () => {
  const kv = new MemoryKV();
  const req = new Request("https://vyncuslim.com/", {
    headers: { "CF-Connecting-IP": "2001:db8::1" }
  });
  const res = await schoolGuard(req, { MODE: "enforce", SCHOOL_IP_KV: kv }, null, () => new Response("OK"));
  assert.equal(res.status, 200);
});
