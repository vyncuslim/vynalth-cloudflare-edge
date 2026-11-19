import test from "node:test";
import assert from "node:assert/strict";
import { dispatchTidbHoneypotEvent, scheduleTidbHoneypotEvent } from "./tidb-honeypot.js";

const DUMMY_URL = "mysql://instance.honey_writer:fake_password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com/vynalth_honeypot";
const enabled = {
  TIDB_HONEYPOT_INGEST_ENABLED: "true",
  TIDB_HONEYPOT_DATABASE_URL: DUMMY_URL,
  TIDB_HONEYPOT_SAMPLE_RATE: "1",
};
const makeArgs = (env = enabled, path = "/admin.php", kind = "login") => {
  const request = new Request("https://vynalthai.com" + path + "?session=SENSITIVE", {
    headers: { Cookie: "token=SENSITIVE", Authorization: "Bearer SENSITIVE",
      "CF-Connecting-IP": "198.51.100.41", "User-Agent": "SensitiveClient" },
  });
  Object.defineProperty(request, "cf", { value: { country: "MY" } });
  return { request, url: new URL(request.url), env, kind, status: 200,
    path, requestId: "11111111-2222-3333-4444-555555555555" };
};

test("TiDB honeypot is off by default, rejects root and bad URLs", async () => {
  assert.deepEqual(await dispatchTidbHoneypotEvent(makeArgs({})), { state: "disabled" });
  const invalidUrls = [
    DUMMY_URL.replace("instance.honey_writer", "instance.root"),
    DUMMY_URL.replace("tidbcloud.com", "attacker.example"),
    DUMMY_URL.replace("/vynalth_honeypot", "/other"),
    DUMMY_URL.replace("mysql://", "https://"),
    DUMMY_URL.replace("fake_password", ""),
  ];
  for (const url of invalidUrls) {
    const args = makeArgs({ ...enabled, TIDB_HONEYPOT_DATABASE_URL: url });
    assert.equal((await dispatchTidbHoneypotEvent(args)).state, "not_configured");
  }
});

test("TiDB honeypot uses parameterized INSERT, safe fields, no secret leakage", async () => {
  const calls = [];
  const result = await dispatchTidbHoneypotEvent(makeArgs(), ({url}) => {
    assert.equal(url, DUMMY_URL);
    return { execute(sql, params) { calls.push({sql,params}); return Promise.resolve({}); } };
  });
  assert.equal(result.state, "inserted");
  assert.equal(calls.length, 1);
  assert.match(calls[0].sql, /VALUES \(\?, \?, \?, \?, \?, \?, \?\)/);
  assert.deepEqual(calls[0].params, [
    "suspicious_probe", "cloudflare_worker", "HTTP",
    null, "MY", "/admin.php", "logged"
  ]);
  const serialized = JSON.stringify(calls);
  for (const forbidden of ["SENSITIVE", "198.51.100.41", "fake_password", "session="])
    assert.equal(serialized.includes(forbidden), false, forbidden);
});

test("TiDB honeypot rejects arbitrary event kinds and remains non-blocking on failure", async () => {
  const invalid = await dispatchTidbHoneypotEvent(makeArgs(enabled, "/admin.php", "unknown"),
    () => { throw Error("should not connect"); });
  assert.equal(invalid.state, "invalid_event");
  const oldWarn = console.warn;
  console.warn = () => {};
  try {
    const result = await dispatchTidbHoneypotEvent(makeArgs(), () => {
      throw Error("fake unreachable database");
    });
    assert.equal(result.state, "failed");
  } finally { console.warn = oldWarn; }
});

test("sampling and disabled flag do not schedule database calls", () => {
  const tasks = [];
  const ctx = {waitUntil(p){tasks.push(p)}};
  assert.equal(scheduleTidbHoneypotEvent({...makeArgs({}),ctx}), false);
  assert.equal(scheduleTidbHoneypotEvent({...makeArgs({...enabled,TIDB_HONEYPOT_SAMPLE_RATE:"0.1"}),ctx},()=>0.9),false);
  assert.equal(scheduleTidbHoneypotEvent({...makeArgs({...enabled,TIDB_HONEYPOT_SAMPLE_RATE:"0"}),ctx},()=>0),false);
  assert.equal(tasks.length,0);
});
