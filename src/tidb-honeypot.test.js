import test from "node:test";
import assert from "node:assert/strict";
import { dispatchTidbHoneypotEvent, scheduleTidbHoneypotEvent } from "./tidb-honeypot.js";

const DUMMY_URL = "mysql://instance.honey_writer:fake_password@gateway01.ap-southeast-1.prod.aws.tidbcloud.com/vynalth_honeypot";
const enabled = {
  TIDB_HONEYPOT_INGEST_ENABLED: "true",
  TIDB_HONEYPOT_DATABASE_URL: DUMMY_URL,
  TIDB_HONEYPOT_SAMPLE_RATE: "1",
};
const makeArgs = (env = enabled, path = "/admin.php", kind = "login", cf = { country: "MY" }) => {
  const request = new Request("https://vynalthai.com" + path + "?session=SENSITIVE", {
    headers: { Cookie: "token=SENSITIVE", Authorization: "Bearer SENSITIVE",
      "CF-Connecting-IP": "198.51.100.41", "User-Agent": "SensitiveClient" },
  });
  Object.defineProperty(request, "cf", { value: cf });
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

test("enriched telemetry stores only validated Cloudflare metadata", async () => {
  const env = { ...enabled, TIDB_HONEYPOT_ENRICHED_ENABLED: "true",
    TIDB_HONEYPOT_SAMPLE_RATE: "0.1" };
  const cf = { country:"MY", colo:"KUL", asn:15169,
    botManagement: { score:24, verifiedBot:false } };
  const calls = [];
  const result = await dispatchTidbHoneypotEvent(makeArgs(env, "/admin.php", "login", cf),
    ({url}) => {
      assert.equal(url, DUMMY_URL);
      return { execute(sql, params) { calls.push({sql,params}); return Promise.resolve({}); } };
    });
  assert.equal(result.state, "inserted");
  assert.equal(result.schema, "v2");
  assert.equal(calls.length, 1);
  assert.match(calls[0].sql, /network_asn/);
  assert.equal((calls[0].sql.match(/\?/g)||[]).length,19);
  const values=calls[0].params;
  assert.equal(values.length,19);
  assert.deepEqual(values.slice(0,7), [
    "suspicious_probe","cloudflare_worker","HTTP",null,"MY","/admin.php","logged"
  ]);
  assert.deepEqual(values.slice(7), [
    "11111111-2222-3333-4444-555555555555",
    "vynalthai.com", "GET", 200, "login", 15169, "KUL", 24,
    false, "cloudflare_edge_observed", "not_identified", 0.1,
  ]);
  for(const secret of ["SENSITIVE","198.51.100.41","fake_password","session="]) {
    assert.equal(JSON.stringify(calls).includes(secret),false,secret);
  }
});

test("metadata absent or untrusted is NULL, not fabricated", async () => {
  const env = { ...enabled, TIDB_HONEYPOT_ENRICHED_ENABLED: "true" };
  const calls=[];
  const request = makeArgs(env,"/admin.php","login",{
    country:"MY",colo:"INVALID-CODE",asn:-1,
    botManagement:{score:999,verifiedBot:true},
  });
  await dispatchTidbHoneypotEvent(request,()=>({
    execute(sql,params){ calls.push(params);return Promise.resolve({}); }
  }));
  assert.equal(calls[0][12],null);
  assert.equal(calls[0][13],null);
  assert.equal(calls[0][14],null);
  const proxy = makeArgs(env,"/admin.php","login",{
    country:"US",colo:"DFW",asn:13335,
    botManagement:{score:2,verifiedBot:true}
  });
  proxy.request.headers.set("CF-Connecting-IP","2a06:98c0:3600::103");
  const untrusted=[];
  await dispatchTidbHoneypotEvent(proxy,()=>({
    execute(sql,params){untrusted.push(params);return Promise.resolve({});}
  }));
  assert.equal(untrusted[0][4],null);
  assert.equal(untrusted[0][12],null);
  assert.equal(untrusted[0][14],null);
  assert.equal(untrusted[0][15],null);
  assert.equal(untrusted[0][16],"cloudflare_cross_zone_worker_proxy");
});

test("the old schema remains supported until migration is approved", async () => {
  const calls=[];
  const result = await dispatchTidbHoneypotEvent(makeArgs(),()=>({
    execute(sql,params){calls.push({sql,params});return Promise.resolve({});}
  }));
  assert.equal(result.schema,"v1");
  assert.equal(calls[0].params.length,7);
  assert.doesNotMatch(calls[0].sql,/network_asn/);
});

test("database failures log sanitized reason only, never SQL or credentials", async () => {
  const lines=[];
  const previous=console.warn;
  console.warn=(...args)=>lines.push(args.map(String).join(" "));
  try {
    const result=await dispatchTidbHoneypotEvent(
      makeArgs({...enabled,TIDB_HONEYPOT_ENRICHED_ENABLED:"true"}),()=>({
        execute(){throw Error("Unknown column; password=fake_password; SENSITIVE")}
      })
    );
    assert.equal(result.state,"failed");
    assert.match(lines.join(" "),/schema_mismatch/);
    assert.doesNotMatch(lines.join(" "),/fake_password|SENSITIVE|Unknown column/);
  } finally {console.warn=previous;}
});
