import test from "node:test";
import assert from "node:assert/strict";
import { dispatchTidbHoneypotEvent, scheduleTidbHoneypotEvent, honeypotDiagnosticsEnabled } from "./tidb-honeypot.js";
const DIAG_UNTIL = new Date(Date.now() + 60 * 60 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

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


test("privacy-safe diagnostic logs only sampled write result, never sensitive payload", async () => {
  const originalInfo=console.info;
  const originalWarn=console.warn;
  const logs=[];
  console.info=(...fields)=>logs.push(fields.map(String).join(" "));
  console.warn=(...fields)=>logs.push(fields.map(String).join(" "));
  const monitored={...enabled,TIDB_HONEYPOT_DIAGNOSTICS_ENABLED:"true",
    TIDB_HONEYPOT_DIAGNOSTICS_UNTIL:DIAG_UNTIL};
  try {
    const inserted=await dispatchTidbHoneypotEvent(makeArgs(monitored),()=>({
      execute(){return Promise.resolve({});}
    }));
    assert.equal(inserted.state,"inserted");
    assert.equal(logs.length,1);
    assert.match(logs[0],/tidb_honeypot_write_result/);
    assert.match(logs[0],/"state":"inserted"/);
    for (const v of [DUMMY_URL,"fake_password","198.51.100.41",
                     "SENSITIVE","/admin.php","session=","SELECT","INSERT INTO"]) {
      assert.equal(logs.join(" ").includes(v),false,v);
    }
    logs.length=0;
    const failed=await dispatchTidbHoneypotEvent(makeArgs(monitored),()=>({
      execute(){throw Error("access denied; mysql://secret:SENSITIVE@evil.example")}
    }));
    assert.equal(failed.state,"failed");
    assert.match(logs.join(" "),/"reason":"auth"/);
    assert.equal(logs.join(" ").includes("SENSITIVE"),false);
    assert.equal(logs.join(" ").includes("evil.example"),false);
    logs.length=0;
    const missing=await dispatchTidbHoneypotEvent(makeArgs({
      ...monitored,TIDB_HONEYPOT_DATABASE_URL:"mysql://bad-password"
    }));
    assert.equal(missing.state,"not_configured");
    assert.match(logs.join(" "),/"state":"not_configured"/);
    assert.equal(logs.join(" ").includes("bad-password"),false);
  } finally {
    console.info=originalInfo;
    console.warn=originalWarn;
  }
});

test("diagnostics do not run for a sampled-out decoy and never schedule with invalid URL", () => {
  const logged=[];
  const originalInfo=console.info;
  console.info=(...xs)=>logged.push(xs.map(String).join(" "));
  try {
    const scheduled=[];
    const ctx={waitUntil(p){scheduled.push(p)}};
    const noSample={...enabled,TIDB_HONEYPOT_SAMPLE_RATE:"0.1",
      TIDB_HONEYPOT_DIAGNOSTICS_ENABLED:"true",
      TIDB_HONEYPOT_DIAGNOSTICS_UNTIL:DIAG_UNTIL};
    assert.equal(scheduleTidbHoneypotEvent({...makeArgs(noSample),ctx},()=>0.99),false);
    assert.equal(scheduled.length,0);
    assert.equal(logged.length,1);
    assert.match(logged[0],/"state":"sampled_out"/);
    assert.match(logged[0],/"reason":"sampling"/);
    logged.length=0;
    const missing={...enabled,TIDB_HONEYPOT_DIAGNOSTICS_ENABLED:"true",
      TIDB_HONEYPOT_DIAGNOSTICS_UNTIL:DIAG_UNTIL,
      TIDB_HONEYPOT_DATABASE_URL:"mysql://not-a-real-url"};
    // Incorrect credentials/config are identified without depending on RNG.
    assert.equal(scheduleTidbHoneypotEvent({...makeArgs(missing),ctx},()=>0.99),false);
    assert.equal(scheduled.length,0);
    assert.equal(logged.length,1);
    assert.match(logged[0],/"state":"not_configured"/);
    logged.length=0;
    const disabled={...noSample,TIDB_HONEYPOT_INGEST_ENABLED:"false"};
    assert.equal(scheduleTidbHoneypotEvent({...makeArgs(disabled),ctx},()=>0),false);
    assert.match(logged[0],/"state":"disabled"/);
    logged.length=0;
    assert.equal(scheduleTidbHoneypotEvent(makeArgs(noSample),()=>0),false);
    assert.match(logged[0],/"state":"no_lifecycle"/);
    for(const sensitive of [DUMMY_URL,"fake_password","198.51.100.41","SENSITIVE","/admin.php"]) {
      assert.equal(logged.join(" ").includes(sensitive),false);
    }
  } finally { console.info=originalInfo; }
});

test("bounded failed-stage labels identify normalizer, connect and execute without leaking secrets", async () => {
  const originalInfo = console.info;
  const originalWarn = console.warn;
  const lines = [];
  console.info = (...xs) => lines.push(xs.map(String).join(" "));
  console.warn = (...xs) => lines.push(xs.map(String).join(" "));
  const monitored = {
    ...enabled,
    TIDB_HONEYPOT_DIAGNOSTICS_ENABLED: "true",
    TIDB_HONEYPOT_DIAGNOSTICS_UNTIL: DIAG_UNTIL,
  };
  const expectOnlySafeStage = (stage, reason) => {
    assert.equal(lines.length, 1);
    assert.match(lines[0], /"state":"failed"/);
    assert.match(lines[0], new RegExp('"stage":"' + stage + '"'));
    assert.match(lines[0], new RegExp('"reason":"' + reason + '"'));
    for (const sensitive of ["SENSITIVE", DUMMY_URL, "fake_password", "/admin.php", "198.51.100.41"])
      assert.equal(lines[0].includes(sensitive), false, sensitive);
    lines.length = 0;
  };
  try {
    // Throw before connect is ever constructed.
    const badRequest = makeArgs(monitored);
    badRequest.request = { get method() { throw Error("SENSITIVE normalization error"); } };
    assert.equal((await dispatchTidbHoneypotEvent(badRequest, () => {
      throw Error("connect should not run");
    })).state, "failed");
    expectOnlySafeStage("normalization", "other");

    assert.equal((await dispatchTidbHoneypotEvent(makeArgs(monitored), () => {
      throw Error("fetch failed: mysql://fake_password:SENSITIVE@evil.invalid");
    })).state, "failed");
    expectOnlySafeStage("connect", "transport");

    assert.equal((await dispatchTidbHoneypotEvent(makeArgs(monitored), () => ({
      execute() { throw Error("access denied SENSITIVE credentials"); },
    }))).state, "failed");
    expectOnlySafeStage("execute", "auth");
  } finally {
    console.info = originalInfo;
    console.warn = originalWarn;
  }
});

test("short-term diagnostic window auto-expires, fails closed on missing or malformed UTC deadline", () => {
  const now=Date.parse("2026-11-19T10:30:00Z");
  const valid={TIDB_HONEYPOT_DIAGNOSTICS_ENABLED:"true",
    TIDB_HONEYPOT_DIAGNOSTICS_UNTIL:"2026-11-19T11:30:00Z"};
  assert.equal(honeypotDiagnosticsEnabled(valid,now),true);
  assert.equal(honeypotDiagnosticsEnabled(valid,now+60*60*1000),false);
  assert.equal(honeypotDiagnosticsEnabled(valid,now+60*60*1000+1),false);
  assert.equal(honeypotDiagnosticsEnabled({...valid,TIDB_HONEYPOT_DIAGNOSTICS_UNTIL:"2026-11-19T20:30:00Z"},now),false);
  assert.equal(honeypotDiagnosticsEnabled({...valid,TIDB_HONEYPOT_DIAGNOSTICS_UNTIL:"2026-11-19T11:30:00+00:00"},now),false);
  assert.equal(honeypotDiagnosticsEnabled({...valid,TIDB_HONEYPOT_DIAGNOSTICS_UNTIL:"bad-data"},now),false);
  assert.equal(honeypotDiagnosticsEnabled({TIDB_HONEYPOT_DIAGNOSTICS_ENABLED:"true"},now),false);
  assert.equal(honeypotDiagnosticsEnabled({...valid,TIDB_HONEYPOT_DIAGNOSTICS_ENABLED:"false"},now),false);
});
