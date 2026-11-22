import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  tidbAcceptanceAuthConfigured,
  tidbAcceptanceLogin,
  tidbAcceptanceSession,
  tidbAcceptanceLogout,
  tidbAcceptanceWithinWindow,
} from "./tidb-acceptance-auth.js";
import { handleTidbAcceptance } from "./tidb-acceptance.js";

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const ROOT = "https://vynalthai.com/__ops/tidb-acceptance";
const PASSWORD = "EXAMPLE_ONLY_AUTH_PASSWORD_22";
const COOKIE = "__Host-vynalth-tidb-acceptance";
const dummyMatch = async candidate => candidate === PASSWORD;
function createEnv() {
  const kvMap = new Map();
  const kv = {
    async get(key) { return kvMap.get(key) || null; },
    async put(key, value, opts) {
      assert.ok(opts?.expirationTtl >= 60);
      kvMap.set(key, value);
    },
    async delete(key) { kvMap.delete(key); },
  };
  return { SCHOOL_IP_KV: kv, kvMap };
}
function loginRequest(password = PASSWORD, origin = "https://vynalthai.com") {
  return new Request(ROOT + "/api/login", {
    method: "POST",
    headers: {
      "Origin": origin,
      "Sec-Fetch-Site": "same-origin",
      "Content-Type": "application/json",
      "CF-Connecting-IP": "198.51.100.10",
    },
    body: JSON.stringify({ password }),
  });
}
test("temporary fixed verifier needs no Cloudflare password Secret, but fails closed without KV", async () => {
  const env = createEnv();
  assert.equal(tidbAcceptanceAuthConfigured(env), true);
  const missing = {};
  assert.equal(tidbAcceptanceAuthConfigured(missing), false);
  const res = await tidbAcceptanceLogin(loginRequest(), missing, new URL(ROOT));
  assert.equal(res.status, 503);
  assert.equal(JSON.stringify(await res.json()).includes(PASSWORD), false);
  assert.equal(tidbAcceptanceWithinWindow(Date.parse("2026-11-25T15:59:59Z")-1),true);
  assert.equal(tidbAcceptanceWithinWindow(Date.parse("2026-11-25T15:59:59Z")),false);
});
test("login issues independent secure HttpOnly cookie, no password in response or KV", async () => {
  const env = createEnv(), request = loginRequest();
  const res = await tidbAcceptanceLogin(request, env, new URL(request.url), dummyMatch);
  assert.equal(res.status, 200);
  const cookie = res.headers.get("Set-Cookie") || "";
  assert.match(cookie, /^__Host-vynalth-tidb-acceptance=v1\.[A-Za-z0-9_-]{43};/);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Secure/);
  assert.equal(cookie.includes(PASSWORD), false);
  assert.equal(JSON.stringify([...env.kvMap]).includes(PASSWORD), false);
  assert.equal(JSON.stringify([...env.kvMap]).includes("198.51.100.10"), false);
  const value = cookie.split(";")[0];
  const sessionReq = new Request(ROOT + "/api/status", { headers: { Cookie: value } });
  const session = await tidbAcceptanceSession(sessionReq, env);
  assert.match(session.csrf, /^[A-Za-z0-9_-]{32}$/);
  assert.ok(session.expiry > Math.floor(Date.now() / 1000));
  assert.equal(await tidbAcceptanceSession(new Request(ROOT + "/api/status", {
    headers: { Cookie: "__Host-vynalth-ip-admin=OTHER_APP_SESSION" },
  }), env), null, "IP administration cookie must not authorize TiDB acceptance");
});
test("wrong dedicated password blocks after five failures, cannot silently create session", async () => {
  const env = createEnv();
  for (let i = 0; i < 5; i++) {
    const req = loginRequest("incorrect" + i);
    const response = await tidbAcceptanceLogin(req, env, new URL(req.url), dummyMatch);
    assert.equal(response.status, 401);
    assert.equal(response.headers.get("Set-Cookie"), null);
  }
  const correct = loginRequest();
  const locked = await tidbAcceptanceLogin(correct, env, new URL(correct.url), dummyMatch);
  assert.equal(locked.status, 429);
});
test("cross-site requests, malformed JSON and missing Cloudflare IP fail closed", async () => {
  const env = createEnv();
  const cross = loginRequest(PASSWORD, "https://untrusted.example");
  assert.equal((await tidbAcceptanceLogin(cross, env, new URL(cross.url), dummyMatch)).status, 403);
  const missingIp = new Request(ROOT + "/api/login", { method: "POST",
    headers: {"Origin":"https://vynalthai.com","Content-Type":"application/json"},
    body: JSON.stringify({password:PASSWORD}),
  });
  assert.equal((await tidbAcceptanceLogin(missingIp, env, new URL(missingIp.url), dummyMatch)).status, 403);
  const malformed = new Request(ROOT + "/api/login", { method: "POST",
    headers: {"Origin":"https://vynalthai.com","Content-Type":"application/json",
      "CF-Connecting-IP":"198.51.100.10"},
    body: '{"password":',
  });
  assert.equal((await tidbAcceptanceLogin(malformed, env, new URL(malformed.url), dummyMatch)).status, 400);
});
test("authenticated dedicated session permits status but CSRF and origin still block writes", async () => {
  const env = createEnv();
  const login = loginRequest();
  const logged = await handleTidbAcceptance(login, env, new URL(login.url), {
    login: (r,e,u) => tidbAcceptanceLogin(r,e,u,dummyMatch),
  });
  assert.equal(logged.status, 200);
  const cookie = logged.headers.get("Set-Cookie").split(";")[0];
  const statusReq = new Request(ROOT + "/api/status", { headers: { Cookie: cookie } });
  const status = await handleTidbAcceptance(statusReq, env, new URL(statusReq.url));
  assert.equal(status.status, 200);
  const state = await status.json();
  assert.equal(state.authenticated, true);
  assert.equal(state.writerConfigured, false);
  assert.match(state.csrf, /^[A-Za-z0-9_-]{32}$/);
  let writes = 0;
  const noCsrf = new Request(ROOT + "/api/run", { method:"POST",
    headers: {"Origin":"https://vynalthai.com","Cookie":cookie,"Content-Type":"application/json"},
    body: JSON.stringify({confirm:"RUN_SINGLE_PROBE"}),
  });
  const denied = await handleTidbAcceptance(noCsrf, env, new URL(noCsrf.url),
    { runProbe: async()=>{ writes++; return {state:"verified"}; } });
  assert.equal(denied.status, 403);
  assert.equal(writes, 0);
});
test("logout revokes just the temporary session", async () => {
  const env = createEnv(), req = loginRequest();
  const res = await tidbAcceptanceLogin(req, env, new URL(req.url), dummyMatch);
  assert.equal(res.status, 200);
  const cookie = res.headers.get("Set-Cookie").split(";")[0];
  const statusReq = new Request(ROOT+"/api/status",{headers:{Cookie:cookie}});
  const before = await tidbAcceptanceSession(statusReq,env);
  assert.ok(before?.csrf);
  const logout = new Request(ROOT+"/api/logout", { method: "POST",
    headers: { "Origin":"https://vynalthai.com", "Cookie":cookie,
      "X-CSRF-Token": before.csrf },
  });
  const out = await handleTidbAcceptance(logout,env,new URL(logout.url));
  assert.equal(out.status,200);
  assert.match(out.headers.get("Set-Cookie"), /Max-Age=0/);
  assert.equal(await tidbAcceptanceSession(statusReq,env),null);
});
