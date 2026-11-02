import test from "node:test";
import assert from "node:assert/strict";
import { gpsRegionalDecision } from "../src/gps-regional-trigger.js";
import { guestGpsGate } from "../src/guest-gps.js";

function makeEnv() {
  const records = new Map();
  return {
    GPS_GATE_ENABLED: "true",
    GPS_GATE_SESSION_SECRET: "test-geolocation-session-secret-over-32-characters",
    GPS_CAMPUS_LAT: "5.368",
    GPS_CAMPUS_LON: "100.220",
    GPS_CAMPUS_RADIUS_METERS: "500",
    GPS_REGION_TIMEZONE_ENABLED: "true",
    GPS_RECHECK_EVERY_DOCUMENT: "true",
    GPS_OUTSIDE_SESSION_FASTPASS: "true",
    CONSENT_KV: {
      async get(key) { return records.get(key) ?? null; },
      async put(key, value) { records.set(key, value); },
    },
  };
}
function cfRequest(url, init={}, country=null) {
  const req = new Request(url, init);
  if (country) Object.defineProperty(req, "cf", { value: { country } });
  return req;
}
const origin = "https://vynalthai.com";
const ip = "203.0.113.21";
const docHeaders = {
  "Accept": "text/html,application/xhtml+xml",
  "Sec-Fetch-Dest": "document",
  "CF-Connecting-IP": ip,
};
function outsideCookie(response) {
  const matched = response.headers.get("set-cookie")?.match(/__Host-vynalth-geo=([^;\s,]+)/);
  assert.ok(matched, "signed outside session cookie must be issued");
  return "__Host-vynalth-geo=" + matched[1];
}
async function verifyOutside(env) {
  const req = cfRequest(origin + "/__shield/gps/verify", {
    method: "POST",
    headers: {
      Origin: origin,
      "Content-Type": "application/json",
      "Sec-Fetch-Site": "same-origin",
    },
    body: JSON.stringify({ lat: 5.9, lon: 101.2, accuracy: 20, returnPath: "/" }),
  });
  const response = await guestGpsGate(req, env, new URL(req.url));
  assert.equal(response?.status, 200);
  assert.equal((await response.json()).classification, "outside");
  return outsideCookie(response);
}

test("foreign regional check is host/IP-bound and does not repeat every 2 minutes", async () => {
  const env = makeEnv();
  const url = origin + "/__shield/gps/region-check";
  const request = cfRequest(url, {
    method: "POST",
    headers: {
      "Origin": origin,
      "Content-Type": "application/json",
      "CF-Connecting-IP": ip,
    },
    body: JSON.stringify({ timezone: "America/New_York" }),
  }, "US");
  const result = await gpsRegionalDecision(request, env, new URL(url));
  assert.equal(result.response?.status, 200);
  assert.match(result.response.headers.get("set-cookie") ?? "", /Max-Age=1800/);
  const cookie = result.response.headers.get("set-cookie").split(";")[0];

  const followUp = cfRequest(origin + "/en/chat", {
    headers: { ...docHeaders, Cookie: cookie },
  }, "US");
  const followResult = await gpsRegionalDecision(followUp, env, new URL(followUp.url));
  assert.equal(followResult.skipGPS, true);
  const changedIp = cfRequest(origin + "/en/chat", {
    headers: { ...docHeaders, "CF-Connecting-IP": "203.0.113.22", Cookie: cookie },
  }, "US");
  const changedResult = await gpsRegionalDecision(changedIp, env, new URL(changedIp.url));
  assert.equal(changedResult.response?.status, 200,
    "a changed IP must not reuse the signed regional verdict");
});

test("signed outside GPS pass avoids foreign timezone preflight", async () => {
  const env = makeEnv();
  const cookie = await verifyOutside(env);
  const request = cfRequest(origin + "/en/chat", {
    headers: { ...docHeaders, Cookie: cookie },
  }, "US");
  const decision = await guestGpsGate(request, env, new URL(request.url));
  assert.equal(decision, null);
});

test("outside session transfers from the trusted hub without fresh GPS popup", async () => {
  const env = makeEnv();
  const cookie = await verifyOutside(env);
  const state = "A".repeat(32);
  const url = origin + "/__shield/gps/bridge?host=vynlink.xyz&return=%2Fexample&state=" + state;
  const request = cfRequest(url, { headers: { Cookie: cookie } });
  const response = await guestGpsGate(request, env, new URL(url));
  assert.equal(response?.status, 302);
  assert.match(response.headers.get("location") ?? "",
    /^https:\/\/vynlink\.xyz\/__shield\/gps\/import\?/);
});

test("cross-domain visitors without a target pass are routed via the bridge", async () => {
  const env = makeEnv();
  const url = "https://vynlink.xyz/example";
  const request = cfRequest(url, { headers: docHeaders });
  const response = await guestGpsGate(request, env, new URL(url));
  assert.equal(response?.status, 302);
  assert.match(response.headers.get("location") ?? "",
    /https:\/\/vynalthai\.com\/__shield\/gps\/bridge\?/);
});

test("an inside-campus GPS fix remains denied", async () => {
  const env = makeEnv();
  const url = origin + "/__shield/gps/verify";
  const request = cfRequest(url, {
    method: "POST",
    headers: { "Origin": origin, "Content-Type": "application/json" },
    body: JSON.stringify({ lat: 5.368, lon: 100.220, accuracy: 10, returnPath: "/" }),
  });
  const response = await guestGpsGate(request, env, new URL(url));
  assert.equal(response?.status, 403);
  assert.equal((await response.json()).error, "CAMPUS_RESTRICTED");
});

test("expired or forged outside tokens do not bypass the GPS challenge", async () => {
  const env = makeEnv();
  const url = origin + "/en/chat";
  const request = cfRequest(url, {
    headers: { ...docHeaders, Cookie: "__Host-vynalth-geo=invalid.token.signature" },
  });
  const result = await guestGpsGate(request, env, new URL(url));
  assert.equal(result?.status, 403);
});
