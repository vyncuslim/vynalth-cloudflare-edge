import test from "node:test";
import assert from "node:assert/strict";
import { guestGpsGate } from "../src/guest-gps.js";

const env = { GPS_GATE_ENABLED: "true" }; // no GPS signing config: normally fail closed
const call = (host, path, method = "GET") => {
  const url = new URL("https://" + host + path);
  const req = new Request(url, { method, headers: { Accept: "text/html" } });
  return guestGpsGate(req, env, url);
};

test("public bug bounty page is anonymous GET/HEAD readable only on apex hosts", async () => {
  for (const host of ["vynalthai.com", "www.vynalthai.com"]) {
    for (const lang of ["en", "cn", "ms"]) {
      for (const method of ["GET", "HEAD"]) {
        assert.equal(await call(host, "/" + lang + "/security/bug-bounty", method), null);
      }
    }
  }
});

test("retired public news article can reach its HTTP redirect on apex hosts", async () => {
  for (const host of ["vynalthai.com", "www.vynalthai.com"]) {
    for (const lang of ["en", "cn", "ms"]) {
      for (const method of ["GET", "HEAD"]) {
        assert.equal(await call(host, "/" + lang + "/news/bug-bounty-program", method), null);
      }
    }
  }
  for (const [host, path, method] of [
    ["vynalthai.com", "/en/news/bug-bounty-program", "POST"],
    ["shield.vynalthai.com", "/en/news/bug-bounty-program", "GET"],
    ["vynalthai.com", "/en/news/private-content", "GET"]
  ]) {
    const result = await call(host, path, method);
    assert.ok(result instanceof Response);
    assert.equal(result.status, 503);
  }
});

test("public bug bounty exemption does not open submission APIs, POSTs, or other hosts", async () => {
  for (const [host, path, method] of [
    ["vynalthai.com", "/en/security/bug-bounty", "POST"],
    ["shield.vynalthai.com", "/en/security/bug-bounty", "GET"],
    ["vynalthai.com", "/api/security/report/submit", "GET"],
    ["vynalthai.com", "/en/admin", "GET"],
    ["vynalthai.com", "/en/security/bug-bounty/private", "GET"]
  ]) {
    const res = await call(host, path, method);
    assert.ok(res instanceof Response, host + path + " must remain gated");
    assert.equal(res.status, 503, host + path + " must fail closed with unavailable GPS configuration");
  }
});
