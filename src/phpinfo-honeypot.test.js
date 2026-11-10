import test from "node:test";
import assert from "node:assert/strict";
import worker from "./index.js";
import { isPhpInfoHoneypotPath, handlePhpInfoHoneypot } from "./phpinfo-honeypot.js";
import { isObservedSecurityProbe, scheduleThreatTelemetry } from "./threat-telemetry.js";
import { classifyEdgeAlert } from "./edge-telegram-alert.js";

const host = "https://vynalthai.com";
const req = (path = "/api/phpinfo.php", method = "GET") =>
  new Request(host + path, { method });

test("only the phpinfo decoy path is handled; no unrelated API interception", () => {
  for (const path of ["/api/phpinfo.php", "/api/phpinfo.php/", "/API/PHPINFO.PHP",
    "/api%2Fphpinfo.php", "/api//phpinfo.php"]) {
    assert.equal(isPhpInfoHoneypotPath(new URL(host + path).pathname), true, path);
  }
  for (const path of ["/api/visitor-info", "/api/phpinfo.php.txt",
    "/api/phpinfo.php/extra", "/phpinfo.php", "/api/security/ingest"]) {
    assert.equal(isPhpInfoHoneypotPath(new URL(host + path).pathname), false, path);
    assert.equal(handlePhpInfoHoneypot(req(path), new URL(host + path)), null);
  }
  assert.equal(isPhpInfoHoneypotPath("/api/%GGphpinfo.php"), false);
});

test("decoy is responsive, accessible, static, and does not disclose request secrets", async () => {
  const secret = "TEST_QUERY_SECRET_9F51";
  const request = new Request(host + "/api/phpinfo.php?token=" + secret, {
    headers: {
      Authorization: "Bearer " + secret,
      Cookie: "session=" + secret,
      "X-Forwarded-For": "203.0.113.27",
      "User-Agent": "Scanner/" + secret,
    },
  });
  const response = handlePhpInfoHoneypot(request, new URL(request.url));
  assert.equal(response.status, 200);
  assert.match(response.headers.get("Content-Type"), /text\/html/);
  assert.match(response.headers.get("Content-Security-Policy"), /script-src 'none'/);
  assert.match(response.headers.get("X-Robots-Tag"), /noindex/);
  assert.match(response.headers.get("Cache-Control"), /no-store/);
  const body = await response.text();
  for (const expected of ["PHP Version 8.3.14", "Loaded Configuration File",
    "Server API", "memory_limit", "session.cookie_httponly",
    'name="viewport"', 'aria-label="Sections"']) {
    assert.ok(body.includes(expected), expected);
  }
  for (const unexpected of [secret, "203.0.113.27", "vynalthai.com",
    "<script", "<form", "document.cookie", "fetch("]) {
    assert.ok(!body.includes(unexpected), "unexpected reflected or executable content: " + unexpected);
  }
});

test("GET/HEAD render the decoy, other methods fail closed without reading bodies", async () => {
  for (const method of ["GET", "HEAD"]) {
    const response = handlePhpInfoHoneypot(req("/api/phpinfo.php", method), new URL(host + "/api/phpinfo.php"));
    assert.equal(response.status, 200);
    const body = await response.text();
    if (method === "HEAD") assert.equal(body, "");
    else assert.match(body, /<html lang="en">/);
  }
  for (const method of ["POST", "PUT", "PATCH", "DELETE"]) {
    const response = handlePhpInfoHoneypot(req("/api/phpinfo.php", method), new URL(host + "/api/phpinfo.php"));
    assert.equal(response.status, 405);
    assert.equal(response.headers.get("Allow"), "GET, HEAD");
    assert.equal(await response.text(), "");
  }
});

test("Worker handles the honeypot before origin proxy and GPS on every managed domain", async () => {
  const roots = ["vynalthai.com", "vynalthai.si", "vyncuslim.com",
    "vyncuslim.si", "vyncuslim.my", "sleepsomno.com",
    "vitamindai.online", "powiismunc.com", "vynli.xyz", "vynlink.xyz", "zokivo.xyz"];
  for (const domain of roots) {
    const request = new Request("https://" + domain + "/api/phpinfo.php?token=UNTRUSTED");
    const response = await worker.fetch(request, {
      GPS_GATE_ENABLED: "true",
      EDGE_TELEGRAM_ALERTS_ENABLED: "false",
      THREAT_INTEL_COLLECT_ENABLED: "false",
    }, { waitUntil() {} });
    assert.equal(response.status, 200, domain);
    assert.equal(response.headers.get("x-vynalth-edge"), "cloudflare-worker", domain);
    assert.match(await response.text(), /PHP Version 8.3.14/);
  }
});

test("GET honeypot request is a suspicious probe even though its HTTP status is 200", () => {
  assert.equal(isObservedSecurityProbe(req()), true);
  assert.equal(isObservedSecurityProbe(req("/api/phpinfo.php", "POST")), true);
  assert.equal(isObservedSecurityProbe(req("/api/phpinfo.php", "DELETE")), true);
  const issue = classifyEdgeAlert(req(), new Response(null, { status: 200 }));
  assert.equal(issue.code, "SUSPICIOUS_PROBE");
  assert.equal(issue.severity, "Warning");
});

test("honeypot emits only privacy-bounded, normalized telemetry without attacker input", async () => {
  const oldFetch = globalThis.fetch;
  const pending = [];
  let event;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, host + "/api/security/ingest");
    event = JSON.parse(options.body);
    return new Response(null, { status: 202 });
  };
  try {
    const request = new Request(host + "/api/phpinfo.php?password=SECRET", {
      headers: { Cookie: "session=SECRET", "User-Agent": "SECRET",
        "CF-Connecting-IP": "198.51.100.35", "CF-Ray": "1234567890abcdef-KUL" },
    });
    assert.equal(scheduleThreatTelemetry(request,
      { THREAT_INTEL_COLLECT_ENABLED: "true", THREAT_INTEL_INGEST_TOKEN: "a".repeat(64) },
      { waitUntil(p) { pending.push(p); } }, "test-id", 200), true);
    await Promise.all(pending);
    assert.equal(event.source, "honeypot");
    assert.equal(event.path, "/api/phpinfo.php");
    assert.equal(event.status, 200);
    assert.equal(event.classification, "suspicious_probe");
    for (const unexpected of ["SECRET", "198.51.100.35", "session=", "password="]) {
      assert.ok(!JSON.stringify(event).includes(unexpected));
    }
  } finally {
    globalThis.fetch = oldFetch;
  }
});
