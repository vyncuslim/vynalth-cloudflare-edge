import test from "node:test";
import assert from "node:assert/strict";
import worker from "./index.js";
import {
  PHP_HONEYPOT_ROUTES, matchPhpHoneypot, isPhpHoneypotPath,
  handlePhpHoneypot,
} from "./php-honeypots.js";
import { isObservedSecurityProbe, scheduleThreatTelemetry } from "./threat-telemetry.js";
import { classifyEdgeAlert } from "./edge-telegram-alert.js";

const base = "https://vynalthai.com";
const req = (path, method = "GET") => new Request(base + path, { method });

test("all new PHP decoys use exact, enumerated routes only", () => {
  assert.equal(PHP_HONEYPOT_ROUTES.length, 28);
  assert.equal(new Set(PHP_HONEYPOT_ROUTES.map(x => x.path)).size, 28);
  assert.equal(new Set(PHP_HONEYPOT_ROUTES.map(x => x.kind)).size, 7);
  for (const route of PHP_HONEYPOT_ROUTES) {
    assert.equal(isPhpHoneypotPath(route.path), true, route.path);
    assert.deepEqual(matchPhpHoneypot(route.path), route);
    assert.equal(matchPhpHoneypot(route.path.toUpperCase())?.path, route.path);
    assert.equal(isObservedSecurityProbe(req(route.path)), true);
  }
  for (const path of ["/index.php", "/api/visitor-info", "/api/security/ingest",
    "/api/legitimate.php", "/wp-admin/install.php", "/some.php",
    "/phpmyadmin/index.php/extra", "/admin.php.txt", "/wp-admin/index.php",
    "/filemanager.php/other", "/admin%252ephp", "/anything/index.php"]) {
    assert.equal(matchPhpHoneypot(path), null, path);
  }
  assert.equal(isPhpHoneypotPath("/api%2Finfo.php"), true);
  assert.equal(isPhpHoneypotPath("/api//info.php/"), true);
  assert.equal(isPhpHoneypotPath("/api/%GGinfo.php"), false);
  assert.equal(isPhpHoneypotPath("/".repeat(300)), false);
});

test("each PHP honeypot renders an isolated and responsive HTML fixture", async () => {
  const secret = "DO_NOT_REFLECT_UNTRUSTED_VALUE_3950";
  const representative = {
    php: ["PHP Version 8.3.14", "session.cookie_httponly"],
    diagnostics: ["Health Checks", "Database ping"],
    login: ["Administrator Sign in", 'disabled>'],
    database: ["Server Overview", "app_core"],
    config: ["APP_ENV", "DB_PASSWORD"],
    files: ["Document Root", "composer.json"],
    backup: ["Backup Jobs", "Restore operations"],
  };
  for (const route of PHP_HONEYPOT_ROUTES) {
    const url = new URL(base + route.path + "?secret=" + secret);
    const request = new Request(url, { headers: {
      Authorization: "Bearer " + secret, Cookie: "x=" + secret,
      "User-Agent": "Scanner/" + secret, "CF-Connecting-IP": "198.51.100.7",
    } });
    const response = handlePhpHoneypot(request, url);
    assert.equal(response.status, 200, route.path);
    assert.match(response.headers.get("Content-Type"), /text\/html/);
    assert.match(response.headers.get("Cache-Control"), /no-store/);
    assert.match(response.headers.get("X-Robots-Tag"), /noindex/);
    assert.match(response.headers.get("Content-Security-Policy"), /script-src 'none'/);
    assert.match(response.headers.get("Content-Security-Policy"), /form-action 'none'/);
    const body = await response.text();
    assert.match(body, /<meta name="viewport"/, route.path);
    for (const keyword of representative[route.kind]) assert.ok(body.includes(keyword), route.path + ": " + keyword);
    for (const forbidden of [secret, "198.51.100.7", "vynalthai.com",
      "<script", "<form", "fetch(", "document.cookie", "<a href"]) {
      assert.equal(body.includes(forbidden), false, route.path + ": " + forbidden);
    }
  }
});

test("HEAD has no response body; writes fail closed and cannot collect credentials", async () => {
  for (const route of PHP_HONEYPOT_ROUTES) {
    const url = new URL(base + route.path);
    const head = handlePhpHoneypot(req(route.path, "HEAD"), url);
    assert.equal(head.status, 200);
    assert.equal(await head.text(), "");
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      const resp = handlePhpHoneypot(req(route.path, method), url);
      assert.equal(resp.status, 405, route.path + " " + method);
      assert.equal(resp.headers.get("Allow"), "GET, HEAD");
      assert.equal(await resp.text(), "");
    }
  }
});

test("Telegram classifies decoys as probes on both 200 and 405", () => {
  for (const route of PHP_HONEYPOT_ROUTES) {
    const a = classifyEdgeAlert(req(route.path), new Response(null, { status: 200 }));
    const b = classifyEdgeAlert(req(route.path, "POST"), new Response(null, { status: 405 }));
    assert.equal(a?.code, "SUSPICIOUS_PROBE", route.path);
    assert.equal(b?.code, "SUSPICIOUS_PROBE", route.path);
  }
});

test("Worker intercepts all managed domain roots without calling origin or GPS", async () => {
  const domains = ["vynalthai.com", "vynalthai.si", "vyncuslim.com",
    "vyncuslim.si", "vyncuslim.my", "sleepsomno.com",
    "vitamindai.online", "powiismunc.com", "vynli.xyz", "vynlink.xyz", "zokivo.xyz"];
  const original = console.info;
  console.info = () => {};
  try {
    for (const domain of domains) {
      const request = new Request("https://" + domain + "/phpmyadmin/index.php?token=SECRET");
      const response = await worker.fetch(request, {
        GPS_GATE_ENABLED: "true", EDGE_TELEGRAM_ALERTS_ENABLED: "false",
        THREAT_INTEL_COLLECT_ENABLED: "false",
      }, { waitUntil() {} });
      assert.equal(response.status, 200, domain);
      assert.equal(response.headers.get("X-Vynalth-Edge"), "cloudflare-worker");
      assert.match(await response.text(), /Database Administration/);
    }
  } finally { console.info = original; }
});

test("all PHP honeypot telemetry has allowlisted path, 200/405 and no user secrets", async () => {
  const prior = globalThis.fetch;
  const sent = [];
  const pending = [];
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "https://vynalthai.com/api/security/ingest");
    sent.push(JSON.parse(options.body));
    return new Response(null, { status: 202 });
  };
  try {
    for (const [i, route] of PHP_HONEYPOT_ROUTES.entries()) {
      const method = i % 2 === 0 ? "GET" : "POST";
      const request = new Request(base + route.path + "?password=HIDDEN", {
        method, headers: { "CF-Ray": "1234567890abcdef-KUL",
          Authorization: "Bearer PRIVATE", Cookie: "private=PRIVATE",
          "CF-Connecting-IP": "203.0.113.28" },
      });
      assert.equal(scheduleThreatTelemetry(request, {
        THREAT_INTEL_COLLECT_ENABLED: "true",
        THREAT_INTEL_INGEST_TOKEN: "a".repeat(64),
      }, { waitUntil(p) { pending.push(p); } }, "test-id", i % 2 ? 405 : 200), true);
    }
    await Promise.all(pending);
    assert.equal(sent.length, PHP_HONEYPOT_ROUTES.length);
    sent.forEach((event, i) => {
      assert.equal(event.source, "honeypot");
      assert.equal(event.path, PHP_HONEYPOT_ROUTES[i].path);
      assert.equal(event.classification, "suspicious_probe");
      assert.equal(event.status, i % 2 ? 405 : 200);
      for (const forbidden of ["HIDDEN", "PRIVATE", "203.0.113.28",
        "password=", "private="]) assert.equal(JSON.stringify(event).includes(forbidden), false);
    });
  } finally { globalThis.fetch = prior; }
});
