import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const file = resolve(fileURLToPath(new URL(".", import.meta.url)), "setup-verified-school-waf.mjs");

test("dry-run requires no Cloudflare token or zone config and makes no changes", () => {
  const result = spawnSync(process.execPath, [file], {
    encoding: "utf8",
    env: { PATH: process.env.PATH || "", HOME: process.env.HOME || "" }
  });
  assert.equal(result.status, 0, result.stderr);
  const data = JSON.parse(result.stdout);
  assert.equal(data.mode, "DRY_RUN");
  assert.equal(data.expression, 'ip.src in $powiis_verified_egress and not (http.host eq "vynalthai.com" and (http.request.uri.path eq "/__shield/campus-beacon" or http.request.uri.path eq "/school-ip-report"))');
  assert.equal(data.zones.length, 5);
});

test("apply fails safely without proper zone IDs and token", () => {
  const result = spawnSync(process.execPath, [file, "--apply"], {
    encoding: "utf8",
    env: { PATH: process.env.PATH || "", HOME: process.env.HOME || "" }
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /WAF setup/);
});
