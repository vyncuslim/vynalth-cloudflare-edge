import test from "node:test";
import assert from "node:assert/strict";
import { applyVpnPageGradient, isVpnBrandDocument, VPN_GRADIENT_HEAD } from "../src/vpn-page-gradient.js";

const url = "https://vpn.page.vynalthai.com/";
const html = new Response("<!doctype html><html><head></head><body>VPN</body></html>", {
  headers: { "content-type": "text/html; charset=utf-8" },
  status: 200,
});

test("VPN HTML GET is eligible for scoped full-page brand", () => {
  assert.equal(isVpnBrandDocument(new Request(url), new URL(url), html), true);
});

test("other hosts never receive the injection", () => {
  for (const host of ["vpn.vynalthai.com", "vynalthai.com", "search.vynalthai.com", "zokivo.xyz"]) {
    const uri = "https://" + host + "/";
    assert.equal(isVpnBrandDocument(new Request(uri), new URL(uri), html), false, host);
  }
});

test("API, downloads, HEAD, redirect and non-HTML stay untouched", () => {
  const api = new Response('{"published":true}', { headers: { "content-type": "application/json" }});
  const binary = new Response("original-payload", { headers: { "content-type": "application/octet-stream" }});
  const redirect = new Response(null, {status: 307, headers: { location: "/downloads/x" }});
  assert.equal(applyVpnPageGradient(api, new Request(url + "api/releases"), new URL(url + "api/releases")), api);
  assert.equal(applyVpnPageGradient(binary, new Request(url + "downloads/Linux-CLI-vynalth-vpn"), new URL(url + "downloads/Linux-CLI-vynalth-vpn")), binary);
  assert.equal(applyVpnPageGradient(redirect, new Request(url), new URL(url)), redirect);
  assert.equal(applyVpnPageGradient(html, new Request(url, {method:"HEAD"}), new URL(url)), html);
});

test("design uses the complete fixed VPN palette, not random colors", () => {
  assert.match(VPN_GRADIENT_HEAD, /#0E61AC/);
  assert.match(VPN_GRADIENT_HEAD, /#FAF2E0/);
  assert.match(VPN_GRADIENT_HEAD, /body \{/);
  assert.match(VPN_GRADIENT_HEAD, /\.gateway-section/);
  assert.match(VPN_GRADIENT_HEAD, /\.download-card/);
  assert.match(VPN_GRADIENT_HEAD, /\.status-section/);
  assert.match(VPN_GRADIENT_HEAD, /\.site-footer/);
  assert.match(VPN_GRADIENT_HEAD, /data-vyn-gradient="new"/);
  assert.match(VPN_GRADIENT_HEAD, /Math\.random\(\)<0\.4/);
  assert.match(VPN_GRADIENT_HEAD, /vynalth-gradient-announcement\.js/);
});

test("HTML stream injection wraps the existing response without redirecting", () => {
  const original = globalThis.HTMLRewriter;
  let appended = "";
  globalThis.HTMLRewriter = class {
    on(selector, handler) {
      assert.equal(selector, "head");
      this.handler = handler;
      return this;
    }
    transform(response) {
      this.handler.element({
        append(value, opts) {
          assert.deepEqual(opts, {html:true});
          appended = value;
        }
      });
      return response;
    }
  };
  try {
    const result = applyVpnPageGradient(html, new Request(url), new URL(url));
    assert.equal(result, html);
    assert.ok(appended.includes("vyn-vpn-full-brand-2026"));
    assert.ok(appended.includes("vyn-vpn-40pct-cohort"));
    assert.ok(appended.includes("vynalth-gradient-announcement.js"));
  } finally {
    if (original === undefined) delete globalThis.HTMLRewriter;
    else globalThis.HTMLRewriter = original;
  }
});
