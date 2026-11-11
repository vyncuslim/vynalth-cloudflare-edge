import test from "node:test";
import assert from "node:assert/strict";
import { isVerifiedGooglePublicCrawler, matchesCidr } from "./public-crawler-access.js";
import edge from "./index.js";

const crawlerIp = "66.249.66.1";
const ranges = async () => ["66.249.0.0/16", "2001:4860:4801:10::/64"];
function request(path = "/", opts = {}) {
  return new Request("https://" + (opts.host || "zokivo.vynalthai.com") + path, {
    method: opts.method || "GET",
    headers: {
      "CF-Connecting-IP": opts.ip ?? crawlerIp,
      "User-Agent": opts.ua ?? "Google-InspectionTool/1.0",
      Accept: "text/html",
      ...opts.headers,
    },
  });
}

test("CIDR validation verifies both IPv4 and IPv6 without network trust shortcuts", () => {
  assert.equal(matchesCidr("66.249.66.1", "66.249.0.0/16"), true);
  assert.equal(matchesCidr("66.248.66.1", "66.249.0.0/16"), false);
  assert.equal(matchesCidr("2001:4860:4801:10::7", "2001:4860:4801:10::/64"), true);
  assert.equal(matchesCidr("2001:4860:4801:11::7", "2001:4860:4801:10::/64"), false);
  assert.equal(matchesCidr("127.0.0.1", "127.0.0.0/33"), false);
  assert.equal(matchesCidr("127.0.0.999", "127.0.0.0/24"), false);
  assert.equal(matchesCidr("2001::2::5", "2001::/16"), false);
  assert.equal(matchesCidr("66.249.66.1", "2001::/16"), false);
});

test("only Google source-IP-verified search GET pages are exempt", async () => {
  for (const path of ["/", "/robots.txt", "/sitemap.xml", "/games", "/how-it-works", "/try",
    "/paper", "/paper/cards", "/library", "/study", "/icon.svg", "/zokivo-mark.svg",
    "/_next/static/chunk.js"]) {
    assert.equal(await isVerifiedGooglePublicCrawler(request(path), ranges), true, path);
  }
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {ua:"Googlebot/2.1"}), ranges), true);
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {ip:"2001:4860:4801:10::2"}), ranges), true);
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {ip:"198.51.100.8"}), ranges), false);
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {ua:"Mozilla/5.0"}), ranges), false);
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {host:"vynalthai.com"}), ranges), true);
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {host:"www.vynalthai.com"}), ranges), true);
  for (const host of ["vynalthai.com", "www.vynalthai.com"]) {
    for (const publicPath of [
      "/sitemap.xml", "/robots.txt", "/en", "/cn/", "/ms/legal",
      "/en/legal/privacy", "/cn/legal/terms", "/ms/legal/biometric-data-notice",
      "/en/about", "/en/news", "/assets/public-code.js",
    ]) {
      assert.equal(await isVerifiedGooglePublicCrawler(request(publicPath, {host}), ranges), true,
        host + publicPath + " must be available only to source-IP-verified crawlers");
    }
    for (const privatePath of [
      "/en/search", "/en/auth", "/en/checkout", "/en/dashboard", "/en/settings",
      "/en/profile", "/api/ai/chat", "/__shield/gps/verify", "/en/security/recovery",
      "/en/security/audit-log", "/en/legal/private-draft", "/.env",
    ]) {
      assert.equal(await isVerifiedGooglePublicCrawler(request(privatePath, {host}), ranges), false,
        host + privatePath + " may not gain GPS exemption");
    }
    assert.equal(await isVerifiedGooglePublicCrawler(request("/en/legal", {
      host, ua:"Googlebot/2.1", ip:"203.0.113.88"
    }), ranges), false, "Googlebot UA alone is insufficient");
    assert.equal(await isVerifiedGooglePublicCrawler(request("/en/legal", {
      host, ua:"Mozilla/5.0"
    }), ranges), false, "Unverified browser is not a Google crawler");
    assert.equal(await isVerifiedGooglePublicCrawler(request("/en/legal", {
      host, method:"POST"
    }), ranges), false, "Non-GET/HEAD requests must not bypass GPS");
  }
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {method:"POST"}), ranges), false);
  for (const path of ["/api/rooms/123456", "/host", "/join/123456", "/paper/scan/123456",
    "/__shield/gps/verify", "/admin", "/.env", "/_next/image?url=private"]) {
    assert.equal(await isVerifiedGooglePublicCrawler(request(path), ranges), false, path);
  }
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {
    ip:"203.0.113.50", headers:{"X-Forwarded-For":crawlerIp}
  }), ranges), false, "Client-supplied X-Forwarded-For cannot forge Google");
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {
    ip:"203.0.113.50", headers:{"CF-IPCountry":"US"}
  }), ranges), false, "Country cannot forge identity");
});

test("vyncuslim personal-site public SEO routes allow only verified Google", async () => {
  for (const host of ["vyncuslim.com", "www.vyncuslim.com"]) {
    for (const path of ["/", "/robots.txt", "/sitemap.xml", "/achievements",
      "/story", "/web-design", "/styles.css", "/script.js", "/favicon.svg"]) {
      assert.equal(await isVerifiedGooglePublicCrawler(request(path, { host }), ranges),
        true, host + path);
    }
    for (const path of ["/jingxin", "/api/friends", "/min-na", "/qing-annie-luo",
      "/api/v1/profile", "/jingxin/admin", "/__shield/gps/verify",
      "/assets/jingxin-memory-hq.avif", "/.env"]) {
      assert.equal(await isVerifiedGooglePublicCrawler(request(path, { host }), ranges),
        false, "Must never bypass GPS for private or unreviewed routes: " + host + path);
    }
    assert.equal(await isVerifiedGooglePublicCrawler(request("/", { host, ip: "203.0.113.75" }), ranges), false);
    assert.equal(await isVerifiedGooglePublicCrawler(request("/", { host, ua: "Googlebot/2.1", ip: "203.0.113.75" }), ranges), false);
    assert.equal(await isVerifiedGooglePublicCrawler(request("/", { host, method: "POST" }), ranges), false);
  }
  assert.equal(await isVerifiedGooglePublicCrawler(request("/", {host:"friends.vyncuslim.com"}), ranges),false);
});

test("Google IP list failure fails closed", async () => {
  assert.equal(await isVerifiedGooglePublicCrawler(request("/"), async () => {throw Error("offline");}),false);
  assert.equal(await isVerifiedGooglePublicCrawler(request("/"), async () => []),false);
});

test("edge delivers public content for verified Google and keeps School IP Policy", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input) => {
    const url = typeof input === "string" ? input : input.url;
    calls.push(url);
    if (url.startsWith("https://developers.google.com/static/crawling/ipranges/")) {
      return new Response(JSON.stringify({prefixes:[{"ipv4Prefix":"66.249.0.0/16"}]}), {
        status:200, headers:{"Content-Type":"application/json"}
      });
    }
    return new Response("ZoKivo public homepage", {status:200,headers:{"Content-Type":"text/html"}});
  };
  const env = {
    GPS_GATE_ENABLED:"true",
    GPS_REGION_TIMEZONE_ENABLED:"true",
    GPS_GATE_SESSION_SECRET:"test-gps-signing-secret-0000000000000000000000",
    GPS_CAMPUS_LAT:"5.3677",GPS_CAMPUS_LON:"100.21995",
    GPS_CAMPUS_RADIUS_METERS:"120",
    SCHOOL_POLICY:{async fetch(){return new Response(null,{status:204});}},
  };
  try {
    const google = await edge.fetch(request("/"), env, {});
    assert.equal(google.status,200);
    assert.equal(await google.text(),"ZoKivo public homepage");
    assert.ok(calls.some(x => x.includes("/ipranges/common-crawlers.json")));
    const originReads = () => calls.filter(x => x.startsWith("https://zokivo.vynalthai.com")).length;
    assert.equal(originReads(),1);
    const falseGoogle = await edge.fetch(request("/", {ip:"203.0.113.77"}),env,{});
    assert.notEqual(await falseGoogle.text(),"ZoKivo public homepage");
    assert.equal(originReads(),1);
    const blockedApi = await edge.fetch(request("/api/rooms/123456"),env,{});
    assert.notEqual(await blockedApi.text(),"ZoKivo public homepage");
    assert.equal(originReads(),1);
    env.SCHOOL_POLICY = {async fetch(){return new Response("school-block",{
      status:403,headers:{"X-School-Policy":"blocked"}
    });}};
    const schoolBlocked = await edge.fetch(request("/"),env,{});
    assert.equal(schoolBlocked.status,403);
    assert.equal(schoolBlocked.headers.get("X-School-Policy"),"blocked");
    assert.equal(originReads(),1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
