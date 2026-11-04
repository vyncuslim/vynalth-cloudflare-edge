import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { gpsPenangOnlyDecision } from "./gps-penang-only.js";
import { guestGpsGate } from "./guest-gps.js";
import { GPS_HTML, GPS_CLIENT } from "./gps-verification-ui.js";
if (!globalThis.crypto) globalThis.crypto = webcrypto;

const SITE = "https://vynalthai.com";
const ENV = {
  GPS_GATE_ENABLED: "true",
  GPS_PENANG_ONLY_ENABLED: "true",
  GPS_REGION_TIMEZONE_ENABLED: "true",
  GPS_RECHECK_EVERY_DOCUMENT: "true",
  GPS_OUTSIDE_SESSION_FASTPASS: "true",
  GPS_GATE_SESSION_SECRET: "test-gps-penang-selector-secret-over-32-characters",
  GPS_CAMPUS_LAT: "5.3677",
  GPS_CAMPUS_LON: "100.21995",
  GPS_CAMPUS_RADIUS_METERS: "120",
};
function request(path="/protected", cf, headers={}) {
  const req = new Request(SITE + path, {
    headers: {
      Accept: "text/html",
      "Sec-Fetch-Dest": "document",
      "CF-Connecting-IP": "198.51.100.12",
      ...headers,
    },
  });
  if (cf !== undefined) Object.defineProperty(req, "cf", { value: cf });
  return req;
}
const gate = (req, env=ENV, country=null) =>
  guestGpsGate(req, env, new URL(req.url), null, null, country);

test("Penang island city and IP coordinates together trigger GPS",async()=>{
  for(const cf of [
    {country:"MY",regionCode:"07",region:"Penang",city:"George Town",latitude:"5.414",longitude:"100.329"},
    {country:"MY",regionCode:"MY-07",city:"Bayan Lepas",latitude:"5.294",longitude:"100.266"},
    {country:"MY",region:"Pulau Pinang",city:"Balik Pulau",latitude:"5.347",longitude:"100.232"}
  ]){
    const r=request("/private",cf);
    assert.equal(gpsPenangOnlyDecision(r,ENV).requireGPS,true,JSON.stringify(cf));
    const response=await gate(r);
    assert.equal(response?.status,403,JSON.stringify(cf));
    assert.match(await response.text(),/Precise location required/);
  }
});

test("Butterworth and other Penang mainland cities do NOT trigger island-only GPS",async()=>{
  for(const cf of [
    {country:"MY",regionCode:"07",region:"Penang",city:"Butterworth",latitude:"5.399",longitude:"100.374"},
    {country:"MY",regionCode:"07",region:"Penang",city:"Seberang Perai",latitude:"5.389",longitude:"100.38"},
    {country:"MY",regionCode:"07",city:"Bukit Mertajam",latitude:"5.363",longitude:"100.463"},
    // A mainland city declaration overrides misleading IP coordinates.
    {country:"MY",regionCode:"07",city:"Butterworth",latitude:"5.414",longitude:"100.329"}
  ]){
    const r=request("/private",cf);
    assert.equal(gpsPenangOnlyDecision(r,ENV).requireGPS,false,JSON.stringify(cf));
    assert.equal(await gate(r),null,JSON.stringify(cf));
  }
});

test("Penang state alone or ambiguous location does not force GPS",async()=>{
  for(const cf of [
    {country:"MY",regionCode:"07",region:"Penang"},
    {country:"MY",regionCode:"MY-07",city:"Penang",latitude:"5.414",longitude:"100.329"},
    {country:"MY",regionCode:"07",city:"George Town"},
    {country:"MY",regionCode:"07",city:"George Town",latitude:"5.399",longitude:"100.374"},
    {country:"MY",regionCode:"07",city:"George Town",latitude:"invalid",longitude:"100.329"}
  ]){
    const r=request("/private",cf);
    assert.equal(gpsPenangOnlyDecision(r,ENV).requireGPS,false,JSON.stringify(cf));
    assert.equal(await gate(r),null,JSON.stringify(cf));
  }
});

test("all known non-Penang Malaysian states enter without GPS or timezone page", async () => {
  for (const cf of [
    { country: "MY", region: "Johor", regionCode: "01" },
    { country: "MY", region: "Selangor", regionCode: "10" },
    { country: "MY", region: "Kedah", regionCode: "02" },
    { country: "MY", region: "Sabah", regionCode: "12" },
    { country: "MY", region: "Sarawak", regionCode: "13" },
    { country: "MY", region: "Perak", regionCode: "08" },
    { country: "MY", region: "Kuala Lumpur", regionCode: "14" },
  ]) assert.equal(await gate(request("/private", cf)), null, JSON.stringify(cf));
});

test("overseas visitors do not see legacy timezone preflight or GPS", async () => {
  for (const country of ["US", "SG", "GB", "JP", "AU", "TH", "ID"]) {
    const r = request("/private", { country, region: "Penang", regionCode: "07" });
    assert.equal(await gate(r), null, country);
  }
});

test("unknown state, country, or Cloudflare metadata does not block ordinary visits", async () => {
  for (const cf of [
    undefined, {}, { country: "MY" }, { country: "MY", regionCode: "" },
    { country: "XX" }, { country: "T1" }, { country: "MY", region: null },
  ]) {
    assert.equal(await gate(request("/private", cf)), null, JSON.stringify(cf));
  }
});

test("browser-supplied CF-IPCountry, state and timezone cannot spoof Penang selection", async () => {
  const spoofed = request("/private", { country: "MY", region: "Johor", regionCode: "01" }, {
    "CF-IPCountry": "MY", "X-Vynalth-Region": "Penang", "X-Region-Code": "07",
    "X-Timezone": "Asia/Kuala_Lumpur",
  });
  assert.equal(await gate(spoofed), null);
  const actual = request("/private", { country: "MY", regionCode: "07", city:"George Town", latitude:"5.414",longitude:"100.329" }, {
    "CF-IPCountry": "US", "X-Region-Code": "01", "X-Timezone": "Europe/London",
  });
  assert.equal((await gate(actual))?.status, 403);
});

test("non-Penang visits remain accessible if GPS signing configuration fails", async () => {
  const wrong = { ...ENV, GPS_GATE_SESSION_SECRET: "broken" };
  const johor = request("/private", { country: "MY", region: "Johor" });
  assert.equal(await gate(johor, wrong), null);
  const penang = request("/private", { country: "MY", regionCode: "07",city:"George Town",latitude:"5.414",longitude:"100.329" });
  assert.equal((await gate(penang, wrong))?.status, 503);
});

test("GPS status and verify-info routes remain accessible", async () => {
  const r = request("/__shield/gps/status", { country: "MY", regionCode: "07",city:"George Town",latitude:"5.414",longitude:"100.329" });
  const response = await gate(r);
  assert.equal(response?.status, 200);
  const status = await response.json();
  assert.equal(status.regionalPolicy.mode, "penang-island-only");
  assert.equal(status.regionalPolicy.gpsRequired, true);
  assert.equal(status.regionalPolicy.vpnDetection, "not-guaranteed");
  const info = await gate(request("/__shield/gps/verify-info", { country: "MY", regionCode: "07",city:"George Town",latitude:"5.414",longitude:"100.329" }));
  assert.equal(info?.status, 200);
  assert.equal((await info.json()).regionalMode, "penang-island-only");
});

test("status endpoint reports GPS enforcement only for Penang visitors", async () => {
  const johor = await gate(request("/__shield/gps/status",
    { country: "MY", region: "Johor", regionCode: "01" }));
  assert.equal(johor?.status, 200);
  const status = await johor.json();
  assert.equal(status.enforcing, false);
  assert.equal(status.regionalPolicy.mode, "penang-island-only");
  assert.equal(status.regionalPolicy.gpsRequired, false);
});

test("the legacy selection behavior is unchanged when Penang mode is disabled", async () => {
  const old = { ...ENV, GPS_PENANG_ONLY_ENABLED: "false",
    GPS_REGION_TIMEZONE_ENABLED: "false" };
  assert.equal((await gate(request("/private", { country: "MY", region: "Johor" }), old))?.status, 403);
});

test("signed internal country without a signed state must not trust the second Worker's state", async () => {
  const req = request("/private", { country: "MY", regionCode: "07" });
  const decision = gpsPenangOnlyDecision(req, ENV, "MY");
  assert.equal(decision.requireGPS, false,
    "the internal Worker's region is not proof of the original visitor state");
});


test("Shield SDK and verification API are not blocked by the optional Penang GPS overlay",async()=>{
  const env={...ENV};
  const cf={country:"MY",regionCode:"07",region:"Penang",city:"George Town",latitude:"5.414",longitude:"100.329"};
  for(const method of ["GET","HEAD"]){
    const req=new Request("https://shield.vynalthai.com/widget.js",{method,headers:{"Accept":"application/javascript"}});
    Object.defineProperty(req,"cf",{value:cf});
    assert.equal(await guestGpsGate(req,env,new URL(req.url)),null,method+" widget.js");
  }
  for(const method of ["GET","HEAD","POST","OPTIONS"]){
    const req=new Request("https://shield.vynalthai.com/api/verify",{method});
    Object.defineProperty(req,"cf",{value:cf});
    assert.equal(await guestGpsGate(req,env,new URL(req.url)),null,method+" /api/verify");
  }
  // Exact host/path/method only: this must NOT exempt private Shield URLs
  // or unrelated origins from the campus GPS policy.
  for(const u of ["https://shield.vynalthai.com/api/admin",
                  "https://shield.vynalthai.com/widget.js.map",
                  "https://another.vynalthai.com/widget.js"]){
    const req=new Request(u);
    Object.defineProperty(req,"cf",{value:cf});
    const result=await guestGpsGate(req,env,new URL(req.url));
    assert.equal(result?.status,403,u);
  }
  const unsafe=new Request("https://shield.vynalthai.com/api/verify",{method:"DELETE"});
  Object.defineProperty(unsafe,"cf",{value:cf});
  assert.equal((await guestGpsGate(unsafe,env,new URL(unsafe.url)))?.status,403);
});

test("Explicit Penang-only flag remains required to avoid changing unrelated domains",async()=>{
  const env={...ENV};delete env.GPS_PENANG_ONLY_ENABLED;
  const mainland=request("/private",{
    country:"MY",regionCode:"07",city:"Butterworth",latitude:"5.399",longitude:"100.374"
  });
  assert.equal(gpsPenangOnlyDecision(mainland,env).enabled,false);
  const legacy=await gate(mainland,env);
  assert.equal(legacy?.status,403,"Existing non-opted-in legacy policy is unchanged");
});

test("public guest /c and text-only chat POST never require location consent", async () => {
  const island = {country:"MY",regionCode:"07",region:"Penang",
    city:"George Town",latitude:"5.414",longitude:"100.329"};
  for (const path of ["/c","/en/c","/cn/c","/ms/c","/c/"]) {
    assert.equal(await gate(request(path,island)), null, path);
  }
  const post = new Request(SITE+"/api/ai/chat-guest", {
    method:"POST",headers:{"Content-Type":"application/json"},body:"{}"
  });
  Object.defineProperty(post,"cf",{value:island});
  assert.equal(await gate(post),null,"guest API continues to server Turnstile/JEV checks");
  assert.equal((await gate(request("/private",island)))?.status,403,
    "sensitive pages must still require their GPS check");
  assert.equal((await gate(request("/api/ai/chat",island)))?.status,403,
    "the authenticated AI route is not exempted by guest chat policy");
  const otherHost = new Request("https://private.vynalthai.com/c",{headers:{Accept:"text/html"}});
  Object.defineProperty(otherHost,"cf",{value:island});
  assert.equal((await guestGpsGate(otherHost,ENV,new URL(otherHost.url)))?.status,403,
    "the GPS exception is only for the primary site");
});

test("GPS UI waits for an explicit click and exits stalled permission requests", () => {
  assert.match(GPS_HTML,/Open public chat without location permission/);
  assert.match(GPS_CLIENT,/watchdog=setTimeout\(\(\)=>\{/);
  assert.match(GPS_CLIENT,/22000/);
  assert.match(GPS_CLIENT,/\$\("start"\)\.addEventListener\("click",run\)/);
  assert.doesNotMatch(GPS_CLIENT,/queueMicrotask\(autoRequest\)/);
  assert.doesNotMatch(GPS_CLIENT,/visibilitychange.*autoRequest/);
});
