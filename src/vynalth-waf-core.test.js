import test from "node:test";
import assert from "node:assert/strict";
import {inspectWafRequest,applyVynalthWaf,PILOT_HOSTS} from "./vynalth-waf-core.js";

const req=(path,host="vynalthai.com",options={})=>new Request("https://"+host+path,options);
const config=mode=>({VYNALTH_WAF_MODE:mode,VYNALTH_WAF_HOSTS:PILOT_HOSTS.join(",")});
const id="00000000-0000-4000-8000-000000000001";
const silent=()=>{};
for(const [path,rule] of [
  ["/.env","VWAF-102"],["/x/.ENV.production","VWAF-102"],
  ["/%252egit/config","VWAF-101"],["/.docker/config.json","VWAF-102"],
  ["/.kube/config","VWAF-102"],["/terraform.tfstate.backup","VWAF-103"],
  ["/api/phpinfo.PHP/extra","VWAF-104"],["/privatekey.pem","VWAF-102"],
  ["/actuator/heapdump","VWAF-106"],["/a%00b","VWAF-002"],
  ["/.git-credentials","VWAF-102"],["/.netrc","VWAF-102"],
  ["/.config/composer/auth.json","VWAF-103"]
])test("hard rule "+rule+" "+path,()=>{
  const v=inspectWafRequest(req(path));
  assert.equal(v.block,true);assert.ok(v.signals.some(s=>s.id===rule));
});
for(const path of ["/","/robots.txt","/sitemap.xml","/.well-known/security.txt","/.well-known/acme-challenge/abc","/en","/login","/api/auth/signup","/api/chat","/firebase.json","/env.js","/api/releases","/docs/example.php.txt","/openapi.json"])
  test("legitimate path "+path,()=>assert.equal(inspectWafRequest(req(path)).block,false));
test("Search-only development rules do not broaden to other hosts",()=>{
  assert.equal(inspectWafRequest(req("/@fs/fixture","search.vynalthai.com")).block,true);
  assert.equal(inspectWafRequest(req("/@fs/fixture")).block,false);
  assert.equal(inspectWafRequest(req("/.changeset/config.json","search.vynalthai.com")).block,true);
});
test("dedicated honeypots and unrelated domains are not intercepted",()=>{
  for(const host of ["shield.vynalthai.com","cf-test.vynalthai.com","vyncuslim.com","unrelated.example"])
    assert.equal(applyVynalthWaf(req("/phpinfo.php",host),config("enforce"),id,silent),null);
});
test("observe mode records high confidence but does not deny",()=>{
  const events=[];assert.equal(applyVynalthWaf(req("/.env"),config("observe"),id,e=>events.push(e)),null);
  assert.equal(events[0].would_block,true);assert.equal(events[0].action,"observe");
});
test("enforce mode denies a hard match with non-cacheable response",async()=>{
  const res=applyVynalthWaf(req("/.git/config"),config("enforce"),id,silent);
  assert.equal(res.status,403);assert.match(res.headers.get("cache-control"),/no-store/);
  assert.equal(res.headers.get("x-vynalth-security-action"),"block-vynalth-waf");
});
test("HEAD denial has no response body",async()=>{
  const res=applyVynalthWaf(req("/.env","vynalthai.com",{method:"HEAD"}),config("enforce"),id,silent);
  assert.equal(res.status,403);assert.equal(await res.text(),"");
});
test("structured query injection signals never trigger a denial alone",()=>{
  const r=req("/api/example?id=1%20union%20select%20a");
  assert.ok(inspectWafRequest(r).signals.some(s=>s.id==="VWAF-201"));
  assert.equal(applyVynalthWaf(r,config("enforce"),id,silent),null);
});
test("free-text search and AI body remain untouched",async()=>{
  const r=req("/api/chat?q=union%20select","vynalthai.com",{method:"POST",body:"example <script> content"});
  assert.equal(inspectWafRequest(r).signals.length,0);
  assert.equal(applyVynalthWaf(r,config("enforce"),id,silent),null);
  assert.equal(await r.text(),"example <script> content");
});
test("malformed encoded paths do not crash",()=>assert.doesNotThrow(()=>inspectWafRequest(req("/docs/%ZZ"))));
test("encoded traversal is observation only without a hard rule",()=>{
  const r=req("/docs/a%2f..%2fb");const d=inspectWafRequest(r);
  assert.ok(d.signals.some(s=>s.id==="VWAF-205"));assert.equal(d.block,false);
});
test("oversize queries are advisory; oversized paths are rejected",()=>{
  const a=inspectWafRequest(req("/search?q="+"a".repeat(5000)));
  assert.ok(a.signals.some(s=>s.id==="VWAF-206"));assert.equal(a.block,false);
  const b=inspectWafRequest(req("/"+"a".repeat(9000)));assert.ok(b.signals.some(s=>s.id==="VWAF-204"));assert.equal(b.block,true);
});
test("unknown mode, absent host and unrecognized host all remain off",()=>{
  for(const e of [{},config("invalid"),{VYNALTH_WAF_MODE:"enforce",VYNALTH_WAF_HOSTS:""}])
    assert.equal(applyVynalthWaf(req("/.env"),e,id,silent),null);
});
test("no bot, user-supplied identity or cookie bypass for protected files",()=>{
  const r=req("/.env?private=UNIQUE_PRIVATE_QUERY","vynalthai.com",{headers:{"user-agent":"ChatGPT-User","cookie":"secret=UNIQUE_PRIVATE_COOKIE","x-device-id":"UNIQUE_PRIVATE_DEVICE"}});
  Object.defineProperty(r,"cf",{value:{botManagement:{verifiedBot:true}}});
  const events=[];const res=applyVynalthWaf(r,config("enforce"),id,e=>events.push(e));
  assert.equal(res.status,403);assert.equal(events.length,1);
  assert.ok(!/UNIQUE_PRIVATE|\/\.env|ChatGPT-User/.test(JSON.stringify(events)));
});
test("telemetry failure cannot unblock a hard rule",()=>{
  assert.equal(applyVynalthWaf(req("/.env"),config("enforce"),id,()=>{throw Error("unavailable")}).status,403);
});
test("OPTIONS and websocket handshake remain unaffected on public paths",()=>{
  assert.equal(applyVynalthWaf(req("/api/chat","vynalthai.com",{method:"OPTIONS"}),config("enforce"),id,silent),null);
  assert.equal(applyVynalthWaf(req("/api/live","vynalthai.com",{headers:{Upgrade:"websocket"}}),config("enforce"),id,silent),null);
});
test("unsafe HTTP method rule uses request metadata (Fetch may reject TRACE upstream)",()=>{
  assert.ok(inspectWafRequest({url:"https://vynalthai.com/",method:"TRACE"}).block);
});
