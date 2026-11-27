import test from "node:test";
import assert from "node:assert/strict";
import {inspectWafRequest,applyVynalthWaf} from "./vynalth-waf-core.js";
const env={VYNALTH_WAF_MODE:"enforce",VYNALTH_WAF_HOSTS:"vynalthai.com,search.vynalthai.com"};
const id="00000000-0000-4000-8000-000000000001";
for(const [path,rule] of [["/.git.zip","VWAF-107"],["/.env~","VWAF-107"],["/etc/passwd","VWAF-108"],["/.config/gh/hosts.yml","VWAF-109"],["/.env;fixture","VWAF-102"],["/%2eenv%ZZ/.git/config","VWAF-101"]]){
 test("v1.2 hard rule "+rule+" "+path,()=>{
  const r=new Request("https://vynalthai.com"+path),v=inspectWafRequest(r);
  assert.equal(v.block,true);assert.ok(v.signals.some(s=>s.id===rule));
  assert.equal(applyVynalthWaf(r,env,id,()=>{}).status,403);
 });
}
for(const path of ["/.well-known/security.txt","/robots.txt","/docs/etc/passwd","/api/releases","/firebase.json","/key.json","/env.js","/openapi.json","/docs/example.php.txt"]){
 test("v1.2 preserves legitimate path "+path,()=>assert.equal(inspectWafRequest(new Request("https://vynalthai.com"+path)).block,false));
}
test("framing and template heuristics are observations, not hard denials",()=>{
 const r=new Request("https://vynalthai.com/api/example?id=%7B%7Bfixture%7D%7D",{headers:{"Content-Length":"0","Transfer-Encoding":"chunked"}});
 const v=inspectWafRequest(r);assert.ok(v.signals.some(s=>s.id==="VWAF-207"));assert.ok(v.signals.some(s=>s.id==="VWAF-208"));assert.equal(v.block,false);
});
