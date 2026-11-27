import test from "node:test";
import assert from "node:assert/strict";
import {pathVariants} from "./vynalth-waf-core.js";
import {isLocalDestination,isLocalDestinationUrl} from "./vwaf-network.js";
import {inspectApiSchema,schemaResponse} from "./vwaf-schema.js";
import {inspectWafContent} from "./vwaf-content.js";
// Frozen previous normalization implementation: exact variant and order parity.
function normalizedDots(path){
  const parts=[];
  for(const segment of path.split("/")){
    if(segment===""||segment===".")continue;
    if(segment===".."){parts.pop();continue}
    parts.push(segment);
  }
  return "/"+parts.join("/");
}
function previousPathVariants(path) {
  const variants = new Set();
  let current=path;
  for(let i=0;i<3;i++) {
    const normalized=current.replace(/\\/g,"/").replace(/\/{2,}/g,"/");
    variants.add(normalized);
    // Some origin routers interpret segment parameters independently of paths.
    // Only fixed sensitive-file rules can turn this normalization into a denial.
    const noParameters=normalized.replace(/;[^/]*/g,"");
    variants.add(noParameters);
    // Inspection only: account for canonical dot segments without rewriting requests.
    variants.add(normalizedDots(normalized));variants.add(normalizedDots(noParameters));
    if(i===2) break;
    let decoded;
    try { decoded=decodeURIComponent(current); } catch {
      // Preserve malformed and non-ASCII bytes; decode only well-formed ASCII escapes.
      decoded=current.replace(/%([0-9a-f]{2})/gi,(m,h)=>parseInt(h,16)<128?String.fromCharCode(parseInt(h,16)):m);
    }
    if(decoded===current) break;
    current=decoded;
  }
  return [...variants];
}

test("canonical path fast path is exactly equivalent to previous normalization",()=>{
 const segments=["","docs","hello",".","..","report.json","%20","%E4%B8%AD","a;b","a%25b","a\\b","%ZZ"];
 let checked=0;
 for(const a of segments)for(const b of segments)for(const end of ["","/"]){
  const path=new URL("https://example.invalid/"+a+"/"+b+end).pathname;
  assert.deepEqual(pathVariants(path),previousPathVariants(path));checked++;
 }
 for(const path of ["/","/robots.txt","/docs/index.html","/api/health","/docs/中文","/docs/ordinary-name"]){
  assert.deepEqual(pathVariants(path),previousPathVariants(path));checked++;
 }
 assert.equal(checked,294);
});
test("reviewed destination validation handles full bounded URL without altering ordinary URL metadata",async()=>{
 const path="/api/cloud-browser-live";
 for(const origin of ["http://127.0.0.1","http://[::1]","http://localhost"]){
  const url=origin+"/"+ "a".repeat(700);
  assert.equal(isLocalDestinationUrl(new URL(url)),true);
  // Generic observation contract remains unchanged; only the explicit schema uses parsed URL.
  assert.equal(isLocalDestination(url),false);
  const body=JSON.stringify({action:"navigate",url});
  const r=new Request("https://vynalthai.com"+path,{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).length)},body});
  const signals=await inspectWafContent(r);
  assert.deepEqual(signals.map(s=>s.id),["VWAF-606"]);
  assert.equal(schemaResponse(r,signals,"enforce").status,403);
  assert.equal(await r.text(),body);
 }
 assert.deepEqual(inspectApiSchema(path,{action:"navigate",url:"https://example.com/"+"a".repeat(700)}),[]);
 assert.deepEqual(inspectApiSchema(path,{action:"status",url:"http://localhost/"+"a".repeat(700)}),[]);
 assert.deepEqual(inspectApiSchema("/api/web-search",{query:"http://localhost"}),[]);
});
