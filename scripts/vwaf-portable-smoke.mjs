/** Same offline, provider-neutral Fetch contract on each independent runtime.
 * No live URLs are fetched and no cloud credentials are required.
 */
import {createPortableWaf} from "../src/vwaf-portable.js";
const host="vynalthai.com",base="https://"+host;
const assert=(actual,expected,label)=>{if(actual!==expected)throw Error(label+": expected "+expected+", got "+actual)};
let forwarded=0;const events=[];
const guard=createPortableWaf({hosts:[host],structuredMode:"enforce",onEvent:e=>events.push(e)});
const app=async r=>{forwarded++;return new Response("application authentication required",{status:401})};
const check=async(path,status,init)=>assert((await guard(new Request(base+path,init),app)).status,status,path);
await check("/robots.txt",401);
await check("/.netrc",403);
await check("/api/records?id="+encodeURIComponent("{{fixture}}"),403);
await check("/api/records?id=ordinary",401);
await check("/search?q="+encodeURIComponent("SQL tutorial"),401);
const body=JSON.stringify({prompt:"fixture",aspectRatio:"bad"});
await check("/api/ai/image",400,{method:"POST",headers:{"Content-Type":"application/json","Content-Length":String(new TextEncoder().encode(body).length)},body});
assert((await guard(new Request("https://unrelated.example/"),app)).status,421,"host boundary");
assert(forwarded,3,"application authorization preserved");
assert(events.length>0,true,"redacted telemetry emitted");
assert(JSON.stringify(events).includes("fixture"),false,"no raw input in telemetry");
console.log("VWAF_PORTABLE_SMOKE passed; local Fetch behavior only, not a live cross-cloud deployment.");
