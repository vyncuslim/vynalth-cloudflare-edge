/** Loopback-only qualification fixture. Never deploy. No outbound fetch. */
import {createPortableWaf} from "../src/vwaf-portable.js";
const host="https://vynalthai.com";
const guard=createPortableWaf({hosts:["vynalthai.com"],structuredMode:"enforce",allowUnframedContent:true});
const next=async()=>new Response(null,{status:204});
function image(invalid,unframed){
 const text=JSON.stringify({prompt:"ordinary synthetic example",aspectRatio:invalid?"invalid":"1:1"});
 const bytes=new TextEncoder().encode(text),headers={"Content-Type":"application/json"};
 if(!unframed)headers["Content-Length"]=String(bytes.length);
 const body=unframed?new ReadableStream({start(c){c.enqueue(bytes);c.close()}}):text;
 return new Request(host+"/api/ai/image",{method:"POST",headers,body,duplex:"half"});
}
export default {async fetch(request){
 if(request.method!=="GET")return new Response(null,{status:405});
 switch(new URL(request.url).pathname){
  case "/ready":return new Response("vwaf-workerd-local-ready");
  case "/case/health":return guard(new Request(host+"/api/health"),next);
  case "/case/docs":return guard(new Request(host+"/docs/example"),next);
  case "/case/image":return guard(image(false,false),next);
  case "/case/image-invalid":return guard(image(true,false),next);
  case "/case/image-unframed":return guard(image(false,true),next);
  case "/case/image-unframed-invalid":return guard(image(true,true),next);
  default:return new Response(null,{status:404});
 }
}};
