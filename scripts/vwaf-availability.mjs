/** Independent public endpoint smoke checks; fixed safe destinations only. */
import {fileURLToPath} from "node:url";
import {resolve} from "node:path";
export const CHECKS=Object.freeze([
 {name:"main-api-health",url:"https://vynalthai.com/api/health",type:"json"},
 {name:"search-home",url:"https://search.vynalthai.com/",type:"html"}
]);
async function prefix(response,max){
 const reader=response.body?.getReader();if(!reader)return "";
 const decoder=new TextDecoder();let size=0,out="";
 try{
  for(;;){const x=await reader.read();if(x.done)return out+decoder.decode();
   const take=x.value.subarray(0,max-size);size+=take.length;out+=decoder.decode(take,{stream:true});
   if(size>=max)return out+decoder.decode();
  }
 }finally{try{await reader.cancel()}catch{}}
}
export async function checkAvailability(fetchImpl=fetch,clock=Date.now){
 const at=new Date(clock()).toISOString();
 const results=await Promise.all(CHECKS.map(async c=>{
  const start=clock();let code=null,healthy=false,reason="unavailable";
  try{
   const r=await fetchImpl(c.url,{method:"GET",redirect:"manual",cache:"no-store",
    headers:{"Cache-Control":"no-cache",Accept:c.type==="json"?"application/json":"text/html","User-Agent":"Vynalth-Availability-Check/2.0"},
    signal:AbortSignal.timeout(5000)});
   code=r.status;
   if(code!==200){reason="unexpected_status";try{await r.body?.cancel()}catch{}}
   else{
    const type=r.headers.get("content-type")||"",s=await prefix(r,c.type==="json"?16384:65536);
    if(c.type==="json"&&type.includes("application/json")){
     try{healthy=JSON.parse(s)?.status==="ok"}catch{}
    }else if(c.type==="html"&&type.includes("text/html"))healthy=/<html\b/i.test(s)&&/Vynalth/i.test(s);
    reason=healthy?"ok":"unexpected_body";
   }
  }catch{reason="network_or_timeout"}
  return{name:c.name,healthy,httpStatus:code,reason,durationMs:Math.max(0,clock()-start)};
 }));
 return {schema:"vwaf-availability-probe-v1",observedAt:at,healthy:results.every(x=>x.healthy),results,
  limitation:"One runner location; point sample, not continuous availability or a 30-day SLI."};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 const r=await checkAvailability();console.log("VWAF_AVAILABILITY "+JSON.stringify(r));if(!r.healthy)process.exitCode=1;
}
