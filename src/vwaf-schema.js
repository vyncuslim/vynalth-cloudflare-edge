/**
 * Explicit API contracts, reviewed against backend commit 0fb9f74407c69f584002726d225b04dbd91497fc.
 * Free-text input is never treated as injection. Reject only conditions the
 * reviewed handler already rejects; tighter typing remains advisory.
 */
import {isLocalDestination} from "./vwaf-network.js";
export const CONTRACT_REVISION="0fb9f74407c69f584002726d225b04dbd91497fc";
const IMAGE_RATIOS=new Set(["1:1","16:9","9:16"]);
function sig(id,category,blocking=false,score=blocking?70:20){return {id,category,blocking,score}}
export function inspectApiSchema(path,value){
 if(!["/api/ai/image","/api/web-search","/api/cloud-browser-live"].includes(path))return [];
 if(!value||typeof value!=="object"||Array.isArray(value))return [sig("VWAF-601","api_body_shape")];
 const own=(k)=>Object.hasOwn(value,k);
 const result=[];
 if(path==="/api/cloud-browser-live"){
  // Source-verified: only action=navigate invokes safeUrl(body.url).
  // The backend must still validate every resolved address and actual egress.
  // A syntactic edge check never substitutes for authorization or DNS checks.
  if(own("action")&&value.action==="navigate"&&own("url")&&typeof value.url==="string"){
   let target;
   try{target=new URL(value.url)}catch{return result}
   if(["http:","https:"].includes(target.protocol)&&isLocalDestination(value.url))
    result.push(sig("VWAF-606","browser_private_destination_contract",true,0));
  }
  return result;
 }
 if(path==="/api/web-search"){
  // The backend coerces and truncates query. Do not change that contract.
  if(!own("query")||typeof value.query!=="string"||!value.query.trim())result.push(sig("VWAF-602","api_query_type"));
  if(typeof value.query==="string"&&value.query.length>600)result.push(sig("VWAF-603","api_query_length"));
 }else{
  const p=own("prompt")?value.prompt:undefined;
  if(typeof p!=="string")result.push(sig("VWAF-602","api_prompt_type"));
  // Missing and falsy prompt, or an invalid string, are already rejected.
  if(!p||typeof p==="string"&&(!p.trim()||p.trim().length>2000))
    result.push(sig("VWAF-604","image_prompt_contract",true,0));
  const a=own("aspectRatio")?value.aspectRatio:undefined;
  // The backend uses a falsy-value default and trims the string.
  // Unknown types remain advisory because the current backend coerces them.
  if(a&&typeof a!=="string")result.push(sig("VWAF-602","api_aspect_ratio_type"));
  if(typeof a==="string"&&a&&!IMAGE_RATIOS.has(a.trim()))
    result.push(sig("VWAF-605","image_aspect_ratio_contract",true,0));
 }
 return result;
}
export function schemaResponse(request,signals,mode){
 if(mode!=="enforce"||!signals.some(s=>s.blocking))return null;
 const privateTarget=signals.some(s=>s.id==="VWAF-606");
 const prompt=signals.some(s=>s.id==="VWAF-604");
 const error=privateTarget?"PRIVATE_BROWSER_TARGET":prompt?"INVALID_IMAGE_PROMPT":"INVALID_ASPECT_RATIO";
 const message=privateTarget?"Private or local network targets are not allowed.":prompt?"Describe the image in 1 to 2000 characters.":"Choose 1:1, 16:9, or 9:16.";
 return new Response(request.method==="HEAD"?null:JSON.stringify({success:false,error,message}),{
  status:privateTarget?403:400,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"private, no-store",
   "X-Content-Type-Options":"nosniff","X-Vynalth-Security-Action":"vwaf-schema-rejected"}
 });
}
