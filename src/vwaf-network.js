/** Pure address normalization and advisory local-destination classification.
 * No DNS, network requests, identity inference or trust in forwarded headers.
 */
export function canonicalNetworkAddress(value){
 if(typeof value!=="string"||value.length>45)return null;
 const s=value.toLowerCase();
 if(/^\d{1,3}(?:\.\d{1,3}){3}$/.test(s)){
  const p=s.split(".");
  if(p.some(x=>Number(x)>255||String(Number(x))!==x))return null;
  return p.join(".");
 }
 if(!s.includes(":")||!/^[0-9a-f:.]+$/.test(s))return null;
 try{
  const h=new URL("http://["+s+"]/").hostname;
  return h.startsWith("[")&&h.endsWith("]")?h.slice(1,-1):null;
 }catch{return null}
}
function localV4(ip){
 const parts=ip.split(".").map(Number);
 if(parts.length!==4)return false;
 const [a,b]=parts;
 return a===0||a===10||a===127||(a===169&&b===254)||(a===172&&b>=16&&b<=31)||
  (a===192&&b===168)||(a===100&&b>=64&&b<=127);
}
export function isLocalDestination(value){
 if(typeof value!=="string"||value.length>512)return false;
 try{return isLocalDestinationUrl(new URL(value))}catch{return false}
}
// For already-parsed, bounded, explicitly reviewed destination fields only.
// The generic advisory string wrapper retains its existing 512-char budget.
export function isLocalDestinationUrl(u){
 if(!(u instanceof URL))return false;
 try{
  if(["file:","ftp:"].includes(u.protocol))return true;
  const hostname=u.hostname.toLowerCase().replace(/\.$/,"");
  if(hostname==="localhost"||hostname.endsWith(".localhost"))return true;
  const ip=canonicalNetworkAddress(hostname.replace(/^\[|\]$/g,""));
  if(!ip)return false;
  if(!ip.includes(":"))return localV4(ip);
  if(ip==="::"||ip==="::1"||/^f[cd][0-9a-f]{2}:|^fe[89ab][0-9a-f]:/.test(ip))return true;
  const mapped=ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if(mapped){
   const a=parseInt(mapped[1],16),b=parseInt(mapped[2],16);
   return localV4([a>>8,a&255,b>>8,b&255].join("."));
  }
  return false;
 }catch{return false}
}
