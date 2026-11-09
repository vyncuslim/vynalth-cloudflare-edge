/**
 * Reference client for the upstream Cloudflare Worker that calls the existing
 * Vynalth Edge SCHOOL/GPS policy-only Service Binding.
 *
 * COPY or import this module into the *calling* Worker, and use:
 *   const signed = await createSignedGpsPolicyRequest(request, env);
 *   const decision = await env.VYNALTH_GPS_POLICY.fetch(signed);
 *
 * GPS_SERVICE_AUTH_SECRET must be present as the same secret on both Workers.
 * The state and city come ONLY from Cloudflare request.cf, never visitor headers.
 * Do not route public client requests to the policy Service Binding directly.
 */
const PREFIX="x-vynalth-gps-service-";
const ENCODER=new TextEncoder();
const ORIGINS=new Set(["vyncuslim.com","www.vyncuslim.com"]);
function validated(value,regex,max=80){
  const x=typeof value==="string"?value:"";
  return x.length<=max&&regex.test(x)?x:"";
}
export async function createSignedGpsPolicyRequest(original, env){
  if(!(original instanceof Request))throw Error("INVALID_REQUEST");
  const url=new URL(original.url);
  if(url.protocol!=="https:"||!ORIGINS.has(url.hostname.toLowerCase()))
    throw Error("INVALID_POLICY_ORIGIN");
  const secret=env?.GPS_SERVICE_AUTH_SECRET;
  if(typeof secret!=="string"||secret.length<32)throw Error("GPS_SERVICE_SECRET_UNAVAILABLE");
  const ip=original.headers.get("CF-Connecting-IP");
  if(!ip||ip.length>64||!/^[a-fA-F0-9:.]+$/.test(ip))
    throw Error("SOURCE_IP_UNAVAILABLE");
  const country=validated(original.cf?.country,/^(?:[A-Z]{2})?$/,2);
  const code=country==="MY"
    ? validated(original.cf?.regionCode,/^[A-Za-z0-9-]*$/,16):"";
  const region=country==="MY"
    ? validated(original.cf?.region,/^[\p{L}\p{M} .-]*$/u,80):"";
  const city=country==="MY"
    ? validated(original.cf?.city,/^[\p{L}\p{M} .-]*$/u,80):"";
  const ts=String(Math.floor(Date.now()/1000));
  const payload=["gps-service-v3",ts,original.method.toUpperCase(),
    original.url,ip,country,code,region,city].join("\n");
  const key=await crypto.subtle.importKey("raw",ENCODER.encode(secret),
    {name:"HMAC",hash:"SHA-256"},false,["sign"]);
  const signature=Array.from(new Uint8Array(await crypto.subtle.sign(
    "HMAC",key,ENCODER.encode(payload))),n=>n.toString(16).padStart(2,"0")).join("");
  const headers=new Headers(original.headers);
  // Never allow an incoming visitor to set a service authentication field.
  for(const name of [...headers.keys()])
    if(name.toLowerCase().startsWith(PREFIX))headers.delete(name);
  headers.set(PREFIX+"v","3");
  headers.set(PREFIX+"ts",ts);
  headers.set(PREFIX+"sig",signature);
  headers.set(PREFIX+"ip",ip);
  headers.set(PREFIX+"country",country);
  headers.set(PREFIX+"region-code",code);
  headers.set(PREFIX+"region",region);
  headers.set(PREFIX+"city",city);
  return new Request(original,{headers});
}
