// Cloudflare Worker -> Vercel: cryptographically authenticate the originating visitor IP.
// Never trust x-vynalth-client-* headers submitted by the public browser.
// This is optional until the same VISITOR_IP_SIGNING_SECRET is configured in
// BOTH the Cloudflare Worker and the Vercel API project.
const AUTH_HEADERS = [
  'x-vynalth-client-ip','x-vynalth-client-ts','x-vynalth-client-signature','x-vynalth-client-host',
  'x-vynalth-client-country','x-vynalth-client-region','x-vynalth-client-geo-signature',
];
function plausibleIp(value) {
  if (!value || value.length > 45) return false;
  const octets=value.split('.');
  if(octets.length===4) return octets.every(s=>/^(0|[1-9][0-9]{0,2})$/.test(s)&&Number(s)<=255);
  return value.includes(':') && /^[0-9a-f:]+$/i.test(value) && value.length<=45;
}
export async function signedVisitorOriginRequest(request, env, now=Date.now()) {
  const headers = new Headers(request.headers);
  for (const name of AUTH_HEADERS) headers.delete(name);
  const key = String(env?.VISITOR_IP_SIGNING_SECRET || '');
  const ip = request.headers.get('CF-Connecting-IP')?.trim() || '';
  // Source is trusted only inside this Worker: Cloudflare generates CF-Connecting-IP
  // on requests from visitors. Do not use browser supplied X-Forwarded-For.
  if (key.length < 32 || !plausibleIp(ip)) return new Request(request,{headers});
  const host = new URL(request.url).hostname.toLowerCase();
  const ts=String(Math.floor(now / 1000));
  const payload=['v1',ip,ts,host].join('|');
  const signingKey=await crypto.subtle.importKey('raw',new TextEncoder().encode(key),
    {name:'HMAC',hash:'SHA-256'},false,['sign']);
  const signature=await crypto.subtle.sign('HMAC',signingKey,new TextEncoder().encode(payload));
  const hex=Array.from(new Uint8Array(signature),b=>b.toString(16).padStart(2,'0')).join('');
  headers.set('x-vynalth-client-host',host);
  headers.set('x-vynalth-client-ip',ip);
  headers.set('x-vynalth-client-ts',ts);
  headers.set('x-vynalth-client-signature',hex);

  // Only request.cf is provided by the Cloudflare runtime. Never sign browser
  // supplied cf-ipcountry / x-vercel-ip-country / x-vynalth-client-country.
  // Geo is approximate IP-derived location, not GPS.
  const country=String(request.cf?.country || '').toUpperCase();
  const region=String(request.cf?.regionCode || '').toUpperCase();
  if (/^[A-Z]{2}$/.test(country) && country!=='XX' && country!=='T1') {
    const safeRegion=/^[A-Z0-9-]{1,12}$/.test(region)?region:'';
    const geoPayload=['geo-v1',ip,ts,host,country,safeRegion].join('|');
    const geoMac=await crypto.subtle.sign('HMAC',signingKey,new TextEncoder().encode(geoPayload));
    const geoHex=Array.from(new Uint8Array(geoMac),b=>b.toString(16).padStart(2,'0')).join('');
    headers.set('x-vynalth-client-country',country);
    headers.set('x-vynalth-client-region',safeRegion);
    headers.set('x-vynalth-client-geo-signature',geoHex);
  }
  return new Request(request,{headers});
}
