/**
 * Scope a no-GPS route exemption to exactly the public Cyber Command's
 * read-only documents and its one authorized cacheable public source API.
 *
 * THIS IS NOT a security authorization result. Run only at the existing
 * guestGpsGate dispatch point, after temporary IP, device and federated checks
 * and before the existing School IP policy. Cloudflare WAF runs ahead of Worker.
 */
const DOCUMENT_PATH = /^\/(?:(?:en|cn|ms)\/)?cyber-command(?:\/(?:overview|live|threats|map|infrastructure|intel|ips|incidents|methodology))?\/?$/;

export function isPublicCyberCommandReadOnly(request, url) {
  if (!request || (request.method !== 'GET' && request.method !== 'HEAD')) return false;
  if (!(url instanceof URL)) return false;
  if (url.protocol !== 'https:') return false;
  if (url.hostname !== 'vynalthai.com' && url.hostname !== 'www.vynalthai.com') return false;
  if (url.pathname === '/api/public/cyber-command/ip-consensus') return true;
  return DOCUMENT_PATH.test(url.pathname);
}
