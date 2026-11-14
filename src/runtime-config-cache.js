// The runtime configuration script is public but must not remain stale after
// deployment or retain values from a previous release in browser/CDN caches.
// This only affects the exact file name; all other asset caching is preserved.
export function applyRuntimeConfigCacheHeaders(headers, pathname) {
  if (pathname !== '/runtime-config.js') return headers;
  headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0');
  headers.set('CDN-Cache-Control', 'no-store');
  headers.set('Cloudflare-CDN-Cache-Control', 'no-store');
  headers.set('Surrogate-Control', 'no-store');
  headers.set('Pragma', 'no-cache');
  headers.set('Expires', '0');
  return headers;
}
