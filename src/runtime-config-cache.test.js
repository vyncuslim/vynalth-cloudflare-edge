import test from 'node:test';
import assert from 'node:assert/strict';
import { applyRuntimeConfigCacheHeaders } from './runtime-config-cache.js';

test('runtime config does not inherit public four-hour caching from origin or proxy', () => {
  const headers = new Headers({
    'Cache-Control': 'public, max-age=14400',
    'Content-Type': 'application/javascript',
    'X-Vercel-Cache': 'HIT',
  });
  const result = applyRuntimeConfigCacheHeaders(headers, '/runtime-config.js');
  assert.equal(result.get('Cache-Control'), 'no-store, no-cache, must-revalidate, max-age=0');
  assert.equal(result.get('CDN-Cache-Control'), 'no-store');
  assert.equal(result.get('Cloudflare-CDN-Cache-Control'), 'no-store');
  assert.equal(result.get('Surrogate-Control'), 'no-store');
  assert.equal(result.get('Expires'), '0');
  assert.equal(result.get('Content-Type'), 'application/javascript');
  assert.equal(result.get('X-Vercel-Cache'), 'HIT');
});

test('other static assets keep existing cache policy', () => {
  for (const pathname of ['/runtime-config.js.map', '/en/runtime-config.js', '/assets/main.js', '/']) {
    const headers = new Headers({'Cache-Control': 'public, max-age=86400'});
    const result = applyRuntimeConfigCacheHeaders(headers, pathname);
    assert.equal(result.get('Cache-Control'), 'public, max-age=86400');
    assert.equal(result.has('CDN-Cache-Control'), false);
  }
});
