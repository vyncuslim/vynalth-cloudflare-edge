import test from 'node:test';
import assert from 'node:assert/strict';
import { documentReferrerPolicy } from './workspace-referrer.js';
test('Workspace HTML sends only an origin, never an admin path or proof', () => {
  for (const path of ['/lab-node-1401-VL/', '/en/lab-node-1401-VL', '/cn/lab-node-1401-VL/settings?proof=synthetic', '/ms/lab-node-1401-VL'])
    assert.equal(documentReferrerPolicy(new URL('https://vynalthai.com'+path),200),'strict-origin');
});
test('all other documents, hosts, and non-successful responses keep no-referrer', () => {
  for (const url of ['https://vynalthai.com/', 'https://vynalthai.com/lab-node-1401-VL-other', 'https://search.vynalthai.com/lab-node-1401-VL/', 'https://vynalthai.com.attacker.invalid/lab-node-1401-VL/', 'https://vynalthai.com/api/admin/access-gate'])
    assert.equal(documentReferrerPolicy(new URL(url),200),'no-referrer');
  assert.equal(documentReferrerPolicy(new URL('https://vynalthai.com/lab-node-1401-VL/'),403),'no-referrer');
});
