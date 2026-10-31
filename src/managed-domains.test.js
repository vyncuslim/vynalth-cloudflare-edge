import test from 'node:test';
import assert from 'node:assert/strict';
import edge from './index.js';
import { MANAGED_ROOT_DOMAINS, getRootDomain } from './managed-domains.js';

const ROOTS = [
  'vynalthai.com','vynalthai.si','vyncuslim.com','vyncuslim.si',
  'vyncuslim.my','sleepsomno.com','vitamindai.online',
  'powiismunc.com','vynli.xyz','vynlink.xyz','zokivo.xyz'
];

test('all 11 explicitly authorized managed roots and child hosts are recognized', () => {
  assert.deepEqual([...MANAGED_ROOT_DOMAINS].sort(), [...ROOTS].sort());
  for (const root of ROOTS) {
    assert.equal(getRootDomain(root), root);
    assert.equal(getRootDomain('www.' + root), root);
    assert.equal(getRootDomain('assets.eu.' + root), root);
    assert.equal(getRootDomain(root.toUpperCase()), root);
  }
  for(const host of ['attacker.example','notvynlink.xyz','vynli.xyz.attacker.test',
    'vyncuslim.my.evil.example','a..vynlink.xyz','x.zokivo.xyz.invalid','']) {
    assert.equal(getRootDomain(host), null, host);
  }
});

test('all 11 domains reach their original host-specific origin without rewriting DNS or Host', async () => {
  const originalFetch = globalThis.fetch;
  const origins = [];
  globalThis.fetch = async request => {
    const url = new URL(request.url);
    origins.push(url.hostname);
    return new Response('origin:'+url.hostname, {status:200});
  };
  try {
    for (const root of ROOTS) {
      for (const host of [root, 'www.'+root]) {
        const request = new Request('https://' + host + '/robots.txt',{
          method:'GET',headers:{Accept:'text/plain'}
        });
        const response = await edge.fetch(request, {GPS_GATE_ENABLED:'false'}, {});
        assert.equal(response.status, 200, host);
        assert.equal(await response.text(), 'origin:'+host);
        assert.equal(response.headers.get('x-vynalth-zone'), root);
        assert.equal(response.headers.get('x-vynalth-edge'), 'cloudflare-worker');
      }
    }
    assert.equal(origins.length, ROOTS.length*2);
  } finally {globalThis.fetch=originalFetch}
});
