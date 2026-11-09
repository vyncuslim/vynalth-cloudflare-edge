import test from 'node:test';
import assert from 'node:assert/strict';
import { getRootDomain, MANAGED_ROOT_DOMAINS } from '../src/managed-domains.js';
import { isObservedSecurityProbe } from '../src/threat-telemetry.js';

test('all 11 managed roots and their subdomains retain edge eligibility', () => {
  assert.equal(MANAGED_ROOT_DOMAINS.length, 11);
  for (const root of MANAGED_ROOT_DOMAINS) {
    assert.equal(getRootDomain(root), root);
    assert.equal(getRootDomain('search.' + root), root);
  }
  assert.equal(getRootDomain('not-vynalthai.com'), null);
});

test('ten decoy route categories are observed without exposing credentials', () => {
  for (const name of ['console','api','environment','database','storage',
    'deployments','debug','identity','health','backups']) {
    const request = new Request('https://search.vynalthai.com/_system/' + name);
    assert.equal(isObservedSecurityProbe(request), true, name);
  }
  assert.equal(isObservedSecurityProbe(new Request('https://vynalthai.com/api/security/ingest')), false);
  assert.equal(isObservedSecurityProbe(new Request('https://vynalthai.com/_system/not-a-trap')), false);
});
