import { test } from 'node:test';
import assert from 'node:assert/strict';
import { expiry } from './reconcile-school-expiry.mjs';

test('short-lived owner-approved individual IP expires', () => {
  const now=Date.now();
  const make=(when,ip='60.51.219.195')=>({
    ip,comment:'POWIIS|exp='+new Date(when).toISOString()+'|ref=approved_record_20261008'
  });
  assert.equal(expiry(make(now-1000),now)?.expired,true);
  assert.equal(expiry(make(now+1000),now)?.expired,false);
  assert.equal(expiry(make(now-1000,'60.51.0.0/16'),now),null);
  assert.equal(expiry(make(now-1000,'2606:4700::/64'),now),null);
  assert.equal(expiry({ip:'60.51.219.195',comment:'unmanaged'},now),null);
});
