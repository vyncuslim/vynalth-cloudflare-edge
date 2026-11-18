import test from 'node:test';
import assert from 'node:assert/strict';
import { isPenangGpsWindow } from '../src/gps-penang-time-window.js';
import { gpsPenangOnlyDecision } from '../src/gps-penang-only.js';

const atMYT = (date, time) => Date.parse(date + 'T' + time + '+08:00');
const penangRequest = {
  cf: { country: 'MY', regionCode: 'MY-07', region: 'Penang', city: 'Butterworth' },
};
const env = {
  GPS_PENANG_ONLY_ENABLED: 'true',
  GPS_PENANG_TIME_WINDOW_ENABLED: 'true',
  GPS_PENANG_ALL_LOCALITIES_ENABLED: 'true',
};

test('MYT time window boundaries are server-time-based and include 05:00, exclude 20:50', () => {
  assert.equal(isPenangGpsWindow(atMYT('2026-11-18', '04:59:59')), false);
  assert.equal(isPenangGpsWindow(atMYT('2026-11-18', '05:00:00')), true);
  assert.equal(isPenangGpsWindow(atMYT('2026-11-18', '12:00:00')), true);
  assert.equal(isPenangGpsWindow(atMYT('2026-11-18', '20:49:59')), true);
  assert.equal(isPenangGpsWindow(atMYT('2026-11-18', '20:50:00')), false);
  assert.equal(isPenangGpsWindow(atMYT('2026-11-18', '23:59:59')), false);
  assert.equal(isPenangGpsWindow(NaN), true);
});

test('all Penang localities including Butterworth require verification during window', () => {
  for (const city of ['Butterworth', 'George Town', 'Bukit Mertajam']) {
    const request = { cf: { ...penangRequest.cf, city } };
    const decision = gpsPenangOnlyDecision(request, env, null, null, null, null,
      atMYT('2026-11-18', '12:00:00'));
    assert.equal(decision.requireGPS, true, city);
  }
});

test('Penang has no GPS prompt outside window', () => {
  assert.equal(gpsPenangOnlyDecision(penangRequest, env, null, null, null, null,
    atMYT('2026-11-18', '20:50:00')).requireGPS, false);
});

test('outside Penang and outside Malaysia have no GPS prompt during window', () => {
  for (const cf of [
    { country: 'MY', regionCode: 'MY-08', region: 'Perak', city: 'Ipoh' },
    { country: 'SG', regionCode: '', region: '', city: 'Singapore' },
  ]) {
    const r = gpsPenangOnlyDecision({ cf }, env, null, null, null, null,
      atMYT('2026-11-18', '12:00:00'));
    assert.equal(r.requireGPS, false);
  }
});

test('signed region metadata is used rather than receiving worker location', () => {
  const decision = gpsPenangOnlyDecision(
    { cf: { country: 'SG', regionCode: 'SG', region: 'Singapore', city: 'Singapore' } },
    env, 'MY', 'MY-07', 'Penang', 'Butterworth', atMYT('2026-11-18', '12:00:00'),
  );
  assert.equal(decision.requireGPS, true);
});

test('legacy operator behavior is unchanged without the new opt-in flags', () => {
  const oldEnv = { GPS_PENANG_ONLY_ENABLED: 'true' };
  assert.equal(gpsPenangOnlyDecision(penangRequest, oldEnv, null, null, null, null,
    atMYT('2026-11-18', '12:00:00')).requireGPS, false);
});
