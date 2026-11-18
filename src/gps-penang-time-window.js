/**
 * Penang GPS challenge hours: 05:00 inclusive to 20:50 exclusive,
 * every day in Malaysian Standard Time (MYT, UTC+08:00, no DST).
 *
 * Use the Worker clock, never a client-controlled timezone/header.
 * Invalid clock input conservatively keeps GPS verification enabled.
 */
export function isPenangGpsWindow(epochMs = Date.now()) {
  const instant = Number(epochMs);
  if (!Number.isFinite(instant)) return true;
  const myt = new Date(instant + 8 * 60 * 60 * 1000);
  const hour = myt.getUTCHours();
  const minute = myt.getUTCMinutes();
  if (!Number.isFinite(hour) || !Number.isFinite(minute)) return true;
  const minutesSinceMidnight = hour * 60 + minute;
  return minutesSinceMidnight >= 5 * 60 &&
    minutesSinceMidnight < 20 * 60 + 50;
}
