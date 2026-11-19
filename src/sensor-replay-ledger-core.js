/**
 * SQLite-backed at-most-once event claim core for honeypot intake V2.
 * Bounded to 20,000 HMAC-keyed event references per ledger.
 * No IP, request body, username, command, credential or binary stored.
 * A claim precedes TiDB I/O: prevents duplicate event dispatch, but a crash
 * between claim and TiDB is NOT recoverable without operator reconciliation.
 */
export const SENSOR_LEDGER_CAP=20000;
const REF_RE=/^[a-f0-9]{64}$/;
const STATES=new Set(["sampled_out","insert_acknowledged","database_uncertain"]);

export function initializeLedger(sql){
  sql.exec("CREATE TABLE IF NOT EXISTS sensor_claims ("+
    "event_ref TEXT PRIMARY KEY NOT NULL,"+
    "claimed_ms INTEGER NOT NULL,"+
    "state TEXT NOT NULL DEFAULT 'reserved' "+
    "CHECK(state IN ('reserved','sampled_out','insert_acknowledged','database_uncertain')))");
}
export function claimEvent(sql,eventRef,nowMs){
  if(typeof eventRef!=="string"||!REF_RE.test(eventRef)||
     !Number.isSafeInteger(nowMs)||nowMs<=0)return "invalid";
  const old=sql.exec("SELECT event_ref FROM sensor_claims WHERE event_ref=?",
      eventRef).toArray();
  if(old.length)return "duplicate";
  const count=sql.exec("SELECT COUNT(*) AS total FROM sensor_claims").one().total;
  if(count>=SENSOR_LEDGER_CAP)return "capacity";
  const inserted=sql.exec(
      "INSERT OR IGNORE INTO sensor_claims(event_ref,claimed_ms,state) "+
      "VALUES (?,?,'reserved')",eventRef,nowMs);
  return inserted.rowsWritten===1?"claimed":"duplicate";
}
export function settleEvent(sql,eventRef,state){
  if(typeof eventRef!=="string"||!REF_RE.test(eventRef)||
     !STATES.has(state))return false;
  const row=sql.exec(
      "UPDATE sensor_claims SET state=? WHERE event_ref=? AND state='reserved'",
      state,eventRef);
  return row.rowsWritten===1;
}
