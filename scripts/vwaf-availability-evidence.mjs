/** Conservative fixed-slot sample coverage summary. An independent monitor's
 * exported observations are input, never invented or extrapolated from uptime.
 * A sampled SLI is not proof of continuous availability between samples.
 */
export function summarizeAvailability(observations,{start,end,intervalMs=60000,checks}={}){
 if(!Number.isSafeInteger(start)||!Number.isSafeInteger(end)||end<=start||
  !Number.isSafeInteger(intervalMs)||intervalMs<1000||(end-start)%intervalMs!==0||
  !Array.isArray(checks)||!checks.length||checks.some(c=>typeof c!=="string"||!c.length)||
  new Set(checks).size!==checks.length||!Array.isArray(observations))
  throw Error("Invalid evidence window or checks");
 const slots=(end-start)/intervalMs;if(slots>1000000)throw Error("Evidence window too large");
 const expected=new Set(checks),bySlot=new Map();
 for(const row of observations){
  if(!row||!Number.isSafeInteger(row.at)||!expected.has(row.check)||typeof row.healthy!=="boolean")
   throw Error("Malformed observation");
  if(row.at<start||row.at>=end)continue;
  const index=Math.floor((row.at-start)/intervalMs);
  let bucket=bySlot.get(index);if(!bucket){bucket=new Map();bySlot.set(index,bucket)}
  // Duplicate/retry cannot mask an unhealthy sample or fill another slot.
  bucket.set(row.check,(bucket.get(row.check)??true)&&row.healthy);
 }
 let healthy=0,unhealthy=0,missing=0;
 for(let n=0;n<slots;n++){
  const bucket=bySlot.get(n);
  if(!bucket||bucket.size!==checks.length){missing++;continue}
  if([...bucket.values()].every(Boolean))healthy++;else unhealthy++;
 }
 const sampleRate=healthy/slots,complete=missing===0;
 return {schema:"vwaf-availability-sample-summary-v1",start,end,intervalMs,slots,checks:[...checks],
  healthy,unhealthy,missing,coverage:(slots-missing)/slots,conservativeSampleRate:sampleRate,
  thirtyDayWindow:end-start>=30*86400000,complete,
  sampledTargetMet:complete&&end-start>=30*86400000&&sampleRate>=0.9999,
  productionAvailabilityCertified:false,
  limitation:"Samples require independent provenance and end-to-end scope review; even complete samples do not prove uninterrupted availability."};
}
