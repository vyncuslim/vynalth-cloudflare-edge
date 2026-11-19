/**
 * CI-ONLY LOCAL WORKER. Uses the ACTUAL private SensorReplayLedger Durable
 * Object class and SQLite, but has NO TiDB, token or network bindings.
 * Never deploy this harness to a public hostname.
 */
export { SensorReplayLedger } from "./sensor-replay-ledger.js";
const HEX64=/^[a-f0-9]{64}$/;
export default {
  async fetch(request, env) {
    const url=new URL(request.url);
    const headers={"Content-Type":"application/json","Cache-Control":"no-store"};
    if(request.method!=="POST"||!["/claim","/settle"].includes(url.pathname)){
      return new Response('{"outcome":"not_found"}',{status:404,headers});
    }
    if(request.headers.get("content-type")!=="application/json"){
      return new Response('{"outcome":"bad_content_type"}',{status:415,headers});
    }
    let body;
    try{
      const raw=await request.text();
      if(raw.length>256) return new Response('{"outcome":"oversized"}',{status:413,headers});
      body=JSON.parse(raw);
    }catch{
      return new Response('{"outcome":"bad_json"}',{status:400,headers});
    }
    if(!body||typeof body!=="object"||Array.isArray(body)||
       !HEX64.test(body.eventRef)){
      return new Response('{"outcome":"invalid_ref"}',{status:400,headers});
    }
    // The EXACT shard-name construction used by sensor-ingest-v2.js.
    const id=env.SENSOR_REPLAY_LEDGER.idFromName(
      "vynalth-protocol-sensor-ledger-v2-"+body.eventRef[0]);
    const stub=env.SENSOR_REPLAY_LEDGER.get(id);
    return stub.fetch(new Request("https://local.test/"+url.pathname.slice(1),{
      method:"POST",headers:{"Content-Type":"application/json"},
      body:JSON.stringify(body)
    }));
  }
};
