/**
 * Private Cloudflare SQLite-backed Durable Object for V2 sensor intake.
 * No network or TiDB credentials in this class. Binding is internal-only.
 */
import { DurableObject } from "cloudflare:workers";
import { initializeLedger,claimEvent,settleEvent } from "./sensor-replay-ledger-core.js";

const HEADERS={
  "Content-Type":"application/json","Cache-Control":"no-store",
  "X-Content-Type-Options":"nosniff"
};
const response=(status,outcome)=>new Response(JSON.stringify({outcome}),
    {status,headers:HEADERS});

export class SensorReplayLedger extends DurableObject {
  constructor(ctx,env){
    super(ctx,env);
    this.sql=ctx.storage.sql;
    initializeLedger(this.sql);
  }
  async fetch(request){
    if(request.method!=="POST")return response(405,"method");
    const path=new URL(request.url).pathname;
    if(path!=="/claim"&&path!=="/settle")return response(404,"path");
    if(request.headers.get("content-type")!=="application/json")
      return response(415,"content_type");
    if(Number(request.headers.get("content-length")||"0")>256)
      return response(413,"oversized");
    let obj;
    try{
      const raw=await request.text();
      if(raw.length>256)return response(413,"oversized");
      obj=JSON.parse(raw);
    }catch{return response(400,"invalid");}
    if(!obj||typeof obj!=="object"||Array.isArray(obj))
      return response(400,"invalid");
    try{
      if(path==="/claim"){
        if(Object.keys(obj).sort().join(",")!=="eventRef,nowMs")
          return response(400,"fields");
        const outcome=claimEvent(this.sql,obj.eventRef,obj.nowMs);
        if(outcome==="claimed")return response(201,outcome);
        if(outcome==="duplicate")return response(409,outcome);
        if(outcome==="capacity")return response(503,outcome);
        return response(400,"invalid");
      }
      if(Object.keys(obj).sort().join(",")!=="eventRef,state")
        return response(400,"fields");
      return settleEvent(this.sql,obj.eventRef,obj.state)
        ?response(200,"settled"):response(409,"not_reserved");
    }catch{return response(503,"ledger_unavailable");}
  }
}
