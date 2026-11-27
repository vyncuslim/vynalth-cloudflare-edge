// Local or CI validation only. Never imports or deploys unreviewed indicators.
import {readFile,writeFile} from "node:fs/promises";
import {verifyIntelEnvelope} from "../src/vwaf-intel.js";
const [file,output]=process.argv.slice(2);
if(!file||!output||!process.env.VWAF_INTEL_PUBLIC_KEY||!/^\d+$/.test(process.env.VWAF_INTEL_MIN_SEQUENCE||"")){
 console.error("Missing approved input or trust anchor.");process.exit(2);
}
try{
 const data=await readFile(file);if(data.byteLength>100000)throw Error("Oversized input");
 const manifest=await verifyIntelEnvelope(JSON.parse(data.toString("utf8")),process.env.VWAF_INTEL_PUBLIC_KEY,Number(process.env.VWAF_INTEL_MIN_SEQUENCE));
 // Do not print indicators to CI logs; publish a reviewed artifact separately.
 await writeFile(output,JSON.stringify(manifest,null,2),{mode:0o600});
 console.log(JSON.stringify({verified:true,sequence:manifest.sequence,indicators:manifest.indicators.length,expiresAt:manifest.expiresAt}));
}catch{console.error("Intelligence verification rejected.");process.exit(1)}
