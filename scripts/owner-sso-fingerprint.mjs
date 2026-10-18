// Compute the configuration value from a verified, immutable SSO "sub".
// Example: node scripts/owner-sso-fingerprint.mjs "the-sub-from-your-auth-backend"
// Never use an email, display name, IP address or a browser-supplied claim.
import { createHash } from "node:crypto";

const subject=process.argv[2];
if(typeof subject!=="string"||!/^[a-zA-Z0-9:_-]{8,128}$/.test(subject)){
 process.stderr.write("Usage: node scripts/owner-sso-fingerprint.mjs <verified-server-side-user-id>\n");
 process.exitCode=1;
}else{
 const digest=createHash("sha256")
   .update("vynalth-owner-subject-v1:"+subject).digest("hex");
 process.stdout.write("VYNALTH_OWNER_SSO_SUBJECT_SHA256="+digest+"\n");
}
