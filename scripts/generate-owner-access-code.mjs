// Run locally only: node scripts/generate-owner-access-code.mjs
// Generates a high-entropy owner code and salted verifier without publishing secrets.
import { pbkdf2Sync, randomBytes } from "node:crypto";

const accessCode = randomBytes(24).toString("base64url");
const salt = randomBytes(24);
const verifier = pbkdf2Sync(accessCode, salt, 25_000, 32, "sha256");

process.stdout.write(
  "\nPRIVATE OWNER ACCESS CODE (store in password manager; never commit):\n" +
  accessCode + "\n\n" +
  "Cloudflare Worker secrets (paste only these derived values):\n" +
  "VYNALTH_TEMP_ACCESS_CODE_SALT_HEX=" + salt.toString("hex") + "\n" +
  "VYNALTH_TEMP_ACCESS_CODE_VERIFIER_HEX=" + verifier.toString("hex") + "\n\n" +
  "Finally, enable VYNALTH_OWNER_SCHOOL_EXEMPT_ENABLED=true in the Worker " +
  "only after the reviewed patch is deployed.\n"
);
