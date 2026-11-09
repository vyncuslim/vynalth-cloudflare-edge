# Penang-only GPS trigger and signed Service Binding v2

## Intended visitor experience

- All of Penang STATE (including Butterworth, Seberang Perai and Penang island) triggers the consent gate when trusted Cloudflare IP metadata identifies country `MY` and state `Penang / Pulau Pinang / 07 / MY-07`. City and coarse IP coordinates are not needed.
- Other Malaysian states, other countries, and unknown state/country skip this **optional** GPS middleware, without bypassing School IP Policy, Cloudflare WAF, private content authorization or app authentication.
- Contradictory state name and code are treated as uncertain, not as proof of Penang.
- This is a **best-effort IP regional filter**; it cannot reliably detect VPN endpoints or confirm someone's actual physical position. A Penang user whose IP resolves to another state can enter without a GPS prompt. If requiring actual geographic enforcement, explicit consent-based GPS for all relevant users would be necessary and would conflict with this UX requirement.
- Users whose non-Penang location is falsely labeled Penang can complete an explicit GPS check; a confirmed OUTSIDE session is signed and reused for 15 minutes. A denial/accuracy failure is not proof the person is in Penang, so support recovery remains important.

## Versioned Service Binding source attestation

The receiving edge Worker now verifies `gps-service-v2` HMAC signed with the existing `GPS_SERVICE_AUTH_SECRET`, covering:
`version, timestamp, method, full URL, source IP, country, regionCode, region`.

Use `src/gps-service-client.js` in the *originating Worker that receives the real visitor request*, before forwarding to the private policy-only Service Binding. It sources state **exclusively from the Cloudflare-provided original `request.cf` object**. Keep the secret only in Worker secrets; never browser JS or repo commits.

Example **for the calling Worker** (adapt the actual binding name):
```js
import { createSignedGpsPolicyRequest } from "./gps-service-client.js";
export default {
  async fetch(request, env) {
    // Handle only the intended policy-bound route; preserve your existing
    // full auth, origin proxy and error-handling code.
    const signed = await createSignedGpsPolicyRequest(request, env);
    const result = await env.VYNALTH_GPS_POLICY.fetch(signed);
    return result;
  }
};
```
The example is **not** a replacement for the existing calling Worker. Actual integration must happen in that Worker's source and deployment environment. The reference client's `VYNALTH_GPS_POLICY` name is an example only; the current live binding name is not verified here.

The receiver strips all signed service headers after verification; no user-controlled value can forge a verified state without the shared secret. The existing authenticated v1 country-only protocol is still accepted for compatibility, but it intentionally provides **no region assertion**. For a Malaysian v1 service call, the optional GPS prompt is therefore skipped rather than claiming the visitor is in Penang. To apply Penang-state gating through a Service Binding, the originating Worker must send verified v2 signed state metadata. **Do not treat this as a fully finished production migration until the upstream calling Worker is verified to emit v2.**

## Validation

- GitHub `npm test` includes Penang/non-Penang selection, v1 compatibility, signed v2 service hop, forgery, IP/country changes, and GPS/geofence regression checks.
- Test a physical, non-Playground Cloudflare edge route: the Cloudflare dashboard Playground does not provide real `request.cf` metadata.
- Verify signed v2 via the *calling* Worker and production region/country metadata, not just receiver unit tests.
- Cloudflare Workers Builds on `main` may automatically deploy this edge Worker. A merged commit does not prove that the separate calling Worker was upgraded or that live Cloudflare routes are active.

## Campus classification and uncertainty

- Verified browser GPS confidently OUTSIDE all configured campus polygons: allow with a short signed pass.
- Browser GPS confidently INSIDE a configured campus: HTTP 403, CAMPUS_RESTRICTED.
- Reported GPS uncertainty overlapping a campus polygon/buffer: retryable 403, never a temporary allow pass in Penang-state mode. Retry with a more accurate reading or request manual review.
- Cloudflare IP region is only a prompt trigger, not proof of the user's real location. A VPN or mobile IP may be misclassified.
- Existing campus polygons were taken from OSM community mapping and are not official certified surveys; this is a site-defined access decision, not an assertion that somebody attends a school.
- Existing guest /c and public asset exemptions, authenticated SSO policy, WAF, and School IP policy remain independent.
