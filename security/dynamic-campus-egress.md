# Vynalth Shield — Automatic verified campus egress protection (staged / NOT deployed)

## Outcome
Once deployed and linked with a **trusted, owner-controlled Windows computer actually
connected to POWIIS_Student**, Vynalth Shield can update the shared Cloudflare IP List
**without requiring the owner to run curl each day**.

**This does not identify individual POWIIS members on personal/home/mobile/VPN networks.**
Public anonymous Vynalth AI access is preserved for all nonmatched public visitors. A
school NAT IP block affects *everyone* using that NAT (including school guests and owner).

### How dynamic reporting works
1. One-time task installation: `security/windows/Install-SchoolBeacon.ps1` generates a
   256-bit signing key, encrypted via DPAPI for the current Windows user, and a device ID.
   A Windows Task Scheduler task runs `Report-SchoolBeacon.ps1` every 10 minutes while
   **that user is logged in and the laptop is powered on**.
2. The reporter sends only when the Windows Wi-Fi connection has the exact SSID
   `POWIIS_Student`, is connected, and the best IPv4 default route is the Wi-Fi
   interface; aborts for known active VPN/TUN/TAP interfaces. This is a **best-effort**
   VPN guard, not proof that all tunneling is absent.
3. The reporter sends a signed body to **POST**
   `https://vynalthai.com/__shield/campus-beacon` over HTTPS, using `curl -4 --noproxy "*"`.
   The server sees the observed source IP at the **Cloudflare Worker edge**; the
   client cannot freely specify the IP to add. No personal WLAN MAC is uploaded.
4. The Cloudflare Worker verifies the HMAC-SHA256 signature, time skew (+/-180s),
   32-character random nonce, configured device ID and exact SSID, plus best-effort
   replay defense in KV. **A new IP requires two different signed observations
   separated by 5–40 minutes**. There is no automatic ASN/range expansion.
5. The Worker adds exactly that individual public IPv4 to the account-scoped
   `powiis_verified_egress` IP List using the Cloudflare API, with a 12-hour expiry
   embedded in `POWIIS|exp=<ISO8601>|ref=<device>`.
   Existing owner-managed matching entries are renewed when needed. Asynchronous
   Cloudflare write completion and list readback are checked.
6. Five zone-level WAF rules can share the same list.
   **Exact WAF expression (after beacon is active):**

   ```text
   ip.src in $powiis_verified_egress and not (http.host eq "vynalthai.com" and http.request.uri.path eq "/__shield/campus-beacon")
   ```

   The only school-IP exception is the narrow authenticated reporter endpoint;
   all other normal URLs remain blocked for the listed egress IP.
7. The **separate** hourly GitHub Actions workflow `school-egress-expiry.yml`
   must be deployed to the default branch, enabled, given Cloudflare list secrets,
   and verified with a real run to remove previously verified IPs after expiry.
   Comment timestamps alone DO NOT expire Cloudflare IP List membership.

## Mandatory first-time provisioning (operator, ONCE)
1. Verify that all five intended domains are in the **same Cloudflare account** and
   orange-cloud proxied, including relevant subdomains. Origin/API endpoints not
   protected by the same Cloudflare zones require their own independently verified
   protection.
2. In that account create a dedicated IP List named **`powiis_verified_egress`**.
   Obtain its Account ID and List ID from your own Cloudflare account.
3. Create a dedicated Cloudflare Workers KV namespace; bind it to the edge Worker
   as **`SCHOOL_BEACON_KV`**. Confirm the Worker has access.
4. On the computer you personally control, download both Windows scripts from
   this PR and run `Install-SchoolBeacon.ps1` **once** in Windows PowerShell
   while logged into the account under which the task should run.
   It prints **`SCHOOL_BEACON_DEVICE_ID`** and a **one-time secret
   `SCHOOL_BEACON_SIGNING_KEY`**. Configure them using the **Cloudflare Worker
   secret/variable settings**, NEVER in a source file, ChatGPT, an email, or CI logs.
   On Windows, the key is saved only as DPAPI-protected data under
   `%APPDATA%\VynalthShield\school-beacon.json`.
5. Configure these additional Worker environment values:
   - `SCHOOL_BEACON_ENABLED=true` (text variable, default absent/off);
   - `SCHOOL_CF_ACCOUNT_ID` and `SCHOOL_CF_LIST_ID` (exact Cloudflare IDs);
   - `SCHOOL_CF_API_TOKEN` (secret with minimal **Account Filter Lists Read/Edit**
     scope, NOT an account global API key).
   - `SCHOOL_BEACON_DEVICE_ID` and `SCHOOL_BEACON_SIGNING_KEY` from step 4.
6. Deploy the audited edge Worker build; confirm direct `workers.dev` and
   `preview_urls` exposure are disabled. Test the signed endpoint from the trusted
   campus computer: first valid report should return
   `awaiting_independent_second_observation`; second report after >=5 minutes
   should result in `new_exact_ip_protected` after Cloudflare completion.
   The endpoint must reject any forged/unsigned report.
7. Create the five WAF rules through reviewed
   `security/setup-verified-school-waf.mjs --apply`, with verified zone-ID map
   and list already containing an approved current school IP.
   On-campus browsing should get HTTP 403, while off-campus ordinary browsing
   of the same page must continue to work. If the campus owner cannot access the
   website, they must use an **off-campus device** for rollback.
8. Put `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_IP_LIST_ID` and
   `CLOUDFLARE_API_TOKEN` into the **edge GitHub repository's Actions secrets**,
   merge the expiry workflow into the default branch, ensure it actually runs
   and verify an expired exact-IP item is removed. Otherwise automatic expiry
   is NOT operational. Keep one owner-managed off-campus recovery path.

## Operational facts / limits
- School WAN could have **several** egress IPs, some accessible only to other staff,
  guest or student network paths. A single reporter discovers only the paths it uses.
  If an unobserved IP is used by another student, they might still access the site.
- When the reporting laptop is shut down, leaves campus, switches off Wi-Fi,
  loses its session, or connects to a VPN, the reporter produces no new observations.
  Existing IPs expire after 12h + cleanup delay; changes during laptop downtime will
  not be discovered automatically. Full-coverage unattended monitoring requires
  an authorized always-on network-side telemetry/feed from POWIIS, which is not
  available in this task.
- As a precaution against misidentification, do not enroll addresses solely from
  `TM ASN 4788`, IP geolocation, school-like email names, or claimed device headers.
- The local Wi-Fi SSID and route checks are defense-in-depth, not independently
  trustworthy attestation. If the registered device or its key is compromised,
  disable the beacon and revoke affected entries.
- Cloudflare List operations are asynchronous with a single bulk operation
  pending per account; if another admin is editing simultaneously, operations
  may fail. The software must NOT claim success when pending/failed.
- If you cannot deploy KV bindings, the signed Worker endpoint, scheduled cleanup
  and WAF zone rules, this PR is **code only** and makes no live change.
- Exact public IPv4 reporting is implemented first, because campus tests did not
  confirm a functional IPv6 path. IPv6 needs its own verified observation pipeline.

## Simple check after deployment
- In Windows Task Scheduler: **Vynalth Shield School Egress Beacon** runs every
  10 minutes when the user is logged in.
- In Cloudflare: list membership changes and renews automatically, with audit
  in Cloudflare API logs and Worker logs (subject to plan).
- In GitHub: **School Verified Egress Expiry** runs hourly and reports removed
  expired exact entries.
- Use a campus connection and an unrelated off-campus TM/Maxis connection to
  validate 403 vs ordinary HTTP 200; don't rely solely on Worker/API logs.
