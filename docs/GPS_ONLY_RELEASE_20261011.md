# Vynalth AI GPS gate — proposed production activation 2026-10-11

This scoped release changes only the GPS code, tests, map data, and Wrangler/route preflight; it does not enable Consent, SSO or School Egress IP blocking.

- Requested by website operator: GPS enabled, OSM approximate candidate boundaries for POWIIS Balik Pulau and Tanjung Bungah (not surveyed).
- Enable: GPS_GATE_ENABLED=true, GPS_POLYGON_MODE=enforce, both explicit release approvals=true.
- Block confidently INSIDE with 403; unknown permission on covered HTML and JSON 403/challenge with retry; OUTSIDE 15-minute cookie.
- Boundary zone: within browser accuracy plus 30 metres of any polygon edge, grant short 5-minute nearby cookie without claiming OFF-CAMPUS status. Protected private photos still require true outside or trusted signed status.
- GPS may be spoofed and should never be used as identity proof; accuracy radius is browser-reported.
- Required outside GitHub: provision a strong `GPS_GATE_SESSION_SECRET` of at least 32 characters in the traffic-serving Cloudflare Worker. Optional `GPS_ACCOUNT_STATUS_SECRET` for server-authorized trust/contact/status exemptions.
- Because GPS_CONFIG_ERROR_ACTION=bypass is set to preserve site availability, missing/invalid config disables GPS checks and raises GPS_GATE_CONFIGURATION_UNAVAILABLE in Worker logs. A source-level flag of true does NOT confirm enforcement is live.
- If the Cloudflare deploy fails or production status reports configurationAvailable=false, fix bindings/secret and redeploy, or rollback to previous Worker version. Do not claim live GPS 403 before observing same-host /__shield/gps/status enabled=true and verifying consent, 403, nearby access and outside access.
- Not all domain apexes are covered by this Worker; verify route ownership.
- Keep recovery/legal/privacy/trust paths accessible and perform a browser-based acceptance of permission denial.
- Source geometry: © OpenStreetMap contributors, ODbL 1.0, way 808258869 and 790940312. This is NOT a legal or certified perimeter.
