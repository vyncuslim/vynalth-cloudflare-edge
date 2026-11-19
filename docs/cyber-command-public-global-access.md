# Cyber Command worldwide read-only GPS scope

Public Vynalth Global Cyber Command documents in English, Mandarin and Malay, along with a single fixed read-only public IPsum consensus API, should be readable without asking for browser geolocation, including inside Penang. This is a presentation/accessibility decision, not an authorization bypass.

The permit list is explicitly bounded to /cyber-command and /{en|cn|ms}/cyber-command, optionally with sections /overview, /live, /threats, /map, /infrastructure, /intel, /ips, /incidents, /methodology, and GET/HEAD /api/public/cyber-command/ip-consensus.

Only exact vynalthai.com and www.vynalthai.com hosts; only GET or HEAD. No other API, session, login, admin, third-party or device route is permitted. A request still passes Cloudflare WAF, temporary block checks, global device restrictions, School IP policy and all existing origin permission gates. A WAF challenge or network block is **not** waived by this exception.

Release verification: unit tests, Worker tests, dry-run, and observed HTTP 200 from overseas and Malaysia via independent egress probes after deployment. This change does not itself provide worldwide reachability evidence and cannot solve Cloudflare WAF rules outside Worker.

Do not alter GPS or School rules for other pages to achieve this outcome.
