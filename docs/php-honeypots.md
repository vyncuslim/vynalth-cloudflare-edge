# PHP decoy suite – Cloudflare edge

Adds **28 explicitly allowlisted scanner-facing PHP paths**, alongside the existing
/api/phpinfo.php decoy. No host DNS/Worker routing is added; a route
works only when its hostname already passes through the owned shared Worker.

| Profile | Paths |
| --- | --- |
| PHP environment | /info.php, /phpinfo.php, /api/info.php, /api/php-info.php, /test.php, /testphp.php, /api/test.php |
| Diagnostics | /debug.php, /diagnostics.php, /health.php, /api/debug.php |
| Administrator sign-in | /admin.php, /administrator.php, /login.php, /admin/login.php, /wp-login.php |
| Database overview | /phpmyadmin/index.php, /pma/index.php, /mysql/index.php, /dbadmin.php |
| Configuration | /config.php, /database.php, /db.php, /dbconnect.php |
| File browser | /filemanager.php, /files.php |
| Backups | /backup.php, /restore.php |

## Isolation contract

- All displayed data, versions, file listings, database metadata and statuses are
  **fictional fixtures**. Not a live backend configuration. PHP does not execute.
- Different page types use dedicated visual profiles. Login inputs are disabled,
  with **no HTML form**, JavaScript, network calls, authentication handling, or
  collection of submitted credentials. Other methods return 405.
- Exact-path allowlist only: other .php routes are **not** intercepted.
  URL queries are ignored; no query values, bodies, cookies, headers, IP or
  GPS are reflected into the HTML.
- CSP prohibits scripts, forms, network connections, external fonts/images and
  framing. Responses are no-store and noindex.
- Every handled request emits a privacy-bounded HONEYPOT_TRIGGER
  console event (fixed profile, hostname, method, status, request ID), plus
  the existing Telegram SUSPICIOUS_PROBE alert logic, and
  best-effort signed service telemetry if secrets are configured.
- Telemetry event source is honeypot, and path is the
  exact static allowlisted canonical path, never an attacker-supplied path.
- Cloudflare upstream WAF rules still apply. A preblocked request does not
  reach this Worker and is not counted by its internal telemetry.
- This is a **scanner detection / deception** mechanism, not proof of compromise
  or an automatic reason to permanently block an IP.

## Verification and rollout

1. npm test and wrangler deploy --dry-run.
2. Inspect Cloudflare Workers Builds production deployment for the matching commit.
3. Safely check GET /info.php, GET /admin.php, GET /phpmyadmin/index.php,
   HEAD /backup.php and POST /admin.php on an owned routed domain.
4. Validate status, CSP, and HONEYPOT_TRIGGER console event.
5. Confirm actual Telegram acknowledgment and telemetry ingestion independently.
6. Roll back the commit if a genuine application PHP endpoint overlaps the allowlist.

The existing /wp-admin/install.php remains intentionally **403 blocked**, not a decoy.
