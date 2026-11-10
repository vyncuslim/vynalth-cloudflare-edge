/**
 * Fixed-path PHP scanner decoys for managed Cloudflare Worker routes.
 *
 * No PHP, credentials, filesystem, internal requests, dynamic environment
 * introspection, or reflected request/user data. All HTML is static.
 * Explicit allowlisting prevents interception of arbitrary .php routes.
 */
export const PHP_HONEYPOT_ROUTES = Object.freeze([
  ["/info.php", "php"], ["/phpinfo.php", "php"],
  ["/api/info.php", "php"], ["/api/php-info.php", "php"],
  ["/test.php", "php"], ["/testphp.php", "php"], ["/api/test.php", "php"],
  ["/debug.php", "diagnostics"], ["/diagnostics.php", "diagnostics"],
  ["/health.php", "diagnostics"], ["/api/debug.php", "diagnostics"],
  ["/admin.php", "login"], ["/administrator.php", "login"],
  ["/login.php", "login"], ["/admin/login.php", "login"], ["/wp-login.php", "login"],
  ["/phpmyadmin/index.php", "database"], ["/pma/index.php", "database"],
  ["/mysql/index.php", "database"], ["/dbadmin.php", "database"],
  ["/config.php", "config"], ["/database.php", "config"],
  ["/db.php", "config"], ["/dbconnect.php", "config"],
  ["/filemanager.php", "files"], ["/files.php", "files"],
  ["/backup.php", "backup"], ["/restore.php", "backup"],
].map(([path, kind]) => Object.freeze({ path, kind })));

const ROUTE_MAP = new Map(PHP_HONEYPOT_ROUTES.map(route => [route.path, route]));
const SECURITY_HEADERS = Object.freeze({
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "private, no-store, max-age=0",
  "X-Robots-Tag": "noindex, nofollow, noarchive",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; " +
    "script-src 'none'; img-src 'none'; connect-src 'none'; font-src 'none'; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
});

const TITLES = Object.freeze({
  php: "PHP Configuration",
  diagnostics: "Runtime Diagnostics",
  login: "Administration",
  database: "Database Administration",
  config: "Application Configuration",
  files: "File Manager",
  backup: "Backup Manager",
});

const THEMES = Object.freeze({
  php: "#7775a7", diagnostics: "#357785", login: "#365b9a",
  database: "#ce8a32", config: "#5c7391", files: "#496e86",
  backup: "#6c699e",
});

const STYLE = [
  ":root{font-family:Arial,Helvetica,sans-serif;line-height:1.48;color:#273044;background:#f1f3f7;font-synthesis:none}",
  "*{box-sizing:border-box}html{scroll-behavior:smooth}",
  "body{margin:0;padding:32px 16px}main{max-width:1030px;margin:0 auto}",
  "header{background:#fff;border:1px solid #dce1e8;border-top:5px solid var(--accent);padding:21px 26px;display:flex;justify-content:space-between;align-items:center;gap:18px;box-shadow:0 3px 14px #1c29400c}",
  "h1{font-size:clamp(1.3rem,3.5vw,1.9rem);margin:0;color:#223044}",
  "h2{font-size:1rem;margin:0 0 10px;color:#31435d}",
  "p{margin:.3rem 0;color:#657184}small{color:#64758b}",
  ".mark{font-size:1.1rem;font-weight:800;letter-spacing:.09em;color:var(--accent);border:2px solid var(--accent);padding:8px 13px;border-radius:7px}",
  ".tabs{margin:16px 0;display:flex;flex-wrap:wrap;gap:8px}",
  ".tabs span{background:#fff;border:1px solid #dce1e8;padding:8px 12px;font-size:.85rem;color:#56647b;border-radius:5px}",
  "section{background:#fff;border:1px solid #dce1e8;margin:18px 0;padding:19px 22px;box-shadow:0 2px 7px #1c294007}",
  ".tablewrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.88rem;min-width:420px}",
  "th,td{border-bottom:1px solid #e4e8ee;padding:10px 12px;text-align:left;overflow-wrap:anywhere}",
  "th{background:#eef1f8;font-weight:700;color:#39475a}",
  "tr:nth-child(even) td{background:#f8f9fc}",
  ".pill{display:inline-block;font-size:.72rem;padding:3px 9px;background:#e6f5ed;color:#237046;border-radius:15px;font-weight:700}",
  ".warn{background:#fff6e5;color:#79540f}",
  ".cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}",
  ".tile{border:1px solid #e0e5ec;border-radius:6px;padding:14px;background:#f9fbfd}",
  ".tile b{display:block;font-size:1.2rem;color:#2e476a;margin:4px 0}",
  ".authbox{max-width:440px;margin:26px auto 8px;padding:26px;border:1px solid #dce1e8;border-radius:7px;background:#fff;box-shadow:0 8px 28px #1c294019}",
  ".field{display:block;font-weight:600;font-size:.87rem;margin:14px 0 6px}",
  "input{width:100%;padding:11px 12px;border:1px solid #c9d3df;background:#f7f8fb;border-radius:5px;color:#4c5b70}",
  "button{padding:11px 16px;border:0;background:#9ba9bb;color:#fff;border-radius:5px;width:100%;margin-top:18px;font-weight:700;cursor:not-allowed}",
  "footer{text-align:center;color:#778395;font-size:.78rem;padding:18px}",
  "@media(max-width:620px){body{padding:10px}header{padding:16px}section{padding:13px}.mark{font-size:.82rem}.tabs{gap:5px}.tabs span{padding:6px 8px}table{min-width:390px}}",
].join("");

function esc(value) {
  return String(value).replace(/[&<>"']/g, ch => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;",
    '"': "&quot;", "'": "&#39;",
  })[ch]);
}
function table(headers, rows) {
  return '<div class="tablewrap"><table><thead><tr>' +
    headers.map(x => "<th scope=\"col\">" + esc(x) + "</th>").join("") +
    "</tr></thead><tbody>" +
    rows.map(row => "<tr>" + row.map(x => "<td>" + esc(x) + "</td>").join("") +
      "</tr>").join("") + "</tbody></table></div>";
}
function section(title, contents) {
  return "<section><h2>" + esc(title) + "</h2>" + contents + "</section>";
}
function renderContent(kind) {
  switch (kind) {
    case "php":
      return section("PHP Version 8.3.14", table(["Directive", "Local Value", "Master Value"], [
        ["Server API", "FPM/FastCGI", "FPM/FastCGI"],
        ["Loaded Configuration File", "/etc/php/8.3/fpm/php.ini", "/etc/php/8.3/fpm/php.ini"],
        ["display_errors", "Off", "Off"],
        ["max_execution_time", "30", "30"],
        ["memory_limit", "128M", "128M"],
        ["upload_max_filesize", "2M", "2M"],
        ["session.cookie_httponly", "On", "On"],
      ])) + section("Extensions", table(["Module", "Support"], [
        ["mysqli", "enabled"], ["pdo_mysql", "enabled"],
        ["curl", "enabled"], ["openssl", "enabled"], ["json", "enabled"],
      ]));
    case "diagnostics":
      return section("Health Checks",
        '<div class="cols">' +
        ['Application runtime', 'Cache adapter', 'Database connector', 'Queue transport']
          .map(x => '<div class="tile"><small>' + esc(x) +
            '</small><b>Operational</b><span class="pill">OK</span></div>').join("") +
        "</div>") +
        section("Environment", table(["Check", "Result"], [
          ["PHP SAPI", "fpm-fcgi"], ["Worker processes", "4"],
          ["Application cache", "Enabled"], ["Database ping", "3 ms"],
          ["Last scheduled task", "Completed"], ["Log level", "warning"],
        ]));
    case "login":
      return '<div class="authbox"><h2>Administrator Sign in</h2>' +
        '<p>Restricted management area</p>' +
        '<label class="field" for="user">Username</label>' +
        '<input id="user" type="text" autocomplete="off" placeholder="Username" disabled>' +
        '<label class="field" for="pass">Password</label>' +
        '<input id="pass" type="password" autocomplete="off" placeholder="Password" disabled>' +
        '<button type="button" disabled>Sign in</button>' +
        '<p><small>Authentication service is temporarily unavailable.</small></p></div>';
    case "database":
      return section("Server Overview", table(["Variable", "Value"], [
        ["Database server", "localhost via TCP/IP"], ["Server type", "MySQL"],
        ["Server version", "8.0.39"], ["Protocol version", "10"],
        ["Connection", "read-only"], ["Client library", "mysqlnd 8.3.14"],
      ])) + section("Databases", table(["Database", "Tables", "Status"], [
        ["app_core", "14", "available"], ["app_cache", "7", "available"],
        ["information_schema", "83", "system"], ["performance_schema", "114", "system"],
      ]));
    case "config":
      return section("Configuration", table(["Setting", "Value"], [
        ["APP_ENV", "production"], ["APP_DEBUG", "false"],
        ["CACHE_DRIVER", "file"], ["SESSION_DRIVER", "database"],
        ["DB_CONNECTION", "mysql"], ["DB_HOST", "127.0.0.1"],
        ["DB_DATABASE", "app_core"], ["DB_PASSWORD", "********"],
        ["MAIL_DRIVER", "smtp"], ["LOG_CHANNEL", "daily"],
      ])) + section("Diagnostics",
        '<p><span class="pill">Loaded</span> Configuration cached.</p>');
    case "files":
      return section("Document Root", table(["Name", "Type", "Size", "Modified"], [
        ["assets", "Directory", "—", "2024-11-21"],
        ["cache", "Directory", "—", "2024-11-21"],
        ["logs", "Directory", "—", "2024-11-21"],
        ["index.php", "PHP file", "3.2 KB", "2024-11-21"],
        ["config.php", "PHP file", "1.8 KB", "2024-11-21"],
        ["composer.json", "JSON file", "1.1 KB", "2024-11-21"],
      ])) + section("Access", '<p><span class="pill warn">Read-only</span> File operations are unavailable.</p>');
    case "backup":
      return section("Backup Jobs", table(["Snapshot", "Type", "Size", "Status"], [
        ["daily-2024-11-21", "Full", "184 MB", "Completed"],
        ["daily-2024-11-20", "Incremental", "39 MB", "Completed"],
        ["daily-2024-11-19", "Incremental", "36 MB", "Completed"],
      ])) + section("Restore",
        '<p><span class="pill warn">Unavailable</span> Restore operations require administrator authorization.</p>');
    default:
      return "";
  }
}
const PAGES = new Map(
  Object.keys(TITLES).map(kind => {
    const body = [
      "<!doctype html><html lang=\"en\"><head>",
      '<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">',
      '<meta name="robots" content="noindex,nofollow,noarchive">',
      "<title>", esc(TITLES[kind]), "</title>",
      "<style>:root{--accent:", THEMES[kind], "}", STYLE, "</style></head><body><main>",
      "<header><div><h1>", esc(TITLES[kind]), "</h1>",
      "<p>System management interface</p></div><div class=\"mark\">",
      kind === "php" ? "php" : kind === "database" ? "DB" : "SYS",
      "</div></header>",
      '<div class="tabs"><span>Overview</span><span>Configuration</span><span>Diagnostics</span></div>',
      renderContent(kind),
      "<footer>System information</footer></main></body></html>",
    ].join("");
    return [kind, body];
  })
);

function normalize(path) {
  if (typeof path !== "string" || path.length > 192) return null;
  let value;
  try { value = decodeURIComponent(path); } catch { return null; }
  // No arbitrary or double-decoded paths. Only exact configured routes match.
  value = value.replace(/\\/g, "/").replace(/\/{2,}/g, "/").toLowerCase();
  if (value.endsWith("/") && value.length > 1) value = value.slice(0, -1);
  return value;
}

export function matchPhpHoneypot(path) {
  const normalized = normalize(path);
  return normalized ? (ROUTE_MAP.get(normalized) || null) : null;
}
export function isPhpHoneypotPath(path) {
  return Boolean(matchPhpHoneypot(path));
}
export function handlePhpHoneypot(request, url) {
  if (!request || !url) return null;
  const match = matchPhpHoneypot(url.pathname);
  if (!match) return null;
  const method = request.method.toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    return new Response(null, {
      status: 405, headers: { ...SECURITY_HEADERS, Allow: "GET, HEAD" },
    });
  }
  return new Response(method === "HEAD" ? null : PAGES.get(match.kind), {
    status: 200, headers: SECURITY_HEADERS,
  });
}
