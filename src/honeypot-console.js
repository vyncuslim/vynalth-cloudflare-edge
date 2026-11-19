/**
 * Static, fictional interface fixtures. NO access to origin, filesystem,
 * database, credentials, cookies, or remote command execution.
 */
const VIEWS = [
  ["overview","Overview"],["files","File Manager"],["terminal","Terminal"],
  ["database","Database"],["services","Services"],["activity","Sessions"],
];
export const HONEY_UI_CSS = [
  ".honey-shell{border:1px solid #d6dfeb;background:#fff;padding:18px;margin:18px 0;box-shadow:0 3px 13px #1c29400c}",
  ".honey-shell [hidden]{display:none!important}",
  ".honey-shell .honey-nav{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid #dce3ec;padding-bottom:13px}",
  ".honey-shell button{width:auto;cursor:pointer;margin:0;padding:9px 13px;background:#e8eef6;color:#324563;border:1px solid #ccd8e5}",
  ".honey-shell button:hover,.honey-shell button:focus-visible{background:#d6e3f2;outline:2px solid #3564a1;outline-offset:1px}",
  ".honey-shell button.chosen,.honey-shell button[type=submit]{background:#3b6091;color:white;border-color:#3b6091}",
  ".honey-shell input,.honey-shell textarea{display:block;width:100%;background:#fff;color:#263b57;border:1px solid #c1cede;padding:9px;max-width:100%}",
  ".honey-shell .honey-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(125px,1fr));gap:10px;margin-top:12px}",
  ".honey-shell .honey-tile{padding:13px;background:#f2f6fb;border:1px solid #e1e6ef;border-radius:5px}",
  ".honey-shell .honey-tile b{display:block;color:#224a76;font-size:1.15rem}",
  ".honey-shell .honey-panel{padding:16px 0 0}",
  ".honey-shell .honey-actions{display:flex;flex-wrap:wrap;gap:7px;margin:12px 0}",
  ".honey-shell .honey-editor{min-height:130px;font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.85rem}",
  ".honey-shell pre{white-space:pre-wrap;word-break:break-word;background:#151f31;color:#dce9e9;padding:15px;max-height:350px;overflow:auto;border-radius:5px;font:13px/1.6 ui-monospace,Consolas,monospace}",
  ".honey-shell .honey-row{display:flex;justify-content:space-between;align-items:center;gap:8px;border-bottom:1px solid #edf0f4;padding:10px 0}",
  ".honey-shell .honey-row button{min-width:86px}",
  ".honey-shell .honey-login{max-width:470px;margin:8px auto;padding:22px;border:1px solid #dbe3ed;border-radius:6px}",
  ".honey-shell .honey-login label{display:block;margin:12px 0 4px;font-weight:600;font-size:.89rem}",
  ".honey-shell .honey-note{color:#67758a;font-size:.84rem;margin:10px 0}",
  ".honey-shell ol{padding-left:24px;max-height:250px;overflow:auto}",
].join("");

function viewButton(id,label) {
  return '<button type="button" role="tab" aria-selected="false" data-honey-view="'+id+'">'+label+'</button>';
}
function serviceRow(name) {
  return '<div class="honey-row" data-honey-service-row><span>'+name+' · '+
    '<strong data-honey-service-state>Running</strong></span>'+
    '<button type="button" data-honey-service>Restart</button></div>';
}
export function interactiveConsoleHTML(kind) {
  const login = kind === "login";
  const loginForm = login
    ? '<div class="honey-login" data-honey-login><h2>Administrator Sign in</h2>'+
      '<p>Restricted management area</p>'+
      '<form data-honey-login-form autocomplete="off">'+
      '<label for="honey-account">Username</label>'+
      '<input id="honey-account" type="text" maxlength="64" autocomplete="off" required>'+
      '<label for="honey-password">Password</label>'+
      '<input id="honey-password" type="password" maxlength="128" autocomplete="off" required>'+
      '<div class="honey-actions"><button type="submit">Sign in</button></div>'+
      '</form><p data-honey-login-status class="honey-note">Secure sign-in gateway</p></div>'
    : '';
  return [
    '<section class="honey-shell" data-honey-root data-honey-mode="',kind,'">',
    loginForm,
    '<div data-honey-workspace', login ? ' hidden' : '', '>',
    '<div class="honey-nav" role="tablist" aria-label="System management">',
    ...VIEWS.map(([id,label])=>viewButton(id,label)),
    '</div>',
    '<div class="honey-panel" data-honey-panel="overview"><h2>System Dashboard</h2>',
    '<div class="honey-grid">',
    '<div class="honey-tile"><small>Host</small><b>app-gateway</b></div>',
    '<div class="honey-tile"><small>CPU</small><b>14%</b></div>',
    '<div class="honey-tile"><small>RAM</small><b>1.8 / 8 GB</b></div>',
    '<div class="honey-tile"><small>Storage</small><b>30% used</b></div>',
    '<div class="honey-tile"><small>Services</small><b>4 online</b></div>',
    '</div><p class="honey-note">System tasks ready.</p></div>',
    '<div class="honey-panel" data-honey-panel="files" hidden><h2>File Manager</h2>',
    '<p>Current directory: /var/www/html</p><div class="honey-actions">',
    ...["index.php","config.php","composer.json","access.log",".env.example"].map(x=>
      '<button type="button" data-honey-file="'+x+'">'+x+'</button>'),
    '</div><p>Editing: <strong data-honey-filename>No file selected</strong></p>',
    '<textarea class="honey-editor" data-honey-editor spellcheck="false" maxlength="1600" aria-label="File editor"></textarea>',
    '<div class="honey-actions"><button type="button" data-honey-save>Save changes</button>',
    '<span data-honey-feedback aria-live="polite"></span></div></div>',
    '<div class="honey-panel" data-honey-panel="terminal" hidden><h2>Terminal</h2>',
    '<pre data-honey-output>Connected to app-gateway\\nLast login: system console\\n$ help</pre>',
    '<form data-honey-terminal-form autocomplete="off">',
    '<label for="honey-command">Command</label><input id="honey-command" data-honey-command autocomplete="off" maxlength="120">',
    '<div class="honey-actions"><button type="submit">Run</button></div></form></div>',
    '<div class="honey-panel" data-honey-panel="database" hidden><h2>Database Administration</h2>',
    '<p>MySQL · app_core</p><form data-honey-sql-form autocomplete="off">',
    '<label for="honey-sql">SQL query</label>',
    '<textarea class="honey-editor" id="honey-sql" data-honey-sql maxlength="180" spellcheck="false">SHOW DATABASES;</textarea>',
    '<div class="honey-actions"><button type="submit">Execute</button></div></form>',
    '<pre data-honey-sql-output>Database connection established.</pre></div>',
    '<div class="honey-panel" data-honey-panel="services" hidden><h2>Service Manager</h2>',
    serviceRow("nginx"),serviceRow("php-fpm"),serviceRow("mysql"),serviceRow("redis"),
    '<h2>Backups</h2><div class="honey-row">',
    '<span>daily-2024-11-21.tar.gz · Completed</span>',
    '<button type="button" data-honey-restore>Restore</button></div>',
    '<p class="honey-note" data-honey-backup aria-live="polite"></p></div>',
    '<div class="honey-panel" data-honey-panel="activity" hidden><h2>Session Activity</h2>',
    '<p class="honey-note">Current browser session</p><ol data-honey-events></ol></div>',
    '</div></section>',
  ].join("");
}
