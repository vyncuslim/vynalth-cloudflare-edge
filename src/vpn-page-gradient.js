/*
 * VPN full-canvas brand theme, restricted to vpn.page.vynalthai.com HTML GETs.
 * No API, installer, download, status, WAF, authentication, or origin changes.
 * The site remains entirely on its original Vercel deployment.
 */

export const VPN_BRAND_HOST = "vpn.page.vynalthai.com";

export function isVpnBrandDocument(request, url, response) {
  return (
    url?.hostname?.toLowerCase() === VPN_BRAND_HOST &&
    request?.method === "GET" &&
    response?.status === 200 &&
    /(?:^|\s|;)text\/html(?:\s*;|\s*$)/i.test(response.headers.get("content-type") || "")
  );
}

const VPN_BRAND_CSS = `
/* New-cohort theme: full-page ocean blue -> warm porcelain; legacy remains intact. */
html[data-vyn-gradient="new"] {
  --vpn-brand-from:#0E61AC;
  --vpn-brand-to:#FAF2E0;
  --vpn-brand-gradient:linear-gradient(125deg,#0E61AC 0%,#6CA8C8 31%,#C7D9D0 62%,#FAF2E0 100%);
  --ink:#172F43;
  --muted:#405B68;
  --blue:#0E61AC;
  --blue-deep:#174B77;
  --line:#A9C4C9;
  --surface:rgba(255,254,250,.88);
  --pale:#DFECE9;
  --soft:#E9F1EC;
  --vpn-panel:rgba(255,253,247,.83);
  --vpn-panel-border:rgba(24,76,96,.22);
  color-scheme:light;
}
html[data-vyn-gradient="new"] body {
  background:var(--vpn-brand-gradient);
  background-attachment:fixed;
  color:#172F43;
  min-height:100vh;
}
html[data-vyn-gradient="new"] :is(.section-grid,.intro-section,.features-section,.gateway-section,.platforms-section,.download-section,.status-section,.faq-section,.outro-section,.section) {
  background:rgba(250,253,250,.66);
  border-color:var(--vpn-panel-border);
  color:#172F43;
}
html[data-vyn-gradient="new"] :is(.section-grid,.hero,.hero-layout,.gateway-layout,.outro-layout) {
  color:#172F43;
}
html[data-vyn-gradient="new"] :is(.site-header,.site-footer) {
  background:rgba(246,252,249,.89);
  color:#172F43;
  border-color:var(--vpn-panel-border);
  backdrop-filter:blur(14px);
  -webkit-backdrop-filter:blur(14px);
}
html[data-vyn-gradient="new"] :is(.brand,.brand b,.nav-links a,.footer-brand,.footer-right,.footer-right a) {
  color:#164667;
}
html[data-vyn-gradient="new"] :is(.nav-links a:hover,.footer-right a:hover,.eyebrow,.section-label,.blue-period,.text-link,.section-index) {
  color:#0E61AC;
}
html[data-vyn-gradient="new"] :is(.hero-copy,.hero-visual,.feature-card,.platform-card,.download-card,.status-list,.gateway-details,.faq-items,.faq-layout,.intro-right) {
  background:var(--vpn-panel);
  color:#172F43;
  border:1px solid var(--vpn-panel-border);
  border-radius:12px;
  box-shadow:0 5px 24px rgba(25,65,82,.09);
}
html[data-vyn-gradient="new"] .hero-copy {
  padding:clamp(20px,3.5vw,44px);
}
html[data-vyn-gradient="new"] .hero-visual {
  background:linear-gradient(130deg,rgba(235,247,245,.94),rgba(251,242,224,.94));
}
html[data-vyn-gradient="new"] :is(.feature-card,.platform-card,.download-card) {
  background:rgba(255,254,249,.86);
}
html[data-vyn-gradient="new"] :is(.feature-card h3,.platform-card h3,.download-card h3,.gateway-section h2,.outro-section h2,.hero h1,.section h2,.gateway-section h3) {
  color:#17374C;
}
html[data-vyn-gradient="new"] :is(.gateway-section .section-label,.outro-pre,.gateway-copy p,.outro-layout p,.gateway-details,.detail-row,.status-line) {
  color:#365568;
}
html[data-vyn-gradient="new"] :is(.hero-text,.hero-note,.visual-topline,.detail-caption,.availability-note,.download-caption,.download-message,.download-safety,.status-disclaimer,.status-lead,.platform-card p,.feature-card p,.footer-inner p,.site-footer p,.faq-items p) {
  color:#405B68;
}
html[data-vyn-gradient="new"] .gateway-section {
  background:rgba(241,249,249,.70);
}
html[data-vyn-gradient="new"] :is(.gateway-details,.status-list,.faq-items) {
  border-color:rgba(24,76,96,.24);
}
html[data-vyn-gradient="new"] :is(.gateway-details .detail-row,.status-line,.faq-items details) {
  border-color:rgba(24,76,96,.19);
}
html[data-vyn-gradient="new"] :is(.gateway-details strong,.gateway-details span,.detail-row strong,.status-line strong,.status-line span) {
  color:#20445A;
}
html[data-vyn-gradient="new"] .outro-section {
  background:linear-gradient(125deg,rgba(14,97,172,.22),rgba(250,242,224,.78));
}
html[data-vyn-gradient="new"] :is(.button-primary,.small-cta,.download-action,.download-card .button-primary) {
  background:#0E61AC;
  color:#fff;
  border-color:#0E61AC;
}
html[data-vyn-gradient="new"] :is(.button-primary,.small-cta,.download-action):hover {
  background:#174B77;
  color:#fff;
}
html[data-vyn-gradient="new"] :is(.button-outline,.button-light,.language-control) {
  background:rgba(255,253,247,.92);
  color:#174B77;
  border:1px solid rgba(24,76,96,.25);
}
html[data-vyn-gradient="new"] .language-button[aria-pressed="true"],
html[data-vyn-gradient="new"] .language-button[aria-current="true"] {
  background:#0E61AC;
  color:#fff;
}
html[data-vyn-gradient="new"] :is(.feature-icon,.download-device-icon,.server-icon,.brand b,.footer-brand b) {
  color:#0E61AC;
}
html[data-vyn-gradient="new"] .download-device-icon {
  background:#DCECE9;
}
html[data-vyn-gradient="new"] :is(.status-good,.tag-green) {
  color:#1E674F;
  background:#E2F2E7;
}
html[data-vyn-gradient="new"] :is(.status-pending,.tag-amber) {
  color:#805715;
  background:#FAEFD7;
}
html[data-vyn-gradient="new"] :is(button,a,summary):focus-visible {
  outline:3px solid #0E61AC;
  outline-offset:3px;
}
html[data-vyn-gradient="new"] ::selection {
  background:#9FC7D0;
  color:#172F43;
}
@media(max-width:760px) {
  html[data-vyn-gradient="new"] body {
    background-attachment:scroll;
  }
  html[data-vyn-gradient="new"] .hero-copy {
    padding:22px;
    border-radius:10px;
  }
  html[data-vyn-gradient="new"] :is(.feature-card,.platform-card,.download-card,.hero-visual) {
    border-radius:10px;
  }
}
@media(prefers-reduced-transparency:reduce) {
  html[data-vyn-gradient="new"] :is(.site-header,.site-footer,.hero-copy,.hero-visual,.feature-card,.platform-card,.download-card,.status-list) {
    background:#FFFCF5;
    backdrop-filter:none;
  }
}
`;

const COHORT_BOOTSTRAP = `(function(){
var key="vynalth-gradient-v2",variant=null,cookies=document.cookie.split(";");
for(var i=0;i<cookies.length;i++){var part=cookies[i].trim();if(part.indexOf(key+"=")===0){var c=part.slice(key.length+1);if(c==="new"||c==="old")variant=c;break;}}
if(!variant){try{var stored=localStorage.getItem(key);if(stored==="new"||stored==="old")variant=stored;}catch(e){}}
if(!variant)variant=Math.random()<0.4?"new":"old";
document.documentElement.dataset.vynGradient=variant;
try{document.cookie=key+"="+variant+"; Path=/; Domain=.vynalthai.com; Max-Age=15552000; SameSite=Lax"+(location.protocol==="https:"?"; Secure":"");localStorage.setItem(key,variant);}catch(e){}
})();`;

export const VPN_GRADIENT_HEAD =
  '<style id="vyn-vpn-full-brand-2026">' + VPN_BRAND_CSS + '</style>' +
  '<script id="vyn-vpn-40pct-cohort">' + COHORT_BOOTSTRAP + '</script>' +
  '<script defer src="https://vynalthai.com/vynalth-gradient-announcement.js"></script>';

/**
 * Apply to the original VPN HTML stream only. Other endpoints keep their
 * exact response body, cache behavior, status, content type and download bytes.
 */
export function applyVpnPageGradient(response, request, url) {
  if (!isVpnBrandDocument(request, url, response)) return response;
  if (typeof HTMLRewriter === "undefined") {
    // Node test environments cannot stream-rewrite HTML; do not alter payloads.
    return response;
  }
  return new HTMLRewriter()
    .on("head", {
      element(element) {
        element.append(VPN_GRADIENT_HEAD, { html: true });
      },
    })
    .transform(response);
}
