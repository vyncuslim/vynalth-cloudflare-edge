/**
 * Explicit restricted identifier policy for public API query metadata.
 * Never applied to prompt/query/text, content uploads, callbacks or redirects.
 * This is not a general SQL parser, XSS sanitizer or SSRF defense.
 */
const SQL=/\bunion\s+(?:all\s+)?select\b|['"]\s*(?:or|and)\s+[0-9]+\s*=\s*[0-9]+/i;
const SCRIPT=/<\s*script(?:\s|>|\/)/i;
const TEMPLATE=/^\s*(?:\{\{[^{}]{1,128}\}\}|\$\{[^{}]{1,128}\})\s*$/;
export function restrictedIdentifierSignal(url,method,field,value,mode){
 if(mode!=="enforce"||!["GET","HEAD"].includes(method)||
  !/^\/api\/[a-z0-9]/i.test(url.pathname)||field!=="id"||typeof value!=="string"||value.length>512)return null;
 // Preserve explicitly designated callbacks, integration relays and code tools.
 if(/^\/api\/(?:webhooks?|callbacks?|oauth|auth|sandbox(?:-runtime)?|browser-run|cloud-browser(?:-live)?|mcp|agent-email)(?:\/|$)/i.test(url.pathname))return null;
 // The new public identifier contract rejects executable syntax in an ID field,
 // but never treats ordinary free-text or an arbitrary URL as malicious.
 if(SQL.test(value)||SCRIPT.test(value)||TEMPLATE.test(value))
  return {id:"VWAF-212",category:"restricted_identifier_syntax",score:75,blocking:true};
 return null;
}
