// The Workspace gate checks legitimate browser request provenance. Keep
// navigation proofs, paths and query strings out of referrers everywhere.
export function documentReferrerPolicy(url, status) {
  return status === 200 && url.hostname === 'vynalthai.com' &&
    /^\/(?:(?:en|cn|ms)\/)?lab-node-1401-VL(?:\/|$)/i.test(url.pathname)
    ? 'strict-origin' : 'no-referrer';
}
