# VWAF 2.0 GA mandatory release policy

GA publication is prohibited unless **all 17 mandatory controls are qualified**, the original synthetic acceptance regression is retained and independently labeled holdout and representative benign tests satisfy the release metrics, and production and independent audit evidence is verified for the candidate. Implementation, CI success, and point-in-time health are not interchangeable with qualification.

The machine-readable checklist is `vwaf-ga-checklist.json`. Evidence and review links must identify exact candidate, scope, results and independent reviewer where required. The checklist validates structure and does not authenticate third-party evidence. Do not set qualified based only on this document, self-generated samples or automated scan completion.

`npm run vwaf:release-gate` now includes the 17-item recorded-qualification condition in addition to existing numeric and independent evidence conditions. The latter remain null until a trustworthy evidence-verification process is implemented; the command deliberately exits nonzero today. This is an offline release-command gate, not GitHub administrative tag/release protection or a production deployment gate. RC work remains separate from GA publication.

No exceptions for failed tests, missing evidence, incomplete scope, or unsupported certification claims. Do not publish a GA tag, release, or marketing statement until every gate is satisfied.
