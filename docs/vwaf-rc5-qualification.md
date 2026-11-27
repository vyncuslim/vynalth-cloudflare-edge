# RC5 defensive inspection and release-gate clarification

- Optimize canonical path inspection using an equivalence-checked fast path and precomputed rule list. All other normalization behavior and rule ordering remain unchanged.
- Reuse the parsed URL in the already-reviewed browser navigation schema. Classify literal destination addresses across the existing bounded JSON inspection size, without broadening unknown API URL-field enforcement. This is not a DNS or egress control and does not replace origin-side authorization and destination validation.
- Preserve the original acceptance corpus, expectations, denominators and results. New differential and schema regression checks are supplementary, not a substitute for an independently labeled corpus.
- Explicitly retain unverified GA conditions for representative benign and attack samples, deployed inspection P95, and zero known unfixed critical findings. No synthetic result automatically qualifies these conditions. The release CLI remains blocked.
- Local CPU and loopback performance reports are separate from deployed inspection latency. No unframed production opt-in, external test traffic or GA publication.

CI, review and deployment verification are required for this candidate. Do not claim a numeric improvement before measuring.
