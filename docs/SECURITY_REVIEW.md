# Review scope and promotion gates

This release is AI-authored and AI-reviewed, not independently security-audited.
Historical focused reviews and implementation tests are not an attestation for the
current source or packaged artifact. Publication is a synthetic technical preview.

Before real-data use, freeze source and dependency hashes and commission review
independent of the authors. Cover the local HTTP trust boundary; token exposure;
passphrase/key lifecycle; session expiry and revocation; migration and transaction
failure; identity selection; exact approval and sender binding; worker egress;
durable attempts; and recovery validation, stale history and key cleanup.

Use disposable synthetic stores, fake providers and bounded reproductions.
Never point a test at an existing user store. Keep detailed findings, runtime logs,
receipts and native screenshots outside Git. Publish sanitized claims and evidence
limits, not private artifacts. Fix findings, then have the exact reproductions
independently retested against the final artifact.

Native Mac tests and real-provider tests are separate evidence lanes. Broker pilots
require explicit, route-specific authorization after the relevant gates pass.
Account connection is never implied by running the demo or tests. Any pilot-driven
code or disclosure change requires review of the delta and renewed approval.
