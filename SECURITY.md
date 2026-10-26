# Security policy

Supported preview: **0.5.1**. Use synthetic records only.

**AI-authored and AI-reviewed; not independently security-audited.** Earlier focused
reviews do not certify this release. Real-data use, account connection and broker
sending require separate boundary review and authorization. No live removal claim
is made. See the [review scope](docs/SECURITY_REVIEW.md).

## Reporting a vulnerability

Use GitHub's private [Report a vulnerability](https://github.com/pkkeable/Velum/security/advisories/new)
form. Do not open a public issue with exploit details, personal information, keys,
request receipts or runtime files. If the private form is unavailable, do not post
sensitive material publicly; wait for the reporting route to be restored.
Use bundled fictional data for a minimal reproduction. Ordinary synthetic demo bugs
can be reported in Issues.

## Boundaries and known limitations

The [threat model](docs/THREAT_MODEL.md) defines assets, controls and non-goals;
the [validation map](docs/SECURITY_VALIDATION.md) maps bounded claims to tests.

- A valid older encrypted row or whole database can be replayed by an attacker
  with storage access. Authentication does not detect rollback. Recovery's stale-history
  gate addresses supported restore workflows, not arbitrary filesystem rollback.
- Unlock throttling is process-local and resets on restart. Scrypt (default
  n=131072, r=8, p=1, 16-byte salt) raises guessing cost; it does not make weak
  passphrases safe. Offline attacks bypass UI throttling.
- Same-user malware, browser extensions, compromised OS, swap, crash dumps and OS
  backups are outside the protection boundary. Python does not guarantee memory erasure.
- Python audit hooks constrain covered calls; they are not an OS sandbox.
- Account revocation is best effort when offline or killed. Disconnect at the
  provider if termination prevents revocation. Native failure behavior remains bounded
  by the evidence in [release validation](docs/RELEASE.md).

A reported vulnerability that undermines a stated release boundary blocks that
boundary until fixed and independently retested. Disclosure timing is coordinated
privately; there is no guaranteed response-time SLA for this preview.
