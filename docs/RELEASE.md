# Release 0.5.2

This is a **synthetic technical preview**, not an approval for personal-data use.
Version consistency does not establish security or live broker capability. The
[scope](PRODUCT_SCOPE.md), [coverage](COVERAGE.md), [recovery limits](RECOVERY.md)
and [review gates](SECURITY_REVIEW.md) describe the supported boundary.

The build backend remains pinned to setuptools 84.1.0, which fixes
[GHSA-xmj3-9gf7-h52w](https://github.com/advisories/GHSA-xmj3-9gf7-h52w),
a legacy Windows wheel-installation path issue. This patch updates reviewer
documentation, release metadata and repository scanner checks; application
behavior and the synthetic boundary are unchanged.

## Reproduce the artifacts

Use Python 3.12, Git and a clean checkout of the release tag. Build in disposable
source copies outside the checkout so generated metadata cannot enter the public tree.
The backend and build dependencies are pinned with hashes. Set a fixed timestamp;
wheel reproducibility is claimed for this documented toolchain, not arbitrary versions.

```sh
VELUM_BUILD=$(mktemp -d /tmp/velum-build.XXXXXX)
python3.12 -m venv "$VELUM_BUILD/env"
"$VELUM_BUILD/env/bin/python" -m pip install --require-hashes --only-binary=:all: -r requirements-build.lock
mkdir "$VELUM_BUILD/source" "$VELUM_BUILD/dist"
git archive HEAD | tar -x -C "$VELUM_BUILD/source"
export SOURCE_DATE_EPOCH=1792972800
"$VELUM_BUILD/env/bin/python" -m build --no-isolation --outdir "$VELUM_BUILD/dist" "$VELUM_BUILD/source"
python3 -m scripts.check_distribution "$VELUM_BUILD/dist/privacy_cleanup_local-0.5.2-py3-none-any.whl"
python3 -m scripts.check_installed "$VELUM_BUILD/dist/privacy_cleanup_local-0.5.2-py3-none-any.whl"
```

Repeat from a second fresh source copy and compare wheel SHA-256 with the release's
`SHA256SUMS`. CI also compares a wheel built directly from source with one built
from the sdist. Sdist checksums identify the published source archive; byte-for-byte
sdist reproduction across environments is not claimed.

## Validation record

The release workflow runs compatibility checks, fully provisioned encrypted tests
with zero skips, Node UI tests, the scripted fictional demo, privacy/history/identity
checks, a checksum-pinned Gitleaks scan and distribution rebuild/install checks.
Use the README's CI link for current results; a passing branch run is not proof for
a different final commit. Native and browser evidence is stated separately below.

During release preparation on October 26, 2026, builder-run local checks passed
on macOS 27.0.1 / Python 3.12.15:

- Native Keychain create/read/delete smoke test using a random temporary item.
- A synthetic vault lifecycle: creation, wrong-passphrase refusal, lock/unlock,
  reopen, encrypted export, tamper refusal, restore after removing the original
  key, new restored keys, reconciliation gating and deletion. Every minted
  temporary Keychain item was removed. Existing user stores were not requested.
- Wheel installation in a fresh environment outside the source checkout, both
  command aliases, and loopback demo startup.
- Browser acceptance in the in-app browser: bundled fictional demo match/request
  preview; session-only shared identity, California batch eligibility, four-email
  preparation, individual approval, skipped requests and one successful fake-provider
  send. No mail app, Google account or broker endpoint was used.

These builder checks preceded the final tag and do not satisfy owner acceptance
or separate QA against a final release candidate. Native validation status:
**narrow native checks run; owner acceptance pending**.
The [native acceptance procedure](WALKTHROUGH.md#native-macos-acceptance)
defines the remaining checks and evidence format.

These checks do not cover actual OS sleep/wake, every browser lifecycle, power loss,
real Google integration or broker submissions. Those remain unverified. No real-data
migration or account connection was part of release validation.

## Publication integrity

The public repository is a fresh source export. The private development history is
not imported. Source, index, reachable history, author/committer metadata, wheel,
sdist and release media are inspected before public visibility. Secret scanners
and allowlists are safeguards, not a guarantee of exhaustive personal-data detection.
Raw runtime artifacts and native screenshots remain outside Git.

Release assets are built from the tagged commit; checksums accompany the wheel,
sdist and sanitized fictional screenshot. A sanitized external acceptance record
can identify hashes without changing the commit it verifies. Do not move a released
tag to incorporate a later report or fix. Later changes receive a new version.

## Final release acceptance

Finish and approve the case study, README and walkthrough timing before freezing
a candidate SHA. Separate QA and owner native acceptance must identify that same
revision. Any later change creates a new candidate; rerun every affected check.
Builder-run checks remain distinct from QA and owner acceptance.

Merging may change the SHA. Record the final commit on main and validate the actual
tag target before release; do not silently transfer evidence from a different
candidate. The published release remains unchanged. Later changes use a new version
and tag, each with explicit owner approval.

The private QA packet distinguishes pre-publication checks from checks that require
public availability, including release-asset verification and the subsequent
privacy rescan. A sanitized acceptance record is a release asset, not a source
change. Merge, release, profile and settings actions require separate approval.
