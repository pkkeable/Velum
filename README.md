# Velum

[![Synthetic checks](https://github.com/pkkeable/Velum/actions/workflows/check.yml/badge.svg)](https://github.com/pkkeable/Velum/actions/workflows/check.yml)

**Enter once. Review every request. Keep the evidence.**

Velum is a local privacy-request workflow that turns one reusable identity into
individually approved requests and a durable record of what happened. It demonstrates
how to automate sensitive work without treating a timeout as success or an approval
as permission to send something different.

> **Technical preview · 0.5.1 · synthetic data only.** Local identity, approval,
> history and encrypted recovery features are implemented. Broker sending uses a
> local fake provider. No broker removal or real-data safety claim is made.
> Gmail is restricted to self-tests; connecting a real account is unnecessary.

### Try the fictional demo

Python 3.9+ on macOS or Linux. No dependencies or accounts:

```sh
git clone https://github.com/pkkeable/Velum.git
cd Velum
python3 -m privacy_cleanup
```

Open **http://127.0.0.1:8765**. Stop with Ctrl+C. The demo accepts only bundled
fictional records. If the port is occupied, add `--port 8875` and open that port.
The macOS encrypted workspace is a separate walkthrough below.

![Velum fictional demo](https://github.com/pkkeable/Velum/releases/download/v0.5.1/velum-demo.png)

## What to look at

| Product behavior | Engineering decision |
| --- | --- |
| One identity feeds qualifying routes | Typed identifiers, per-route eligibility and minimum-field mapping |
| Review sender, recipient and exact message | Approval fingerprint binds the disclosure; edits invalidate unused approvals |
| Interrupted sending stays uncertain | Attempt reserved before dispatch; no automatic retry after ambiguous outcomes |
| History survives profile changes | Stored request snapshots rather than reconstruction from the latest identity |
| Keep nothing by default; explicitly opt into saved records | Separate in-memory and encrypted SQLite stores |
| Restore without silently repeating requests | Fresh keys, no exported OAuth grant, paused queues and reconciliation gate |

**For technical reviewers:** [architecture](docs/ARCHITECTURE.md),
[threat model and non-goals](docs/THREAT_MODEL.md),
[claim-to-test map](docs/SECURITY_VALIDATION.md), and
[release reproduction](docs/RELEASE.md).

## What works, and what remains unverified

| Capability | Evidence level |
| --- | --- |
| Shared identity, exact approvals, attention queue and masked history | Implemented and exercised with synthetic records |
| Apollo, Cognism, Lusha, ContactOut and Hunter email contracts | Automated simulation only; eligibility and unresolved scope differ by route |
| Epsilon request preparation and other broker guidance | Local/manual workflow; no live acceptance claim |
| California DROP | Official user-opened resource; no integration or identity transfer |
| Encrypted records and portable backup/restore | Implemented; see native-test limits in the release record |
| Gmail connection | Send-only implementation; broker sending refused; fake-Google tests |
| Broker replies and listing observations | Dated user reports, not independent verification |
| Discovery, scheduled checks, hosted sync and family assistance | Planned, not implemented |

A provider accepting a message is not a broker acknowledgment or proof of deletion.
Route evidence has a 30-day review window; expired routes pause until reviewed.
The [coverage register](docs/COVERAGE.md) records the limits. This preview is not a
maintained removal service.

## Run the current workflow

The dependency-free demo illustrates listing decisions. The newer shared-identity,
five-route simulation and privacy modes run in the **macOS synthetic workspace**.
Follow the complete [walkthrough](docs/WALKTHROUGH.md). Use fictional data only.
No email account is needed; the fake provider stays on loopback.

![Exact-email review in the synthetic workspace](https://github.com/pkkeable/Velum/releases/download/v0.5.1/velum-workspace.png)

The product is called **Velum**; its distribution is `privacy-cleanup-local`, its
module is `privacy_cleanup`, and both `velum` and `privacy-cleanup` commands are
supported. These compatibility identifiers do not move or migrate existing data.

## Validate and contribute

```sh
make test
make demo
make check
```

Python and Node are needed for development checks. Full encrypted-storage tests
also require the platform's hash-locked private dependencies. CI runs a fully
provisioned lane that rejects skipped tests, plus dependency-free compatibility
lanes where encrypted-module skips are expected. See [CONTRIBUTING.md](CONTRIBUTING.md).

## How this was built

The maintainer defined the product, privacy boundaries, acceptance criteria and
release decisions. Claude Code and Codex assisted with implementation, testing,
review and release preparation. **AI-authored and AI-reviewed; not independently
security-audited.** Automated tests and reproducible builds are evidence of specific
behaviors, not proof of general security or real broker effectiveness.

This repository is a reviewed source export from private development. Its
[development history](docs/HISTORY.md) explains the increments and their limits.
The [roadmap](docs/ROADMAP.md) keeps real-world use behind separate review and pilot
gates. Report vulnerabilities privately through [SECURITY.md](SECURITY.md).

MIT license. EB Garamond is distributed under the SIL Open Font License; see
[third-party notices](privacy_cleanup/THIRD_PARTY.md).
