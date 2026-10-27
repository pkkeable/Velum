# Velum

People whose contact details appear on data-broker sites face a fragmented removal
process. Each request can disclose more information, and a sent message does not
establish that a listing is gone.

Velum turns one identity into individually reviewed requests and a record of what
happened. The local workflow is implemented and exercised with fictional records;
[automated checks](https://github.com/pkkeable/Velum/actions/workflows/check.yml) back up specific claims.

<a href="https://github.com/pkkeable/Velum/releases/download/v0.5.1/velum-demo.png"><img src="https://github.com/pkkeable/Velum/releases/download/v0.5.1/velum-demo.png" alt="Velum's local demo using the bundled fictional Avery Example identity" width="480"></a>

> **What's real and what's simulated · technical preview 0.5.2**
> Reviewing requests and keeping history work locally. Sending to brokers is simulated,
> and Gmail sending is limited to test messages to yourself. No real personal data has
> been used. Tested on macOS in limited scenarios; full acceptance results are attached
> to each release.

**[Read the case study: decisions, tradeoffs and scope cuts →](docs/CASE_STUDY.md)**

## Try the fictional demo

Python 3.9+ on macOS or Linux. No dependencies or accounts:

```sh
git clone https://github.com/pkkeable/Velum.git
cd Velum
python3 -m privacy_cleanup
```

Open **http://127.0.0.1:8765**. Stop with Ctrl+C. The demo accepts only bundled
fictional records. If the port is occupied, add `--port 8875` and open that port.

The quick demo shows how to review a listing and decide what request to make.
The shared-identity workflow described in the case study is a separate **macOS
workspace**: follow the [walkthrough](docs/WALKTHROUGH.md) to try it with fictional
data and simulated sending. No email account is needed.

**Under a minute from clone to running demo (macOS test, Oct 26).**

Preliminary builder run on macOS with Python already installed, measured from
starting an anonymous clone to seeing the demo in the browser. Clean-machine
acceptance results are attached to each release.

## For technical reviewers

- [Architecture and decisions](docs/ARCHITECTURE.md)
- [Threat model and non-goals](docs/THREAT_MODEL.md)
- [Security claims and their tests](docs/SECURITY_VALIDATION.md)
- [Encrypted recovery and its limits](docs/RECOVERY.md)
- [Workspace walkthrough and native acceptance](docs/WALKTHROUGH.md)
- [Release reproduction and validation limits](docs/RELEASE.md)
- [Product case study](docs/CASE_STUDY.md)

The [coverage register](docs/COVERAGE.md) distinguishes simulated email routes,
manual handoffs and official user-opened resources, including California DROP.
Eligibility varies by route; expired evidence pauses a route until reviewed.
A provider accepting a message is not a broker acknowledgment or proof of deletion.
This preview is not a maintained removal service.

The product is **Velum**; its distribution is `privacy-cleanup-local`, its module is
`privacy_cleanup`, and both `velum` and `privacy-cleanup` commands are supported.
These compatibility identifiers do not move or migrate existing data.

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
security-audited.** Tests establish specific behaviors; they do not establish
general security or real broker effectiveness.

The [development history](docs/HISTORY.md) describes the private development behind
this reviewed source export. The [roadmap](docs/ROADMAP.md) keeps real-world use
behind separate review and pilot gates. Report vulnerabilities privately through
[SECURITY.md](SECURITY.md).

MIT license. EB Garamond is distributed under the SIL Open Font License; see
[third-party notices](privacy_cleanup/THIRD_PARTY.md).
