# Velum: making sensitive automation accountable

## Problem

Removing personal information from data-broker sites is a fragmented process.
People whose contact details are listed have to identify the right record, determine what a site requires, decide
what to disclose and follow up. Sending a request is only one step; it does not
prove that the information was removed.

I wanted an application that could prepare and submit requests from one reusable
identity while preserving control over each disclosure. The challenge was deciding
what the system could do responsibly and what evidence would justify its claims.

## My role and judgment

I set the product direction, privacy boundaries, acceptance criteria and release
decisions. I used Claude Code and Codex for implementation, testing, review and
release preparation. My role was to challenge the proposed scope, ask what had
actually been demonstrated and decide where progress needed another gate.

I pushed beyond a guided checklist toward an executable workflow, because a checklist
leaves the riskiest steps, what to disclose and whether a request actually went out,
to the person's memory. I also chose a
synthetic portfolio release: the submission workflow runs against a local fake
provider, and real-data use remains gated. That decision makes the work inspectable
without presenting an unverified service as ready for people to trust.

## Tradeoffs

**Local control versus hosted convenience.** I chose a local application, with
session-only use by default and saved records as an explicit choice. A hosted
service would make access across devices easier, but would introduce account,
deployment and recovery obligations before the core workflow was established.
The cost is more setup and responsibility on the user's device.

**Exact approval versus automation speed.** A single blanket permission would
make submission faster. I required separate match confirmation and review of the
exact request because permission to act on one record should not authorize a
different disclosure. A prepared batch reduces repeated entry while preserving
individual approval. It also requires more attention from the user.

**Honest uncertainty versus seamless retries.** Automatically retrying a timeout
would feel smoother. I chose to block another attempt until the uncertain outcome
is reconciled because an interrupted response can conceal a successful send.
That leaves some work unresolved instead of manufacturing a clean completion state.

## Risk and program thinking

I treated evidence as a progression: researched route, simulated behavior, tested
implementation, native acceptance and live outcome. These levels do not substitute
for one another. A successful fake-provider send establishes something narrower
than a broker accepting a request or removing a listing.

The repository maps bounded security claims to named tests and states known gaps.
The review status is explicit: **AI-authored and AI-reviewed; not independently
security-audited.** An independent review remains a prerequisite for real-data use.
Release acceptance is tied to a specific source revision; changes require renewed
checks rather than inheriting a previous result.

When a release step got ahead of its acceptance gate, I
contained it, recorded the breach and tightened the acceptance rules through dated
amendments instead of treating the published state as done.

## Deliberate scope cuts

- **Live broker sending and a real-data pilot:** excluded from this release because
  simulation does not establish route acceptance or readiness for personal information.
- **Automated discovery:** deferred because finding a possible record creates a
  separate matching, access and verification problem. Broader coverage would not
  resolve that uncertainty.
- **Hosted sync and family assistance:** deferred because they introduce additional
  identity, authority and recovery boundaries beyond the single-adult local workflow.
- **Scheduled checks and unattended retries:** deferred because elapsed time does
  not establish current permission, and an unknown outcome needs reconciliation.

## Outcomes and what I would do next

The result is an inspectable local workflow: reusable identity, exact-request
review, simulated execution, dated history and encrypted recovery. It ships with a
fictional demo, security claims mapped to named tests, and a release process in
which acceptance is pinned to one source revision and verified separately from the
builder. I am not claiming verified removals, adoption, time savings or
independently audited security.

For this portfolio release, the remaining work is owner acceptance and separate
QA against the final candidate. Before pursuing real use, I would commission
independent review, resolve route-specific uncertainties and authorize one bounded
pilot. Its receipts and follow-up evidence would determine whether expansion is
justified.

## For technical reviewers

[Architecture](ARCHITECTURE.md) · [Threat model](THREAT_MODEL.md) ·
[Claim-to-test map](SECURITY_VALIDATION.md) · [Recovery](RECOVERY.md) ·
[Coverage evidence](COVERAGE.md) · [Development history](HISTORY.md)
