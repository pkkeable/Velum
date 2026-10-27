# Product scope

Release direction, October 26, 2026: Velum is a portfolio technical preview of a
local privacy-request workflow. One adult enters identifiers once, approves each
exact request and retains dated outcomes. This release demonstrates that workflow
with synthetic records and a local fake sender; real submissions and a real-data
pilot are outside its completion criteria. The proposed live-submission product
remains separately gated in [ROADMAP.md](ROADMAP.md).

## Current release

- Session-only by default; encrypted saved record is explicit opt-in.
- Shared names, emails, addresses, phones and current residence; ambiguous choices
  need resolution rather than inference.
- Five simulated email contracts, per-request review, in-page batch confirmation,
  pause/resume, duplicate controls and uncertain-attempt reconciliation.
- Stored exact disclosures, masked history, attention groups and manual reply tracking.
- Manual listing matching remains separate from request approval.
- Portable encrypted recovery for saved records, excluding sender credentials.
- macOS private-workspace CLI; macOS/Linux dependency-free fictional demo.

## Release boundaries

Only bundled fixtures enter the demo. Other synthetic records belong in disposable
workspaces outside Git. Existing user stores must not be migrated or restarted by
setup or tests. No real person search, broker form submission or opt-out is enabled.

Official broker links are bare and user-clicked. Manual handoffs can open an external
page or mail application only when the user explicitly chooses them; this preview's
testing does not execute those external actions. Receipt, acknowledgment, deletion
statement and observed absence are separate evidence levels.

Public source publication is distinct from approval for real-data use. Independent
storage/transport/recovery review, native validation and separately approved
route-specific pilots remain prerequisites for that promotion. Planned discovery,
observation and hosted functionality is described in [ROADMAP.md](ROADMAP.md).
