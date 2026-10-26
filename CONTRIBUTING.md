# Contributing

Read [AGENTS.md](AGENTS.md), [scope](docs/PRODUCT_SCOPE.md) and the
[threat model](docs/THREAT_MODEL.md). Submit minimal synthetic reproductions only.
Do not attach runtime databases, screenshots, logs, credentials or real listing URLs.

Use Python 3.12+ with the appropriate hash-locked dependencies for encrypted tests;
Node is needed for UI handler tests. Keep virtual environments and build output
outside the checkout. See [release setup](docs/RELEASE.md).

Run `make test`, `make demo`, and `make check`. New files require an explicit
public-allowlist update. Fixture seals and binary hashes require content review,
not just a hash update. Use `git config core.hooksPath .githooks` for the optional
staged-content hook. Inspect the staged diff; scans are not proof of anonymity.

Use a GitHub noreply commit identity. Keep author and committer metadata free of
private addresses. Do not rewrite existing attribution. New PRs need passing CI;
changes to storage, approvals, credentials, transport or recovery need a focused
boundary review and regression evidence. Keep plans separate from implemented behavior.
