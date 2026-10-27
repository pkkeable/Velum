# Contributing

Read [AGENTS.md](AGENTS.md), [scope](docs/PRODUCT_SCOPE.md) and the
[threat model](docs/THREAT_MODEL.md). Submit minimal synthetic reproductions only.
Do not attach runtime databases, screenshots, logs, credentials or real listing URLs.

Use Python 3.12 with the matching hash-locked dependencies for encrypted tests (`requirements-private.lock` on an Apple-silicon Mac, `requirements-private-linux.lock` on Linux x86_64);
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

## Commit privacy

Before creating a pull request, enable GitHub's **Keep my email addresses private**
and **Block command line pushes that expose my email** in
[Settings → Emails](https://github.com/settings/emails). Configure the local Git
identity with the no-reply address shown there. Local Git configuration alone does
not control the temporary merge commits GitHub creates for pull requests.

For a new public repository, verify a pull request's head and generated merge
commit attribution while the repository is still private. Any unexpected email
is a publication blocker. The release check intentionally examines reachable
author and committer metadata, including GitHub-generated merge commits in PR CI.
