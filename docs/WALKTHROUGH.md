# Synthetic walkthrough

## Dependency-free demo

From the clone, run `python3 -m privacy_cleanup` and open the printed loopback URL.
Use the bundled Avery Example identity, discover fictional candidates, confirm one
match, inspect and approve its exact request, and exercise the simulated result.
Notice the distinction between submitted, uncertain and broker-reported deletion.
This older fixture-driven demo is separate from the shared-identity workspace.

## Current macOS workspace

Requires Python 3.12 on an Apple-silicon Mac. These commands install only hash-locked dependencies
in an isolated temporary environment.

Run this block in one terminal from the repository root. The subshell stops its
fake provider when the UI exits; the temporary environment/store remain for inspection.

```sh
(
  VELUM_ENV=$(mktemp -d /tmp/velum-env.XXXXXX)
  VELUM_STORE=$(mktemp -d /tmp/velum-workspace.XXXXXX)
  python3.12 -m venv "$VELUM_ENV"
  "$VELUM_ENV/bin/python" -m pip install --require-hashes --only-binary=:all: -r requirements-private.lock || exit 1
  "$VELUM_ENV/bin/python" -m scripts.fake_provider --port 8799 &
  VELUM_FAKE_PID=$!
  trap 'kill "$VELUM_FAKE_PID" 2>/dev/null || true' EXIT
  "$VELUM_ENV/bin/python" -m privacy_cleanup private --synthetic-workspace --data-dir "$VELUM_STORE" --fake-transport 8799
)
```

Port **8766** is the default for the local workspace server, selected by
`python -m privacy_cleanup private` when `--port` is omitted. Port **8799** is
chosen explicitly above for the fake mail provider; `--fake-transport 8799` tells
the workspace where to reach it. Both services bind only to loopback.

Both ports must be unused. To change the workspace port, add `--port 8876` to
the private-workspace command. To change the fake-provider port, update both
its `--port` and the workspace's `--fake-transport` to the same unused number.
Do not attach to an unknown service. The quick demo uses a different default, 8765.

Open the **full printed launch link**; its fragment carries a per-launch token.
Choose the default session-only mode. It does not create a saved vault or Keychain
entry. An encrypted record is a separate opt-in and can trigger a Keychain prompt.

Enter a fictional adult identity: Avery Example, an email under `example.invalid`,
and California as current residence. Tick the reachable-email and adult-self checkboxes.
California enables four email routes plus Epsilon manual preparation; Hunter is excluded.
Do not connect Gmail or open mail handoffs. Build the batch, prepare ready requests,
inspect each recipient/body, approve individually, then choose the local simulated
sender. Compare the history against the saved exact messages. Change residence to
Texas and mark the fictional email as Work to exercise Hunter's provisional route;
Lusha becomes unavailable. Prior history keeps its original disclosure.

Stop both servers with Ctrl+C. Session-only records disappear at application level;
OS memory and swap are outside that guarantee. Temporary saved records and virtual
environments require explicit local cleanup. For recovery use [RECOVERY.md](RECOVERY.md).

## Native macOS acceptance

Use the frozen release-candidate checkout and a disposable directory with fictional records only.
Never test against existing user data or request existing Keychain entries. Keep
raw logs and screenshots outside Git. A sanitized summary can identify the commit,
package hash, OS/runtime version, checks completed and unresolved cases.

The optional `python -m scripts.keychain_check` creates, reads and deletes one
random temporary item under a dedicated synthetic service. It can trigger a native
prompt. It does not prove same-user isolation or validate the full vault lifecycle.

For the full native lane, follow the workspace setup above using a temporary
encrypted record. Exercise create, wrong-passphrase refusal, lock/unlock, restart,
idle expiry and two-tab stale actions. Export a synthetic backup before deleting
the original test vault and its test key. Restore into a new directory without the
original key; verify history, the reconciliation gate, fresh keys and excluded
sender credentials. Reject tampered archives and wrong secrets. Finally delete
the restored test vault and verify that only the application's own random test
items were removed.

Real sleep/resume, Safari/Firefox behavior, process interruption during native key
operations and OS power loss require separate observation. Record each as tested,
failed or untested; a successful memory-key test must not fill in a native result.
Do not connect an account, send mail or import calendar events during this lane.

### Acceptance evidence

Native validation status: **narrow native checks run; owner acceptance pending**.
Record the exact source SHA and package hash before starting. If either
changes, do not carry the result forward without reviewing and retesting the delta.

Keep the complete acceptance packet private and outside the repository. Publish
only a sanitized acceptance record as a release asset, identifying the verified
SHA, package hash, environment, checks and limitations. Do not commit logs or move
a published tag to attach later evidence. See [release validation](RELEASE.md).
