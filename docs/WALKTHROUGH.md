# Synthetic walkthrough

## Dependency-free demo

From the clone, run `python3 -m privacy_cleanup` and open the printed loopback URL.
Use the bundled Avery Example identity, discover fictional candidates, confirm one
match, inspect and approve its exact request, and exercise the simulated result.
Notice the distinction between submitted, uncertain and broker-reported deletion.
This older fixture-driven demo is separate from the shared-identity workspace.

## Current macOS workspace

Requires Python 3.12+ on macOS. These commands install only hash-locked dependencies
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

Both ports 8799 and 8766 must be unused. If startup reports a port conflict, stop
and choose unused ports in the two commands; do not attach to an unknown service.

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
