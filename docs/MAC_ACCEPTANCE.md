# Native macOS acceptance

Use a release checkout and a disposable directory with fictional records only.
Never test against existing user data or request existing Keychain entries. Keep
raw logs and screenshots outside Git. A sanitized summary can identify the commit,
package hash, OS/runtime version, checks completed and unresolved cases.

The optional `python -m scripts.keychain_check` creates, reads and deletes one
random temporary item under a dedicated synthetic service. It can trigger a native
prompt. It does not prove same-user isolation or validate the full vault lifecycle.

For the full native lane, follow [WALKTHROUGH.md](WALKTHROUGH.md) using a temporary
encrypted record. Exercise create, wrong-passphrase refusal, lock/unlock, restart,
idle expiry, two-tab stale actions and delete. Verify only the application's own
random test items disappear. Then export and restore a synthetic backup into a new
directory without the original key, verify history, the reconciliation gate, fresh
keys and excluded sender credentials. Reject tampered archives and wrong secrets.

Real sleep/resume, Safari/Firefox behavior, process interruption during native key
operations and OS power loss require separate observation. Record each as tested,
failed or untested; a successful memory-key test must not fill in a native result.
Do not connect an account, send mail or import calendar events during this lane.
