# Local encrypted backup and recovery

Implemented in the technical preview. Synthetic-only until independent recovery
review and native Mac acceptance. No hosted storage, scheduler or automatic backup.


## Design and limits

A separate backup recovery passphrase encrypts an authenticated, versioned manifest
with AES-256-GCM. A fresh 16-byte salt and 12-byte nonce are generated per export;
scrypt has fixed n=131072, r=8, p=1 (about 128 MiB). Input cannot request extra KDF
work. The format header, salt and nonce are authenticated. Maximum archive size is
16 MiB; nesting, record count, revision values and JSON shapes are bounded. Unknown
format/storage versions, duplicate JSON keys, malformed collection shapes and
normal workspace/history reader failures refuse restore. This is not exhaustive
field-level validation of every historical event.
A long unique backup passphrase is essential against offline guessing. There is no
forgotten-passphrase recovery, escrow, reset or guarantee of memory zeroization.

Export holds the store mutex and a SQLite transaction while reading a consistent
snapshot. It includes saved profile, cases and workflow; excludes the sender record
and all OAuth credentials. It never copies the old vault key or Keychain item.
Plaintext exists only in process memory, not temporary files. An owned mode-0700
non-Git destination directory is required; encrypted files are mode 0600. Export
uses a temporary ciphertext file, fsync and atomic no-overwrite link. An abrupt
crash may leave an encrypted temporary file; a completed archive still requires
its recovery passphrase. Application/OS memory, swap and backups are separate risks.

Restore authenticates and validates before creating anything. It stages normal
record readers in an encrypted in-memory store and installs records in one SQLite
transaction in a new directory with a fresh vault ID, fresh random data key and
fresh passphrase-wrapped Keychain entry. It needs no original Keychain. No existing
directory is accepted, even an empty one. Interrupted/failed restore may leave a
new empty/incomplete directory and, if Keychain cleanup fails or the process dies,
an orphaned wrapped key. Never treat that directory as a completed restore. Retain
it for inspection; retry to a different new directory. The original store/archive
is unchanged. There is no silent overwrite or merge. Native power-loss and Keychain
failure behavior must still be tested on Mac; exception injection is not that proof.

Restored history is visibly marked with snapshot and restore dates. Unused manual
and email approvals are invalidated; consumed approvals remain historical evidence.
Batch queues are paused. Interrupted sends
become uncertain through existing reconciliation logic. Existing uncertain attempts
remain blocked. Restored history can omit actions after the snapshot: check Sent
mail and broker replies and record missing/uncertain requests before acknowledging
reconciliation. This is an owner assertion, not automated evidence verification.
Until then re-export, new preparation, approvals, dispatch, self-tests and manual handoffs are
blocked server-side. Reconciliation does not reconnect accounts, approve messages
or resume the queue. Any connection requires fresh consent. Old builds do not
understand the recovery record and refuse case/send operations; do not downgrade.

Deleting the local store does not delete separately held backup files or broker
records. Backups retain old history and may undo local deletion if restored.
Protect and delete backup copies independently. A backup passphrase unlocks that
backup even after the original vault/Keychain is deleted. Conversely, without the
backup passphrase that archive is unrecoverable. Session-only mode is deliberately
not backed up; explicitly save it to an encrypted record first if retention is wanted.

## Explicit CLI workflow

Use the installed `velum` or compatibility `privacy-cleanup` command on macOS with
Python 3.12+ and the pinned native dependencies. Stop the running app first; the
exclusive vault lock refuses concurrent CLI access. Passphrases are prompted via
getpass, never command-line arguments, browser storage, logs or environment values.
Ctrl+C/EOF cancels; error messages do not print identity fields or secret values.
Privacy & settings describes these commands; restored pages show the stale-history
warning. No new HTTP file-upload/download route is enabled.

```sh
velum recovery export --synthetic-workspace --data-dir /absolute/synthetic-store --archive /absolute/private-backups/example.velum
velum recovery restore --synthetic-workspace --data-dir /absolute/new-synthetic-store --archive /absolute/private-backups/example.velum
velum recovery reconcile --synthetic-workspace --data-dir /absolute/new-synthetic-store
```

For export, enter the current vault passphrase, then a separate backup passphrase
and confirmation. Keep the latter separately from the archive. For restore, enter
the backup passphrase and a new vault passphrase with confirmation. Start the app
explicitly against the new store, review History, and record missing/uncertain
activity. Stop it and run reconcile; type RECONCILED only after completing that
review. Start the app again, reconnect only when authorized, and review each new
request. The CLI and normal startup still refuse the personal default directory;
real account connection and sending are not authorized by these instructions.

## Native acceptance and promotion

Linux tests use disposable stores and abstract memory key stores. Native tests must
prove encrypted export and clean-Mac restore with no original Keychain entry,
wrong-secret/tamper refusal, restart/lock/delete, Keychain failure/interruption and
permissions; also verify existing sleep/resume, idle, multiple-tab and Safari/Firefox
behavior. Mail handoff/calendar import require separate authorization; VoiceOver
remains on hold. Independent focused model review does not replace native checks
or qualified human security assessment. Personal-data/live-send promotion and any
publication remain separate owner decisions.
