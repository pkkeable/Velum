# Threat model

## Non-goals

Velum does not defend against same-user malware, a compromised OS, malicious browser
extensions, OS backups/swap/crash dumps, or guaranteed erasure of process/browser
memory. Session-only means no application-managed persistent store, not forensic
absence. The Python network guard is not an OS sandbox. This is a synthetic preview,
not an independently security-audited service or a real broker-removal guarantee.

Test references below resolve through [SECURITY_VALIDATION.md](SECURITY_VALIDATION.md).

| Asset | Attacker or failure | Mitigation | Test reference | Known gap |
| --- | --- | --- | --- | --- |
| Saved identity and history | Disk reader, modified ciphertext | AES-GCM records with authenticated context | C1, C2 | Metadata remains; replay of valid older rows/DB is not detected |
| Wrapped data key | Keychain item reader | Passphrase-derived wrapping key, vault binding | C3 | Same-user/native isolation not established by memory-key tests |
| Passphrase | Guessing | Scrypt default n=131072, r=8, p=1; 16-byte salt; process-local delay | C4 | Delay resets on restart; offline guessing bypasses it; no weak-passphrase guarantee |
| Launch/session tokens | Foreign web page or stale tab | Host/origin/token checks; session invalidation | C5, C6 | Terminal/browser compromise exposes tokens |
| Local HTTP API | Malformed input, cross-origin request | Exact schemas, bounds, loopback binding | C5, C7 | Native/browser stack outside Python guard |
| Approved email | Changed request, concurrent dispatch, timeout | Fingerprint, reservation, conservative uncertainty | C8, C9, C10 | Provider acceptance is not broker acceptance or deletion |
| Gmail grant | Accidental retention or broad permission | Encrypted opt-in storage, narrow scope checks, revocation attempts | C11, C12 | Offline/abrupt shutdown may prevent provider revocation; no real Google acceptance test |
| Session data | Unexpected persistence or expired token | Separate memory store, invalidation on end | C13 | Python/OS memory is not zeroized |
| Backup | Tamper, lost original key, stale history | Authenticated bounded archive; new restore keys; pause/reconciliation; no OAuth export | C14, C15, C16 | Backup secret required; native power-loss/orphan cleanup remains unverified |
| Outbound boundary | Accidental networking or broker send | UI/worker audit guards; Gmail self-test restriction | C17, C18 | Not containment against malicious native code or modified source |

Supported deletion removes records and the application's keys, retaining an empty
database shell. It does not erase backups, broker copies or filesystem remnants.
Supported restore marks history stale; it cannot detect arbitrary rollback outside
that workflow. See [recovery](RECOVERY.md) for interruption and reconciliation limits.
