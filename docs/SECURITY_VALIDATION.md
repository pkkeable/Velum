# Claim-to-test map

These are bounded implementation checks, not an independent security audit. CI's
fully provisioned lane rejects skipped tests. `scripts.check_release` verifies
that every listed Python test exists; existence is not proof of adequate coverage.
Review assertions and negative cases, especially for storage, sending and recovery.

| ID | Bounded claim | Test ID |
| --- | --- | --- |
| C1 | Saved profile bytes are encrypted in the application database; this does not hide metadata. | `tests/test_private.py::VaultTests::test_ciphertext_only_and_restart_unlock` |
| C2 | Modified ciphertext/revision is rejected; valid older data replay is a known gap. | `tests/test_private.py::VaultTests::test_modified_ciphertext_and_revision_fail_authentication` |
| C3 | The key-store interface receives a passphrase-wrapped key, not the raw data key. Native isolation is not established by this test. | `tests/test_private.py::VaultTests::test_keychain_holds_only_a_wrapped_key_without_the_passphrase` |
| C4 | Wrong passphrases are refused with a process-local delay; offline resistance is bounded by the documented KDF. | `tests/test_private.py::VaultTests::test_wrong_passphrase_reveals_nothing_and_is_throttled` |
| C5 | Before any vault access, private HTTP rejects a missing or wrong Host, a missing or wrong launch token on API routes, cross-site fetch metadata, and any Origin other than the app's own. Requests that change state must also carry the app's own Origin. | `tests/test_security_validation.py::HTTPTrustBoundaryTests::test_private_routes_reject_before_any_vault_access`; `tests/test_private.py::PrivateHTTPTests::test_host_origin_and_bootstrap_token_are_required` |
| C6 | Lock invalidates the session and drops the key reference; memory zeroization is not claimed. | `tests/test_private.py::VaultTests::test_lock_invalidates_session_and_erases_key_reference` |
| C7 | Exact private command schemas and body bounds are enforced. | `tests/test_private.py::PrivateHTTPTests::test_exact_schema_and_bounded_body` |
| C8 | Identity, contract, external history and time changes invalidate approval. | `tests/test_execution.py::ExecutionTests::test_approval_invalidated_by_identity_contract_external_history_or_time` |
| C9 | Concurrent dispatch reserves/sends one attempt. | `tests/test_execution.py::ExecutionTests::test_double_click_and_concurrent_dispatch_send_once` |
| C10 | An uncertain attempt blocks retry until explicit reconciliation. | `tests/test_execution.py::ExecutionTests::test_uncertain_blocks_retry_until_the_owner_reconciles` |
| C11 | Fake-Google connection accepts only the expected account/grant and stores it encrypted in saved mode. Real Google is untested. | `tests/test_gmail.py::ConnectorTests::test_connect_stores_only_an_encrypted_grant_for_the_verified_account` |
| C12 | Session expiry still erases local data when revocation cannot reach the provider; provider revocation is not guaranteed. | `tests/test_privacy_modes.py::SessionOnlyTests::test_idle_expiry_erases_even_when_google_is_unreachable` |
| C13 | Session-only operation does not write application records to disk or key-store interface. OS swap/dumps are outside scope. | `tests/test_privacy_modes.py::SessionOnlyTests::test_nothing_is_written_to_disk_or_the_keychain` |
| C14 | Backup authentication, version and size limits refuse malformed input. | `tests/test_recovery.py::RecoveryTests::test_authentication_version_and_resource_limits` |
| C15 | Restore works without the original key and excludes the sender record. This uses memory keys, not native Keychain. | `tests/test_recovery.py::RecoveryTests::test_portable_restore_lock_restart_delete_without_original_keys` |
| C16 | Restored queues pause, uncertainty persists and reconciliation gates outbound work. | `tests/test_recovery.py::RecoveryTests::test_paused_queue_preserved_uncertainty_and_outbound_gate` |
| C17 | Covered UI-process DNS, UDP, remote bind and child-process calls are denied; not an OS sandbox. | `tests/test_boundaries.py::NetworkGuardTests::test_audit_guard_blocks_outbound_dns_udp_subprocess_and_remote_bind` |
| C18 | Gmail rejects broker messages before contacting Google. | `tests/test_gmail.py::GmailTransportTests::test_broker_messages_are_refused_before_contacting_google` |

## Additional evidence and non-goals

- Production backup KDF roundtrip: `tests/test_recovery.py::RecoveryTests::test_production_kdf_roundtrip`.
- Restore interruption/rollback: `tests/test_recovery.py::RecoveryTests::test_restore_overwrite_refusal_and_transaction_rollback`.
- Old approved/interrupted email history: `tests/test_recovery.py::RecoveryTests::test_existing_approved_email_and_dispatching_history_restore_conservatively`.
- Full local-worker journey: `tests/test_execution.py::ExecutionTests::test_end_to_end_with_the_real_worker_process_and_fake_provider`.
- Request rendering, source pinning, jurisdiction, email selection and documented coverage are checked in `tests/test_coverage.py`.
- UI handler tests in `tests/private_ui.test.cjs` cover stale responses, privacy modes, exact approval and history. They do not establish real-browser accessibility.
- No telemetry/hosted service/external AI is an architecture restriction checked by source review; tests do not prove absence of all possible network behavior.
- Independent audit, real Google integration, real broker acceptance, native power loss,
  forensic deletion, anti-rollback, memory erasure and hostile same-user containment
  are **not established**. See [THREAT_MODEL.md](THREAT_MODEL.md).

Native checks are recorded separately in [RELEASE.md](RELEASE.md). A test against a
key-store stand-in cannot establish native Keychain isolation. Historical passing
results are not reused as proof for a different commit or package.
