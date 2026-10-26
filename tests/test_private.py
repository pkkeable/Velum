"""Synthetic, isolated private-storage tests. Never touch the user's Keychain."""
import copy
import http.client
import json
import os
import re
import socket
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

try:
    from privacy_cleanup.vault import WRAP_LENGTH, WRAPPED, PassphraseSetupRequired, Vault, passphrase_bytes
except ImportError:
    raise unittest.SkipTest("Private tests require the encryption dependency on Python 3.12+")

from privacy_cleanup.domain import Profile, RuleError
from privacy_cleanup.identity import from_legacy
from privacy_cleanup.private_server import create_server
from privacy_cleanup.storage import Store

TMP = "/private/tmp" if Path("/private/tmp").exists() else "/tmp"
LEGACY_PROFILE = {"full_name": "Avery CipherCanary Example", "email": "cipher-canary@example.invalid",
           "city": "Synthetic CipherCanary Town", "region": "ZZ", "postal_code": "00000", "country": "US"}
PROFILE = from_legacy(LEGACY_PROFILE)
PROFILE["self_adult"] = True
PROFILE["emails"][0]["reachable"] = True
PASS = "synthetic PassphraseCanary 42"
FAST = 14  # Minimum scrypt cost; production uses the default.
CREATE = {"acknowledged": True, "passphrase": PASS, "confirmation": PASS}


def make_legacy(vault, keys):
    """Turn a fresh synthetic vault into the pre-passphrase layout: a raw key under the bare ID."""
    identifier = vault._meta()[0]
    raw = vault.key
    keys.values.clear()
    keys.values[identifier] = raw
    vault.lock()
    return identifier, raw


class MemoryKeys:
    def __init__(self):
        self.values = {}
        self.fail_delete = False

    def get(self, identifier):
        return self.values.get(identifier)

    def put(self, identifier, key):
        self.values[identifier] = key

    def delete(self, identifier):
        if self.fail_delete:
            raise RuleError("Synthetic key deletion failure")
        self.values.pop(identifier, None)


class VaultTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP)
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "private"
        self.keys = MemoryKeys()
        self.monotonic = self.wall = 1000
        self.vault = Vault(self.path, self.keys, clock=lambda: self.monotonic, wall=lambda: self.wall, kdf_log2n=FAST)
        self.addCleanup(lambda: self.vault.close())

    def create(self):
        self.session = self.vault.unlock(PASS, create=True)["session"]
        return self.session

    def save(self):
        self.create()
        return self.vault.save(self.session, PROFILE, 0)

    def test_starts_locked_without_key_and_does_not_create_key_until_requested(self):
        self.assertTrue(self.vault.status()["locked"])
        self.assertFalse(self.vault.status()["initialized"])
        self.assertEqual(self.keys.values, {})
        with self.assertRaises(RuleError): self.vault.read(None)
        with self.assertRaises(RuleError): self.vault.unlock(PASS)

    def test_ciphertext_only_and_restart_unlock(self):
        self.save()
        for path in self.path.iterdir():
            if path.is_file():
                data = path.read_bytes()
                for value in (LEGACY_PROFILE["full_name"], LEGACY_PROFILE["email"], LEGACY_PROFILE["city"]):
                    self.assertNotIn(value.encode(), data, "Synthetic plaintext leaked")
                for key in self.keys.values.values():
                    self.assertNotIn(key, data, "Vault key persisted outside key store")
        self.vault.close()
        self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
        self.assertTrue(self.vault.status()["locked"])
        result = self.vault.unlock(PASS)
        self.assertEqual(result["profile"], PROFILE)
        self.assertEqual(result["version"], 1)
        with self.assertRaises(RuleError): self.vault.read(self.session)

    def test_wrong_key_fails_and_locks_without_overwriting(self):
        self.save()
        identifier = self.vault._meta()[0]
        self.vault._store_wrapped(identifier, b"z" * 32, passphrase_bytes(PASS))
        before = (self.path / "vault.sqlite3").read_bytes()
        with self.assertRaisesRegex(RuleError, "authentication failed"): self.vault.unlock(PASS)
        self.assertTrue(self.vault.status()["locked"])
        self.assertEqual(before, (self.path / "vault.sqlite3").read_bytes())

    def test_missing_key_is_not_silently_recreated(self):
        self.save(); self.keys.values.clear(); self.vault.lock()
        with self.assertRaisesRegex(RuleError, "missing"): self.vault.unlock(PASS)
        self.assertFalse(self.keys.values)
        with self.assertRaises(RuleError): self.vault.unlock(PASS, create=True)

    def test_modified_ciphertext_and_revision_fail_authentication(self):
        self.save()
        with self.vault.db:
            self.vault.db.execute("UPDATE records SET revision=revision+1")
        with self.assertRaisesRegex(RuleError, "authentication failed"): self.vault.read(self.session)
        self.assertIsNone(self.vault.key)

    def test_ciphertext_bit_flip_rejected(self):
        self.save()
        blob = self.vault.db.execute("SELECT body FROM records").fetchone()[0]
        with self.vault.db:
            self.vault.db.execute("UPDATE records SET body=?", (bytes([blob[0] ^ 1]) + blob[1:],))
        with self.assertRaises(RuleError): self.vault.read(self.session)

    def test_nonce_collision_fails_without_profile_change(self):
        self.save()
        nonce = self.vault.db.execute("SELECT nonce FROM records").fetchone()[0]
        with patch("privacy_cleanup.vault.secrets.token_bytes", return_value=nonce):
            with self.assertRaisesRegex(RuleError, "nonce allocation"): self.vault.save(self.session, PROFILE, 1)
        self.assertEqual(self.vault.read(self.session)["version"], 1)

    def test_stale_save_does_not_overwrite(self):
        self.save()
        with self.assertRaises(RuleError): self.vault.save(self.session, PROFILE, 0)
        self.assertEqual(self.vault.read(self.session)["version"], 1)

    def test_simultaneous_saves_reserve_one_revision(self):
        from concurrent.futures import ThreadPoolExecutor
        self.create()
        def save(_):
            try: self.vault.save(self.session, PROFILE, 0); return True
            except RuleError: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sum(pool.map(save, range(2))), 1)

    def test_lock_invalidates_session_and_erases_key_reference(self):
        self.save(); self.vault.lock()
        self.assertIsNone(self.vault.key)
        with self.assertRaises(RuleError): self.vault.read(self.session)
        new_session = self.vault.unlock(PASS)["session"]
        self.assertNotEqual(new_session, self.session)
        with self.assertRaises(RuleError): self.vault.save(self.session, PROFILE, 1)

    def test_polling_does_not_refresh_idle_session(self):
        self.create()
        for _ in range(4):
            self.monotonic += 200; self.wall += 200
            self.vault.status(); self.vault.read(self.session)
        self.monotonic += 101; self.wall += 101
        self.vault.expire()
        self.assertTrue(self.vault.status()["locked"])
        self.assertIsNone(self.vault.key)

    def test_explicit_activity_refreshes_and_sleep_or_clock_reversal_locks(self):
        self.create()
        self.monotonic += 800; self.wall += 800; self.vault.touch(self.session)
        self.monotonic += 100; self.wall += 100
        self.assertFalse(self.vault.status()["locked"])
        self.wall += 10
        self.assertTrue(self.vault.status()["locked"])
        self.vault.unlock(PASS); self.wall -= 1
        self.assertTrue(self.vault.status()["locked"])

    def test_second_process_or_instance_cannot_open_same_vault(self):
        with self.assertRaisesRegex(RuleError, "already open"): Vault(self.path, self.keys, kdf_log2n=FAST)

    def test_demo_and_private_directories_cannot_mix(self):
        with self.assertRaises(RuleError): Store(self.path)
        demo = Path(self.tmp.name) / "demo"
        Store(demo)
        with self.assertRaises(RuleError): Vault(demo, self.keys)

    def test_git_directory_rejected_before_write(self):
        root = Path(self.tmp.name) / "checkout"; root.mkdir(); (root / ".git").write_text("gitdir: elsewhere")
        with self.assertRaises(RuleError): Vault(root / "vault", self.keys)
        self.assertFalse((root / "vault").exists())

    def test_symlink_and_hardlink_rejected(self):
        root = Path(self.tmp.name)
        link = root / "link"; link.symlink_to(self.path)
        with self.assertRaises(RuleError): Vault(link, self.keys)
        self.vault.close()
        os.link(self.path / "vault.sqlite3", root / "linked-database")
        with self.assertRaises(RuleError): Vault(self.path, self.keys, kdf_log2n=FAST)

    def test_path_replacement_is_detected(self):
        self.create(); moved = self.path.with_name("moved")
        self.path.rename(moved); self.path.mkdir(mode=0o700)
        with self.assertRaises(RuleError): self.vault.read(self.session)

    def test_private_file_permissions(self):
        self.save()
        for path in self.path.iterdir(): self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_unsafe_permission_change_locks_before_read(self):
        self.save()
        (self.path / "vault.sqlite3").chmod(0o644)
        with self.assertRaises(RuleError): self.vault.read(self.session)
        self.assertIsNone(self.vault.key)

    def test_deletion_requires_confirmation_and_current_revision(self):
        self.save()
        for confirmation, revision in (("delete", 1), ("DELETE LOCAL PROFILE", 1), ("DELETE", 0)):
            with self.assertRaises(RuleError): self.vault.delete(self.session, confirmation, revision)
        self.assertEqual(self.vault.read(self.session)["profile"], PROFILE)

    def test_deletion_clears_key_records_and_uses_new_key_namespace(self):
        self.save(); old_id = self.vault._meta()[0]
        self.vault.delete(self.session, "DELETE", 1)
        self.assertFalse(self.keys.values)
        self.assertFalse(self.vault.status()["initialized"])
        self.assertEqual(self.vault.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)
        self.create(); self.assertNotEqual(old_id, self.vault._meta()[0])

    def test_interrupted_key_deletion_stays_inaccessible_after_restart(self):
        self.save(); self.keys.fail_delete = True
        with self.assertRaises(RuleError): self.vault.delete(self.session, "DELETE", 1)
        self.vault.close(); self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
        self.assertTrue(self.vault.status()["deletion_pending"])
        with self.assertRaises(RuleError): self.vault.unlock(PASS)
        self.keys.fail_delete = False
        self.vault.delete(None, "DELETE", None)
        self.assertFalse(self.keys.values)

    def test_unknown_schema_refuses_without_rewrite(self):
        self.save(); self.vault.close()
        conn = sqlite3.connect(str(self.path / "vault.sqlite3")); conn.execute("PRAGMA user_version=99"); conn.close()
        before = (self.path / "vault.sqlite3").read_bytes()
        with self.assertRaisesRegex(RuleError, "version"): Vault(self.path, self.keys, kdf_log2n=FAST)
        self.assertEqual(before, (self.path / "vault.sqlite3").read_bytes())

    def test_invalid_profile_is_not_logged_in_error(self):
        self.create()
        invalid = copy.deepcopy(PROFILE)
        invalid["emails"][0]["value"] = "not-an-email-CipherCanary"
        try: self.vault.save(self.session, invalid, 0)
        except RuleError as error: self.assertNotIn("CipherCanary", str(error))
        else: self.fail("Invalid email accepted")
        self.assertIsNone(self.vault.read(self.session)["profile"])
        self.assertNotIn(LEGACY_PROFILE["full_name"], repr(Profile.parse(LEGACY_PROFILE)))

    # Review H-1 / I-1: unlocking needs the passphrase; Keychain holds only a wrapped key.

    def test_keychain_holds_only_a_wrapped_key_without_the_passphrase(self):
        self.save()
        identifier = self.vault._meta()[0]
        self.assertEqual(set(self.keys.values), {identifier + WRAPPED})
        blob = self.keys.values[identifier + WRAPPED]
        self.assertEqual(len(blob), WRAP_LENGTH)
        self.assertNotIn(self.vault.key, blob)
        self.assertNotIn(PASS.encode(), blob)

    def test_wrong_passphrase_reveals_nothing_and_is_throttled(self):
        self.save(); self.vault.lock()
        for _ in range(3):
            with self.assertRaisesRegex(RuleError, "does not unlock"): self.vault.unlock("wrong synthetic passphrase")
        self.assertTrue(self.vault.status()["locked"])
        self.assertIsNone(self.vault.key)
        with self.assertRaisesRegex(RuleError, "Too many"): self.vault.unlock(PASS)
        self.monotonic += 2; self.wall += 2
        self.assertEqual(self.vault.unlock(PASS)["profile"], PROFILE)
        self.assertEqual((self.vault.failures, self.vault.retry_at), (0, None))

    def test_short_or_missing_passphrase_cannot_create_a_vault(self):
        for value in ("short", "", None, 12345):
            with self.assertRaises(RuleError): self.vault.unlock(value, create=True)
        self.assertFalse(self.keys.values)
        self.assertFalse(self.vault.status()["initialized"])

    def test_new_passphrase_minimum_uses_normalized_characters(self):
        with self.assertRaisesRegex(RuleError, "Unicode normalization"):
            self.vault.unlock("e\u0301" * 6, create=True)
        self.assertFalse(self.keys.values)
        self.assertFalse(self.vault.status()["initialized"])
        self.vault.unlock("e\u0301" * 12, create=True)
        self.vault.lock()
        self.assertIsNone(self.vault.unlock("\u00e9" * 12)["profile"])
        make_legacy(self.vault, self.keys)
        with self.assertRaisesRegex(RuleError, "Unicode normalization"):
            self.vault.set_passphrase("e\u0301" * 6)

    def test_unlock_preserves_pre_fix_normalized_passphrase(self):
        self.save()
        identifier = self.vault._meta()[0]
        # Reproduce an existing wrapped key created when length was checked
        # before NFC normalization. Only the synthetic in-memory key is replaced.
        self.vault._store_wrapped(identifier, self.vault.key, ("\u00e9" * 6).encode())
        self.vault.close()
        self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
        for spelling in ("\u00e9" * 6, "e\u0301" * 6):
            self.assertEqual(self.vault.unlock(spelling)["profile"], PROFILE)
            self.vault.lock()

    def test_creation_never_adopts_a_planted_key(self):
        planted = b"p" * 32
        identifier = self.vault._meta()[0]
        self.keys.values[identifier] = planted
        self.keys.values[identifier + WRAPPED] = b"planted wrapped key"
        self.create()
        self.assertNotEqual(self.vault._meta()[0], identifier)
        self.assertNotEqual(self.vault.key, planted)

    def test_legacy_vault_requires_passphrase_setup_then_drops_raw_key(self):
        self.save()
        records = self.vault.db.execute("SELECT * FROM records ORDER BY id").fetchall()
        identifier, raw = make_legacy(self.vault, self.keys)
        with self.assertRaises(PassphraseSetupRequired): self.vault.unlock(PASS)
        with self.assertRaises(RuleError): self.vault.set_passphrase("short")
        result = self.vault.set_passphrase(PASS)
        self.assertEqual(result["profile"], PROFILE)
        self.assertNotIn("notice", result)
        self.assertEqual(set(self.keys.values), {identifier + WRAPPED})
        self.assertEqual(records, self.vault.db.execute("SELECT * FROM records ORDER BY id").fetchall())
        self.vault.lock()
        self.assertEqual(self.vault.unlock(PASS)["profile"], PROFILE)
        self.assertEqual(self.vault.key, raw)
        with self.assertRaisesRegex(RuleError, "already has a passphrase"): self.vault.set_passphrase(PASS)

    def test_legacy_key_removal_failure_is_reported_and_retried(self):
        self.save()
        identifier, _ = make_legacy(self.vault, self.keys)
        self.keys.fail_delete = True
        self.assertIn("notice", self.vault.set_passphrase(PASS))
        self.assertIn(identifier, self.keys.values)
        self.keys.fail_delete = False; self.vault.lock()
        self.vault.unlock(PASS)
        self.assertEqual(set(self.keys.values), {identifier + WRAPPED})

    def test_set_passphrase_refuses_a_legacy_key_that_does_not_open_records(self):
        self.save()
        identifier, _ = make_legacy(self.vault, self.keys)
        self.keys.values[identifier] = b"w" * 32
        with self.assertRaisesRegex(RuleError, "authentication failed"): self.vault.set_passphrase(PASS)
        self.assertNotIn(identifier + WRAPPED, self.keys.values)

    def test_deletion_removes_wrapped_and_legacy_keys(self):
        self.save()
        identifier = self.vault._meta()[0]
        self.keys.values[identifier] = b"leftover legacy key material!!!!"
        self.vault.delete(self.session, "DELETE", 1)
        self.assertFalse(self.keys.values)

    # Review L-1: a tab whose session was replaced learns that from status polling.

    def test_status_reports_whether_this_tab_session_is_still_valid(self):
        first = self.create()
        self.assertTrue(self.vault.status(first)["session_valid"])
        second = self.vault.unlock(PASS)["session"]
        self.assertFalse(self.vault.status(first)["session_valid"])
        self.assertTrue(self.vault.status(second)["session_valid"])
        self.assertFalse(self.vault.status("é")["session_valid"])
        self.assertFalse(self.vault.status()["locked"])


class PrivateHTTPTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.vault = Vault(Path(self.tmp.name) / "private", MemoryKeys(), kdf_log2n=FAST); self.addCleanup(self.vault.close)
        self.server = create_server(self.vault, 0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.stop)
        self.port = self.server.server_port; self.token = self.server.token
        self.session = None

    def stop(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join()

    def request(self, path, payload=None, extra=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        headers = {"X-App-Token":self.token, "X-Private-Session":self.session or "", "Content-Type":"application/json", "Origin":"http://127.0.0.1:"+str(self.port)}
        headers.update(extra or {})
        try:
            conn.request("GET" if payload is None else "POST", path, None if payload is None else json.dumps(payload), headers)
            result = conn.getresponse(); body = result.read()
            return result.status, dict(result.getheaders()), json.loads(body) if result.getheader("Content-Type").startswith("application/json") else body
        finally: conn.close()

    def test_private_ui_roundtrip_lock_and_no_demo_or_live_actions(self):
        self.assertEqual(self.request("/api/profile")[0], 409)
        self.session = self.request("/api/create", CREATE)[2]["session"]
        self.assertEqual(self.request("/api/save", {"profile":PROFILE,"version":0})[0], 200)
        self.assertEqual(self.request("/api/profile")[2]["profile"], PROFILE)
        self.assertEqual(self.request("/api/status")[2]["mode"], "private-local")
        for path in ("/api/action", "/api/submit", "/api/search", "/api/export", "/app.js", "/vault.sqlite3"):
            self.assertEqual(self.request(path)[0], 404)
        self.request("/api/lock", {})
        self.assertEqual(self.request("/api/profile")[0], 409)

    def test_host_origin_and_bootstrap_token_are_required(self):
        for headers in ({"Host":"attacker.invalid"}, {"Origin":"https://attacker.invalid"}, {"X-App-Token":"wrong"}):
            self.assertEqual(self.request("/api/create", CREATE, headers)[0], 403)
        self.assertFalse(self.vault.status()["initialized"])

    def test_exact_schema_and_bounded_body(self):
        for body in ({"acknowledged":True,"mode":"live"}, [], {"acknowledged":False}):
            self.assertEqual(self.request("/api/create", body)[0], 409)
        self.assertEqual(self.request("/api/create", {"acknowledged":"x"*9000})[0], 413)

    def test_headers_and_error_output_have_no_personal_data(self):
        code, headers, page = self.request("/")
        self.assertEqual(code, 200); self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])
        self.assertNotIn(LEGACY_PROFILE["full_name"].encode(), page)
        self.session = self.request("/api/create", CREATE)[2]["session"]
        with patch.object(self.vault, "save", side_effect=RuntimeError(LEGACY_PROFILE["email"])):
            result = self.request("/api/save", {"profile":PROFILE,"version":0})
        self.assertEqual(result[0], 500)
        self.assertNotIn(LEGACY_PROFILE["email"], json.dumps(result))
        self.assertTrue(self.vault.status()["locked"])

    def test_confirmed_deletion_through_http(self):
        self.session = self.request("/api/create", CREATE)[2]["session"]
        self.request("/api/save", {"profile":PROFILE,"version":0})
        self.assertEqual(self.request("/api/delete", {"confirmation":"wrong","version":1})[0], 409)
        response = self.request("/api/delete", {"confirmation":"DELETE","version":1})
        self.assertEqual(response[0], 200)
        self.assertFalse(response[2]["initialized"])
        self.assertFalse(self.vault.keys.values)

    # Review H-1, L-2, L-4 and I-2 regressions over real loopback HTTP.

    def raw(self, data):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=10)
        try:
            sock.sendall(data); chunks = []
            while chunk := sock.recv(65536): chunks.append(chunk)
            return b"".join(chunks)
        finally: sock.close()

    def test_page_does_not_hand_out_the_api_token(self):
        code, headers, page = self.request("/")
        self.assertEqual(code, 200)
        self.assertNotIn(self.token.encode(), page)
        self.assertNotIn(b"app-token", page)
        self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")

    def test_create_requires_matching_passphrase_confirmation(self):
        self.assertEqual(self.request("/api/create", dict(CREATE, confirmation=PASS + "x"))[0], 409)
        self.assertFalse(self.vault.status()["initialized"])

    def test_unlock_needs_the_passphrase_over_http(self):
        self.session = self.request("/api/create", CREATE)[2]["session"]
        self.request("/api/save", {"profile":PROFILE,"version":0}); self.request("/api/lock", {})
        for body in ({}, {"passphrase": "wrong synthetic passphrase"}):
            status, _, result = self.request("/api/unlock", body)
            self.assertEqual(status, 409); self.assertNotIn("profile", result)
        status, _, result = self.request("/api/unlock", {"passphrase": PASS})
        self.assertEqual((status, result["profile"]), (200, PROFILE))

    def test_legacy_vault_upgrade_over_http(self):
        self.session = self.request("/api/create", CREATE)[2]["session"]
        self.request("/api/save", {"profile":PROFILE,"version":0})
        make_legacy(self.vault, self.vault.keys)
        status, _, result = self.request("/api/unlock", {"passphrase": PASS})
        self.assertEqual((status, result.get("passphrase_setup")), (409, True))
        self.assertEqual(self.request("/api/passphrase", {"passphrase":PASS, "confirmation":"different synthetic phrase"})[0], 409)
        status, _, result = self.request("/api/passphrase", {"passphrase":PASS, "confirmation":PASS})
        self.assertEqual((status, result["profile"]), (200, PROFILE))

    def test_truncated_body_is_rejected_without_locking(self):
        self.session = self.request("/api/create", CREATE)[2]["session"]
        response = self.raw(("POST /api/touch HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nOrigin: http://127.0.0.1:%d\r\n"
                             "Content-Type: application/json\r\nX-App-Token: %s\r\nContent-Length: 50\r\n\r\n{}"
                             % (self.port, self.port, self.token)).encode())
        self.assertTrue(response.startswith(b"HTTP/1.0 400"), response[:40])
        self.assertFalse(self.vault.status()["locked"])

    def test_non_ascii_token_is_rejected_cleanly(self):
        response = self.raw(b"GET /api/status HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nX-App-Token: \xe9\r\n\r\n" % self.port)
        self.assertTrue(response.startswith(b"HTTP/1.0 403"), response[:40])

    def test_malformed_requests_get_the_same_security_headers(self):
        head = self.raw(b"BREW / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % self.port).split(b"\r\n\r\n", 1)[0]
        self.assertTrue(head.startswith(b"HTTP/1.0 501"), head[:40])
        self.assertIn(b"Content-Security-Policy:", head)
        self.assertIn(b"application/json", head)
