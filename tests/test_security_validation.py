"""Security-claim validation with synthetic data, disposable vaults and in-memory or file-backed
fake key stores. Never touches the user's Keychain, data directory or a non-loopback host.

Each class maps to a row of docs/SECURITY_VALIDATION.md.
"""
import contextlib
import io
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import MagicMock, patch

try:
    from privacy_cleanup.vault import WRAP_LENGTH, WRAPPED, Vault
except ImportError:
    raise unittest.SkipTest("Security validation tests require the encryption dependency on Python 3.12+")

from privacy_cleanup import private_server, server as demo_server
from privacy_cleanup.cases import Cases
from privacy_cleanup.domain import RuleError
from privacy_cleanup.private_server import create_server
import test_private
from test_private import CREATE, FAST, LEGACY_PROFILE, PASS, PROFILE, TMP, MemoryKeys, make_legacy
from test_cases import VALUES

ROOT = Path(__file__).resolve().parent.parent
GET_ROUTES = ["/api/status", "/api/brokers", "/api/profile", "/api/cases", "/api/submissions", "/api/unknown"]
POST_ROUTES = ["/api/create", "/api/unlock", "/api/passphrase", "/api/lock", "/api/touch", "/api/save",
               "/api/upgrade", "/api/delete", "/api/cases/create", "/api/cases/command", "/api/workflow",
               "/api/execution", "/api/sender", "/api/unknown"]


def raw_status(port, method, path, headers, body=b""):
    """One request with exactly these header lines (no client-added Host/Origin)."""
    lines = ["%s %s HTTP/1.1" % (method, path)] + ["%s: %s" % h for h in headers]
    if method == "POST":
        lines.append("Content-Length: %d" % len(body))
    lines.append("Connection: close")
    data = ("\r\n".join(lines) + "\r\n\r\n").encode() + body
    with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
        sock.sendall(data)
        reply = b""
        while chunk := sock.recv(65536):
            reply += chunk
    return int(reply.split(b" ", 2)[1]), reply


def rejected_variants(port, token, mutation):
    """Header sets that must all be refused before any state access."""
    host, origin = "127.0.0.1:%d" % port, "http://127.0.0.1:%d" % port
    good = [("Host", host), ("Origin", origin), ("X-App-Token", token), ("Content-Type", "application/json")]

    def swap(name, value):
        return [(k, v) for k, v in good if k != name] + ([(name, value)] if value is not None else [])

    variants = {
        "missing Host": swap("Host", None),
        "foreign Host": swap("Host", "attacker.invalid"),
        "rebinding Host with port": swap("Host", "attacker.invalid:%d" % port),
        "localhost Host": swap("Host", "localhost:%d" % port),
        "IPv6 loopback Host": swap("Host", "[::1]:%d" % port),
        "other loopback address": swap("Host", "127.0.0.2:%d" % port),
        "Host without port": swap("Host", "127.0.0.1"),
        "Host for another local port": swap("Host", "127.0.0.1:%d" % (port + 1 if port < 65535 else port - 1)),
        "foreign Origin": swap("Origin", "https://attacker.invalid"),
        "null Origin": swap("Origin", "null"),
        "other local app Origin": swap("Origin", "http://127.0.0.1:%d" % (port + 1 if port < 65535 else port - 1)),
        "localhost Origin": swap("Origin", "http://localhost:%d" % port),
        "cross-site fetch metadata": good + [("Sec-Fetch-Site", "cross-site")],
        "missing token": swap("X-App-Token", None),
        "wrong token": swap("X-App-Token", "x" * len(token)),
        "token prefix": swap("X-App-Token", token[:-1]),
        "session without token": swap("X-App-Token", None) + [("X-Private-Session", "synthetic-session")],
    }
    if mutation:
        variants["direct client without Origin"] = swap("Origin", None)
    return variants, good


class HTTPTrustBoundaryTests(unittest.TestCase):
    """Every protected route refuses bad Host/Origin/token before touching state."""

    def serve(self, server):
        server.service_actions = lambda: None  # Only request-driven state access is measured.
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        return server.server_port, server.token

    def test_private_routes_reject_before_any_vault_access(self):
        vault = MagicMock()
        port, token = self.serve(create_server(vault, 0))
        checked = 0
        for method, routes in (("GET", GET_ROUTES), ("POST", POST_ROUTES)):
            variants, _ = rejected_variants(port, token, method == "POST")
            for path in routes:
                for name, headers in variants.items():
                    vault.reset_mock()
                    status, reply = raw_status(port, method, path, headers, b"{}")
                    self.assertEqual(status, 403, (method, path, name))
                    self.assertEqual(vault.mock_calls, [], (method, path, name))
                    self.assertNotIn(token.encode(), reply)
                    checked += 1
        self.assertGreater(checked, 300)

    def test_authorized_requests_reach_state_and_unauthenticated_reach_only_static_files(self):
        vault = MagicMock()
        vault.status.return_value = {"mode": "private-local", "locked": True, "initialized": True}
        port, token = self.serve(create_server(vault, 0))
        vault.reset_mock()
        _, good = rejected_variants(port, token, True)
        self.assertEqual(raw_status(port, "GET", "/api/status", good)[0], 200)
        vault.status.assert_called()
        self.assertEqual(raw_status(port, "POST", "/api/lock", good, b"{}")[0], 200)
        vault.lock.assert_called()
        # Loopback reachability without the token: the page and assets only, never the token.
        vault.reset_mock()
        for path in ("/", "/private.js", "/style.css"):
            status, reply = raw_status(port, "GET", path, [("Host", "127.0.0.1:%d" % port)])
            self.assertEqual(status, 200, path)
            self.assertNotIn(token.encode(), reply)
        self.assertEqual(vault.mock_calls, [])

    def test_demo_routes_reject_before_any_store_access(self):
        store = MagicMock()
        port, token = self.serve(demo_server.create_server(store, 0))
        _, good = rejected_variants(port, token, True)
        good = [("X-Demo-Token", v) if k == "X-App-Token" else (k, v) for k, v in good]
        for method, path in (("GET", "/api/state"), ("POST", "/api/action")):
            variants, _ = rejected_variants(port, token, method == "POST")
            for name, headers in variants.items():
                headers = [("X-Demo-Token", v) if k == "X-App-Token" else (k, v) for k, v in headers]
                store.reset_mock()
                self.assertEqual(raw_status(port, method, path, headers, b"{}")[0], 403, (method, path, name))
                self.assertEqual(store.mock_calls, [], (method, path, name))
        store.read.return_value = {"synthetic": True}
        self.assertEqual(raw_status(port, "GET", "/api/state", good)[0], 200)
        store.read.assert_called_once()
        # Documented demo design: the synthetic demo page itself carries its token, so any local
        # process that can reach the port can use the demo API. Private mode never does this.
        status, reply = raw_status(port, "GET", "/", [("Host", "127.0.0.1:%d" % port)])
        self.assertEqual(status, 200); self.assertIn(token.encode(), reply)


class FileKeys(MemoryKeys):
    """Fake key store persisted to a JSON file so a crashed process's keys survive restart."""

    def __init__(self, path):
        super().__init__(); self.path = Path(path)
        if self.path.exists():
            self.values = {k: bytes.fromhex(v) for k, v in json.loads(self.path.read_text()).items()}

    def _flush(self):
        self.path.write_text(json.dumps({k: v.hex() for k, v in self.values.items()}))

    def put(self, identifier, key):
        super().put(identifier, key); self._flush()

    def delete(self, identifier):
        super().delete(identifier); self._flush()


class FailingPut(MemoryKeys):
    fail_put = True

    def put(self, identifier, key):
        if self.fail_put:
            raise RuleError("Synthetic Keychain write failure")
        super().put(identifier, key)


class VaultKeyLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "private"

    def open(self, keys, **kwargs):
        vault = Vault(self.path, keys, kdf_log2n=FAST, **kwargs); self.addCleanup(vault.close)
        return vault

    def test_each_tampered_key_wrap_region_fails_closed_and_recovers_when_restored(self):
        keys = MemoryKeys(); vault = self.open(keys)
        session = vault.unlock(PASS, create=True)["session"]; vault.save(session, PROFILE, 0); vault.lock()
        (name, blob), = keys.values.items()
        self.assertTrue(name.endswith(WRAPPED)); self.assertEqual(len(blob), WRAP_LENGTH)
        flip = lambda i: blob[:i] + bytes([blob[i] ^ 1]) + blob[i + 1:]  # noqa: E731
        tampered = {"magic": flip(0), "kdf cost in range": blob[:4] + bytes([15]) + blob[5:],
                    "kdf cost out of range": blob[:4] + bytes([21]) + blob[5:], "kdf r": blob[:5] + bytes([9]) + blob[6:],
                    "salt": flip(10), "nonce": flip(25), "sealed key": flip(40), "tag": flip(WRAP_LENGTH - 1),
                    "truncated": blob[:-1], "extended": blob + b"\0", "empty": b""}
        for region, value in tampered.items():
            keys.values[name] = value
            vault.failures, vault.retry_at = 0, None
            with self.assertRaises(RuleError) as error:
                vault.unlock(PASS)
            self.assertIsNone(vault.key, region); self.assertIsNone(vault.session, region)
            self.assertNotIn(PASS, str(error.exception))
            self.assertTrue(vault.status()["locked"])
        keys.values[name] = blob
        vault.failures, vault.retry_at = 0, None
        self.assertEqual(vault.unlock(PASS)["profile"], PROFILE)

    def test_wrapped_key_is_bound_to_its_vault_identifier(self):
        keys = MemoryKeys(); vault = self.open(keys)
        vault.unlock(PASS, create=True); vault.lock()
        identifier = vault._meta()[0]
        blob = keys.values.pop(identifier + WRAPPED)
        other = "b" * 32
        with vault.db:
            vault.db.execute("UPDATE meta SET vault_id=? WHERE id=1", (other,))
        keys.values[other + WRAPPED] = blob  # The right passphrase, but a wrap made for another vault.
        with self.assertRaisesRegex(RuleError, "does not unlock"):
            vault.unlock(PASS)
        self.assertIsNone(vault.key)

    def test_records_are_bound_to_the_vault_identifier(self):
        vault = self.open(MemoryKeys())
        session = vault.unlock(PASS, create=True)["session"]; vault.save(session, PROFILE, 0)
        with vault.db:
            vault.db.execute("UPDATE meta SET vault_id=? WHERE id=1", ("c" * 32,))
        with self.assertRaisesRegex(RuleError, "authentication failed"):
            vault.read(session)
        self.assertIsNone(vault.key)

    def test_record_copied_from_another_vault_and_key_is_refused(self):
        first = self.open(MemoryKeys())
        s1 = first.unlock(PASS, create=True)["session"]; first.save(s1, PROFILE, 0)
        row = first.db.execute("SELECT revision, nonce, body FROM records WHERE id='profile'").fetchone()
        other_path = Path(self.tmp.name) / "other"
        second = Vault(other_path, MemoryKeys(), kdf_log2n=FAST); self.addCleanup(second.close)
        s2 = second.unlock(PASS, create=True)["session"]
        with second.db:
            second.db.execute("UPDATE records SET revision=?, nonce=?, body=? WHERE id='profile'", row)
        with self.assertRaisesRegex(RuleError, "authentication failed"):
            second.read(s2)
        self.assertIsNone(second.key)

    def test_keychain_write_failure_during_creation_leaves_an_empty_vault_and_no_key(self):
        keys = FailingPut(); vault = self.open(keys)
        with self.assertRaises(RuleError):
            vault.unlock(PASS, create=True)
        self.assertEqual(keys.values, {})
        self.assertFalse(vault.status()["initialized"]); self.assertIsNone(vault.key)
        self.assertEqual(vault.db.execute("SELECT COUNT(*) FROM records").fetchone()[0], 0)
        keys.fail_put = False
        self.assertIn("session", vault.unlock(PASS, create=True))

    def test_keychain_write_failure_during_legacy_upgrade_keeps_the_old_key_and_stays_locked(self):
        keys = FailingPut(); keys.fail_put = False
        vault = self.open(keys)
        session = vault.unlock(PASS, create=True)["session"]; vault.save(session, PROFILE, 0)
        identifier, raw = make_legacy(vault, keys)
        keys.fail_put = True
        with self.assertRaises(RuleError):
            vault.set_passphrase(PASS)
        self.assertEqual(keys.values, {identifier: raw})
        self.assertIsNone(vault.key); self.assertIsNone(vault.session)
        keys.fail_put = False
        self.assertEqual(vault.set_passphrase(PASS)["profile"], PROFILE)
        self.assertNotIn(identifier, keys.values)

    def test_no_plaintext_data_key_canary_or_passphrase_in_key_store_or_files(self):
        keys = MemoryKeys(); vault = self.open(keys)
        session = vault.unlock(PASS, create=True)["session"]
        vault.save(session, PROFILE, 0)
        cases = Cases(vault, clock=lambda: 1_790_000_000)
        cases.create(session, "epsilon", "", "Synthetic NoteCanary evidence for one fictional adult.", True)
        identifier, raw = make_legacy(vault, keys)
        vault.set_passphrase(PASS)
        data_key = vault.key
        self.assertEqual(data_key, raw)
        vault.lock(); session = vault.unlock(PASS)["session"]; vault.lock()
        for name, value in keys.values.items():
            self.assertTrue(name.endswith(WRAPPED)); self.assertEqual(len(value), WRAP_LENGTH)
            self.assertNotIn(data_key, value); self.assertNotIn(PASS.encode(), value)
        vault.close()
        canaries = [b"CipherCanary", b"cipher-canary", b"NoteCanary", PASS.encode(), data_key]
        files = list(self.path.iterdir())
        self.assertTrue(files)
        for path in files:
            data = path.read_bytes()
            for canary in canaries:
                self.assertNotIn(canary, data, path.name)
                self.assertNotIn(canary.hex().encode(), data, path.name)


class VaultCrashAndConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "private"
        self.key_file = Path(self.tmp.name) / "fake-keys.json"

    def child(self, code):
        script = ("import sys; sys.path[:0] = [%r, %r]\n" % (str(ROOT), str(ROOT / "tests")) +
                  "from test_security_validation import FileKeys\nfrom privacy_cleanup.vault import Vault\n"
                  "from test_private import PASS, PROFILE, FAST\nimport os\n" + code)
        return subprocess.run([sys.executable, "-I", "-c", script, str(self.path), str(self.key_file)],
                              capture_output=True, text=True, timeout=60)

    def test_process_crash_inside_a_write_transaction_rolls_back_cleanly(self):
        # os._exit: abrupt user-space exit without commit; not SIGKILL, power loss or an OS crash.
        result = self.child(
            "v = Vault(sys.argv[1], FileKeys(sys.argv[2]), kdf_log2n=FAST)\n"
            "s = v.unlock(PASS, create=True)['session']; v.save(s, PROFILE, 0)\n"
            "v.db.execute('BEGIN IMMEDIATE')\n"
            "v._write_record('profile', {'profile': None}, 2)\n"
            "v.db.execute('INSERT INTO records VALUES (?, 1, ?, ?)', ('case/' + 'a' * 32, b'n' * 12, b'x'))\n"
            "os._exit(9)\n")
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertTrue((self.path / "vault.sqlite3-journal").exists())  # A hot journal was left behind.
        vault = Vault(self.path, FileKeys(self.key_file), kdf_log2n=FAST); self.addCleanup(vault.close)
        opened = vault.unlock(PASS)
        self.assertEqual(opened["version"], 1)  # The child's committed save; its crashed write is gone.
        self.assertIn(LEGACY_PROFILE["email"], json.dumps(opened["profile"]))
        ids = [r[0] for r in vault.db.execute("SELECT id FROM records")]
        self.assertEqual(ids, ["profile"])
        self.assertEqual(vault.db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        nonces = [r[0] for r in vault.db.execute("SELECT nonce FROM records")]
        ledger = {r[0] for r in vault.db.execute("SELECT nonce FROM used_nonces")}
        self.assertTrue(set(nonces) <= ledger)
        vault.save(opened["session"], opened["profile"], 1)  # Writable again after recovery.

    def test_crash_after_keychain_write_during_creation_is_recoverable(self):
        result = self.child(
            "v = Vault(sys.argv[1], FileKeys(sys.argv[2]), kdf_log2n=FAST)\n"
            "v._open = lambda *a, **k: os._exit(9)\n"
            "v.unlock(PASS, create=True)\n")
        self.assertEqual(result.returncode, 9, result.stderr)
        keys = FileKeys(self.key_file)
        orphan = set(keys.values)
        self.assertEqual(len(orphan), 1)  # A passphrase-wrapped key for a vault with no records.
        vault = Vault(self.path, keys, kdf_log2n=FAST); self.addCleanup(vault.close)
        self.assertFalse(vault.status()["initialized"])
        with self.assertRaises(RuleError):
            vault.unlock(PASS)  # Never adopts the orphaned key as an existing vault.
        session = vault.unlock(PASS, create=True)["session"]
        self.assertNotIn(vault._meta()[0] + WRAPPED, orphan)
        vault.save(session, PROFILE, 0)

    def test_concurrent_writes_keep_unique_nonces_and_one_history_entry_per_success(self):
        vault = Vault(self.path, MemoryKeys(), kdf_log2n=FAST); self.addCleanup(vault.close)
        session = vault.unlock(PASS, create=True)["session"]; vault.save(session, PROFILE, 0)
        cases = Cases(vault, clock=lambda: 1_790_000_000)
        created = cases.create(session, "epsilon", "", "Synthetic first note.", True)
        identifier = created["cases"][0]["id"]

        def note(index):
            for _ in range(200):
                version = next(c for c in cases.state(session)["cases"] if c["id"] == identifier)["version"]
                try:
                    cases.command(session, identifier, version, "note", {"note": "Synthetic note %d" % index})
                    return True
                except RuleError:
                    continue
            return False

        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertTrue(all(pool.map(note, range(40))))
        case = next(c for c in cases.state(session)["cases"] if c["id"] == identifier)
        self.assertEqual(sum(e["kind"] == "note" for e in case["history"]), 40)
        self.assertEqual(case["version"], 41)
        rows = vault.db.execute("SELECT nonce FROM records").fetchall()
        ledger = [r[0] for r in vault.db.execute("SELECT nonce FROM used_nonces")]
        self.assertEqual(len(ledger), len(set(ledger)))
        self.assertTrue({r[0] for r in rows} <= set(ledger))
        # One nonce per encryption: the empty profile at creation, the saved profile, the case and 40 notes.
        self.assertEqual(len(ledger), 1 + 1 + 1 + 40)


class LockingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.mono = self.wall = 1000.0
        self.vault = Vault(Path(self.tmp.name) / "private", MemoryKeys(), kdf_log2n=FAST,
                           clock=lambda: self.mono, wall=lambda: self.wall)
        self.addCleanup(self.vault.close)
        self.server = create_server(self.vault, 0)
        thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        self.addCleanup(lambda: (self.server.shutdown(), self.server.server_close(), thread.join()))
        self.port, self.token = self.server.server_port, self.server.token

    def post(self, path, payload, session=""):
        headers = [("Host", "127.0.0.1:%d" % self.port), ("Origin", "http://127.0.0.1:%d" % self.port),
                   ("X-App-Token", self.token), ("Content-Type", "application/json"), ("X-Private-Session", session)]
        status, reply = raw_status(self.port, "POST", path, headers, json.dumps(payload).encode())
        return status, json.loads(reply.split(b"\r\n\r\n", 1)[1])

    def get(self, path, session=""):
        headers = [("Host", "127.0.0.1:%d" % self.port), ("X-App-Token", self.token), ("X-Private-Session", session)]
        status, reply = raw_status(self.port, "GET", path, headers)
        return status, json.loads(reply.split(b"\r\n\r\n", 1)[1])

    def wait_locked(self):
        deadline = time.monotonic() + 3
        while self.vault.session is not None and time.monotonic() < deadline:
            time.sleep(0.02)
        return self.vault.session is None

    def test_server_locks_on_a_suspend_shaped_clock_gap_without_any_request(self):
        session = self.post("/api/create", CREATE)[1]["session"]
        self.wall += 60  # Wall time advanced while the monotonic clock did not: a sleep/suspend shape.
        self.assertTrue(self.wait_locked())
        self.assertEqual(self.get("/api/profile", session)[0], 409)

    def test_idle_expiry_and_clock_reversal_lock_without_any_request(self):
        for advance in ({"mono": 900, "wall": 900}, {"mono": -1, "wall": 0}, {"mono": 0, "wall": -1}):
            session = self.post("/api/unlock" if self.vault.status()["initialized"] else "/api/create",
                                {"passphrase": PASS} if self.vault.status()["initialized"] else CREATE)[1]["session"]
            self.mono += advance["mono"]; self.wall += advance["wall"]
            self.assertTrue(self.wait_locked(), advance)
            self.assertEqual(self.get("/api/cases", session)[0], 409)

    def test_replaced_session_is_refused_by_every_session_route(self):
        first = self.post("/api/create", CREATE)[1]["session"]
        self.post("/api/save", {"profile": PROFILE, "version": 0}, first)
        second = self.post("/api/unlock", {"passphrase": PASS})[1]["session"]
        self.assertNotEqual(first, second)
        self.assertFalse(self.get("/api/status", first)[1]["session_valid"])
        stale = "Vault is locked or this session expired"
        for path in ("/api/profile", "/api/cases", "/api/submissions"):
            status, body = self.get(path, first)
            self.assertEqual(status, 409, path); self.assertIn(stale, body["error"], path)
        commands = {"/api/touch": {}, "/api/save": {"profile": PROFILE, "version": 1},
                    "/api/upgrade": {"version": 1, "acknowledged": True},
                    "/api/delete": {"confirmation": "DELETE", "version": 1},
                    "/api/cases/create": {"broker": "epsilon", "listing_url": "", "note": "Synthetic.", "self_only": True},
                    "/api/cases/command": {"id": "a" * 32, "version": 0, "action": "note", "data": {"note": "x"}},
                    "/api/workflow": {"version": 0, "profile_version": 1, "action": "pause", "data": {}},
                    "/api/execution": {"id": "a" * 32, "version": 0, "action": "revoke", "data": {}}}
        for path, payload in commands.items():
            status, body = self.post(path, payload, first)
            # The session check itself refused it, not a later version or schema check.
            self.assertEqual(status, 409, path); self.assertIn(stale, body["error"], path)
        self.assertEqual(self.get("/api/profile", second)[1]["version"], 1)  # Nothing changed.
        self.assertEqual(self.get("/api/cases", second)[1]["cases"], [])
        self.assertTrue(self.get("/api/status", second)[1]["session_valid"])


class GuardLimitTests(unittest.TestCase):
    def test_guard_is_not_containment(self):
        """Documents the claim boundary: covered calls are refused, deliberate code is not contained.
        If this ever fails because Python closed the path, review the docs, do not widen claims."""
        code = """
import os, subprocess, sys
from privacy_cleanup.network import install
install()
try:
    subprocess.run(['/usr/bin/true']); print('covered call allowed')
except PermissionError:
    print('covered call refused')
del sys.modules['_posixsubprocess']
import _posixsubprocess
r, w = os.pipe()
pid = _posixsubprocess.fork_exec([b'/usr/bin/true'], [b'/usr/bin/true'], True, (), None, None,
    -1, -1, -1, -1, -1, -1, r, w, True, False, 0, None, None, None, -1, None, False)
print('deliberate bypass started a process' if os.waitpid(pid, 0)[1] == 0 else 'unexpected')
"""
        result = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, %r)\n" % str(ROOT) + code],
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.stdout.split("\n")[:2], ["covered call refused", "deliberate bypass started a process"],
                         result.stderr)


class StartupOrderTests(unittest.TestCase):
    def setUp(self):
        mask = os.umask(0o022); os.umask(mask)
        self.addCleanup(os.umask, mask)  # main() sets the process umask.

    def test_worker_spawns_before_the_guard_and_the_guard_precedes_workspace_and_listener(self):
        order = []
        listener = MagicMock(); listener.serve_forever.side_effect = KeyboardInterrupt
        listener.server_port, listener.token = 1, "synthetic"
        worker = MagicMock(kind="fake", simulated=True)
        with tempfile.TemporaryDirectory(dir=TMP) as temp, \
                patch("sys.argv", ["private", "--synthetic-workspace", "--data-dir", str(Path(temp) / "v"), "--fake-transport", "9"]), \
                patch.object(private_server, "MacKeyStore", side_effect=lambda: order.append("keys")), \
                patch.object(private_server.WorkerClient, "spawn", side_effect=lambda spec: order.append("spawn") or worker), \
                patch.object(private_server, "install", side_effect=lambda: order.append("guard")), \
                patch.object(private_server, "Workspace", side_effect=lambda *a: order.append("workspace") or MagicMock()), \
                patch.object(private_server, "create_server", side_effect=lambda *a: order.append("listener") or listener), \
                contextlib.redirect_stdout(io.StringIO()):
            private_server.main()
        self.assertEqual(order, ["keys", "spawn", "guard", "workspace", "listener"])

    def test_demo_installs_the_guard_before_opening_storage(self):
        order = []
        with tempfile.TemporaryDirectory(dir=TMP) as temp, \
                patch("sys.argv", ["demo", "--data-dir", str(Path(temp) / "d")]), \
                patch.object(demo_server, "install", side_effect=lambda: order.append("guard")), \
                patch.object(demo_server, "Store", side_effect=lambda *a: order.append("store") or MagicMock()), \
                patch.object(demo_server, "create_server", side_effect=lambda *a: order.append("listener") or
                             MagicMock(server_port=1, serve_forever=MagicMock(side_effect=KeyboardInterrupt))), \
                contextlib.redirect_stdout(io.StringIO()):
            demo_server.main()
        self.assertEqual(order, ["guard", "store", "listener"])


if __name__ == "__main__":
    unittest.main()
