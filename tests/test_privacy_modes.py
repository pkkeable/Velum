"""Batch 4 workstream 2: session-only by default, the opt-in encrypted record, and one clean
end-or-delete flow. Synthetic data, memory keys and temporary directories only."""
import http.client
import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

try:
    from privacy_cleanup.vault import WRAPPED, SessionVault, Vault
except ImportError:
    raise unittest.SkipTest("Private tests require the encryption dependency on Python 3.12+")

from privacy_cleanup.domain import RuleError
from privacy_cleanup.gmail import SCOPE
from privacy_cleanup.private_server import create_server
from privacy_cleanup.workspace import Workspace
from test_coverage import JourneyBase
from test_private import FAST, PASS, PROFILE, TMP, MemoryKeys

ACCOUNT = "cipher-canary@example.invalid"


class GmailWorker:
    """Stands in for the sending worker: a Gmail kind that records revocations."""
    kind, simulated, available, google_port = "gmail", True, True, None

    def __init__(self, reachable=True):
        self.reachable, self.revoked = reachable, []

    def revoke(self, token):
        self.revoked.append(token)
        return self.reachable


def connect(store):
    """A synthetic stored Gmail grant, as the OAuth callback would write it."""
    with store.mutex, store.db:
        store.db.execute("BEGIN IMMEDIATE")
        store._write_record("sender", {
            "schema": 1, "kind": "gmail", "client_id": "000000-synthetic", "client_secret": "synthetic-secret",
            "refresh_token": "synthetic-refresh", "account_email": ACCOUNT, "scope": SCOPE,
            "connected_at": "2026-10-11T00:00:00Z", "last_test": None}, 1)


class Clock:
    def __init__(self):
        self.mono = self.wall = 1000.0

    def advance(self, seconds):
        self.mono += seconds
        self.wall += seconds


class ModesBase:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.data = self.root / "record"  # Never created unless the owner chooses a record.
        self.keys, self.clock, self.worker = MemoryKeys(), Clock(), GmailWorker()
        self.session_store = SessionVault(idle_seconds=600, clock=lambda: self.clock.mono, wall=lambda: self.clock.wall)
        self.ws = Workspace(self.data, self.keys, self.worker, session_store=self.session_store,
                            open_vault=lambda path, keys: self.make_vault(path, keys))
        self.addCleanup(self.ws.close)

    def make_vault(self, path, keys):
        Path(path).mkdir(mode=0o700, exist_ok=True)
        return Vault(path, keys, kdf_log2n=FAST, clock=lambda: self.clock.mono, wall=lambda: self.clock.wall)

    def start(self):
        self.token = self.ws.start_session()["session"]
        self.ws.parts.store.save(self.token, PROFILE, 0)
        return self.token


class SessionOnlyTests(ModesBase, unittest.TestCase):
    def test_nothing_is_written_to_disk_or_the_keychain(self):
        before = sorted(os.listdir(self.root))
        status = self.ws.status()
        self.assertIsNone(status["store"])
        self.assertFalse(status["vault_exists"])
        self.start()
        self.ws.parts.cases.create(self.token, "spokeo", "https://www.spokeo.com/synthetic", "Synthetic", True)
        self.assertEqual(self.ws.parts.store.read(self.token)["profile"], PROFILE)
        self.assertEqual(sorted(os.listdir(self.root)), before)
        self.assertFalse(self.data.exists())
        self.assertEqual(self.keys.values, {})
        self.assertIsNone(self.session_store.keys)
        self.assertEqual(self.session_store.db.execute("PRAGMA database_list").fetchone()[2], "")  # In memory.

    def test_ending_erases_everything_and_refuses_the_old_token(self):
        self.start()
        connect(self.session_store)
        result = self.ws.end_session(self.token)
        self.assertTrue(result["revoked"])
        self.assertEqual(self.worker.revoked, ["synthetic-refresh"])
        self.assertEqual(result["ended"], {"reason": "ended", "revoked": True})
        self.assertIsNone(result["store"])
        self.assertEqual(self.session_store.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)
        with self.assertRaises(RuleError):
            self.session_store.read(self.token)
        with self.assertRaises(RuleError):
            self.ws.parts

    def test_ending_needs_the_current_token(self):
        self.start()
        with self.assertRaises(RuleError):
            self.ws.end_session("stale")
        self.assertEqual(self.ws.parts.store.read(self.token)["profile"], PROFILE)

    def test_idle_expiry_revokes_google_then_erases(self):
        self.start()
        connect(self.session_store)
        self.clock.advance(590)
        self.ws.service()
        self.assertEqual(self.ws.status(self.token)["remaining_seconds"], 10)
        self.clock.advance(10)
        self.ws.service()
        self.assertEqual(self.worker.revoked, ["synthetic-refresh"])
        status = self.ws.status(self.token)
        self.assertEqual(status["ended"], {"reason": "idle", "revoked": True})
        self.assertFalse(status["session_valid"])
        self.assertEqual(self.session_store.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)

    def test_idle_expiry_erases_even_when_google_is_unreachable(self):
        self.worker.reachable = False
        self.start()
        connect(self.session_store)
        self.clock.advance(600)
        self.ws.service()
        self.assertEqual(self.ws.status()["ended"], {"reason": "idle", "revoked": False})
        self.assertEqual(self.session_store.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)

    def test_request_expiry_revokes_before_service_runs(self):
        for action in (lambda: self.ws.status(self.token),
                       lambda: self.session_store.read(self.token)):
            self.start()
            connect(self.session_store)
            self.clock.advance(600)
            try:
                action()
            except RuleError:
                pass
            self.assertEqual(self.session_store.ended, {"reason": "idle", "revoked": True})
            self.assertEqual(self.session_store.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)
        self.assertEqual(self.worker.revoked, ["synthetic-refresh"] * 2)

    def test_shutdown_and_replacement_revoke_before_erasing(self):
        self.start()
        connect(self.session_store)
        self.ws.start_session()
        self.assertEqual(self.worker.revoked, ["synthetic-refresh"])
        connect(self.session_store)
        self.ws.close()
        self.assertEqual(self.worker.revoked, ["synthetic-refresh"] * 2)
        self.assertIsNone(self.session_store.key)

    def test_pending_callback_cannot_block_erasure_or_enter_replacement_session(self):
        from urllib.parse import urlencode
        from test_gmail import CLIENT, SECRET, callback
        for action in (self.ws.lock, self.ws.start_session):
            self.start()
            entered, resume = threading.Event(), threading.Event()
            def exchange(request):
                entered.set()
                resume.wait(3)
                return {"outcome": "connected", "refresh_token": "synthetic-late", "account_email": ACCOUNT}
            self.worker.connect = exchange
            gmail = self.ws.session.execution.gmail
            gmail.start(self.token, CLIENT, SECRET)
            port, state = gmail.listener.server_port, gmail.pending["state"]
            request = threading.Thread(target=lambda: callback(port, urlencode({"state": state, "code": "synthetic"})), daemon=True)
            request.start()
            self.assertTrue(entered.wait(2))
            ending = threading.Thread(target=action, daemon=True)
            ending.start()
            ending.join(1)
            try:
                self.assertFalse(ending.is_alive(), "Cleanup must not wait for a callback needing the store lock")
            finally:
                resume.set()
            request.join(3)
            self.assertFalse(request.is_alive())
            self.assertFalse(gmail.connected())
            self.assertIn("synthetic-late", self.worker.revoked)

    def test_activity_keeps_the_session_open(self):
        self.start()
        self.clock.advance(500)
        self.ws.parts.store.touch(self.token)
        self.clock.advance(500)
        self.ws.service()
        self.assertTrue(self.ws.status(self.token)["session_valid"])

    def test_starting_again_erases_the_earlier_session(self):
        first = self.start()
        second = self.ws.start_session()["session"]
        self.assertIsNone(self.ws.parts.store.read(second)["profile"])
        with self.assertRaises(RuleError):
            self.ws.parts.store.read(first)

    def test_an_open_session_blocks_opening_a_record(self):
        self.start()
        for action in (lambda: self.ws.create_vault(PASS), lambda: self.ws.unlock_vault(PASS)):
            with self.assertRaises(RuleError):
                action()
        self.assertFalse(self.data.exists())

    def test_an_unexpected_error_erases_the_session(self):
        self.start()
        self.ws.fail()
        self.assertEqual(self.ws.status()["ended"]["reason"], "error")
        self.assertEqual(self.session_store.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)


class ConvertTests(ModesBase, unittest.TestCase):
    def test_a_session_moves_into_a_new_encrypted_record(self):
        self.start()
        self.ws.parts.cases.create(self.token, "spokeo", "https://www.spokeo.com/synthetic", "Synthetic", True)
        connect(self.session_store)
        result = self.ws.convert(self.token, PASS)
        self.assertEqual(result["profile"], PROFILE)
        self.assertEqual(self.worker.revoked, [])  # The grant moved with the records.
        self.assertEqual(self.ws.status(result["session"])["store"], "vault")
        self.assertEqual(self.session_store.ended, {"reason": "converted", "revoked": None})
        self.assertEqual(self.session_store.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)
        vault = self.ws.vault.store
        cases = self.ws.parts.cases.state(result["session"])["cases"]
        self.assertEqual([c["broker"] for c in cases], ["spokeo"])
        self.assertTrue(self.ws.vault.execution.gmail.connected())
        # The plaintext is nowhere in the database file, and the record reopens with the passphrase.
        raw = (self.data / "vault.sqlite3").read_bytes()
        self.assertNotIn(b"CipherCanary", raw)
        self.assertEqual(len([k for k in self.keys.values if k.endswith(WRAPPED)]), 1)
        vault.lock()
        self.assertEqual(self.ws.unlock_vault(PASS)["profile"], PROFILE)

    def test_conversion_refuses_while_a_send_is_in_flight(self):
        self.start()
        self.ws.session.execution.inflight.add("job")
        with self.assertRaises(RuleError):
            self.ws.convert(self.token, PASS)
        self.assertFalse(self.data.exists())
        self.assertEqual(self.ws.parts.store.read(self.token)["profile"], PROFILE)


class DeleteTests(ModesBase, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.token = self.ws.create_vault(PASS)["session"]
        self.ws.parts.store.save(self.token, PROFILE, 0)
        connect(self.ws.vault.store)

    def test_a_stale_page_is_refused_before_google_is_asked(self):
        for confirmation, version in (("DELETE", 0), ("delete", 1), ("DELETE LOCAL PROFILE", 1)):
            with self.assertRaises(RuleError):
                self.ws.delete_vault(self.token, confirmation, version)
        self.assertEqual(self.worker.revoked, [])
        self.assertEqual(self.ws.parts.store.read(self.token)["profile"], PROFILE)

    def test_delete_revokes_then_erases_records_and_key(self):
        result = self.ws.delete_vault(self.token, "DELETE", 1)
        self.assertTrue(result["revoked"])
        self.assertEqual(self.worker.revoked, ["synthetic-refresh"])
        self.assertEqual(self.keys.values, {})
        self.assertFalse(result["vault_exists"])
        self.assertIsNone(result["store"])
        self.assertEqual(self.ws.vault.store.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)

    def test_delete_finishes_locally_when_google_is_unreachable(self):
        self.worker.reachable = False
        result = self.ws.delete_vault(self.token, "DELETE", 1)
        self.assertFalse(result["revoked"])
        self.assertEqual(self.keys.values, {})

    def test_idle_only_locks_a_record_and_keeps_google_access(self):
        self.clock.advance(900)
        self.ws.service()
        self.assertTrue(self.ws.status()["locked"])
        self.assertEqual(self.worker.revoked, [])
        self.assertEqual(self.ws.unlock_vault(PASS)["profile"], PROFILE)


class OrphanKeyTests(ModesBase, unittest.TestCase):
    def test_creation_removes_a_key_left_by_an_interrupted_creation(self):
        vault = self.make_vault(self.data, self.keys)
        self.addCleanup(vault.close)
        orphan = vault._meta()[0]
        self.keys.values[orphan + WRAPPED] = b"synthetic orphan"
        self.keys.values[orphan] = b"synthetic legacy orphan"
        vault.unlock(PASS, create=True)
        self.assertNotIn(orphan + WRAPPED, self.keys.values)
        self.assertNotIn(orphan, self.keys.values)
        self.assertEqual(list(self.keys.values), [vault._meta()[0] + WRAPPED])

    def test_creation_stops_when_the_orphan_cannot_be_removed(self):
        vault = self.make_vault(self.data, self.keys)
        self.addCleanup(vault.close)
        orphan = vault._meta()[0]
        self.keys.values[orphan + WRAPPED] = b"synthetic orphan"
        self.keys.fail_delete = True
        with self.assertRaises(RuleError):
            vault.unlock(PASS, create=True)
        self.assertFalse(vault.status()["initialized"])


class ModesHTTPTests(ModesBase, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.server = create_server(self.ws, 0, self.worker)
        self.port = self.server.server_port
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.session = ""

    def request(self, path, payload=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        headers = {"X-App-Token": self.server.token, "X-Private-Session": self.session,
                   "Content-Type": "application/json", "Origin": "http://127.0.0.1:%d" % self.port}
        try:
            conn.request("GET" if payload is None else "POST", path, None if payload is None else json.dumps(payload), headers)
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_start_save_and_end_through_http(self):
        status = self.request("/api/status")[1]
        self.assertEqual((status["store"], status["vault_exists"]), (None, False))
        code, result = self.request("/api/start", {})
        self.assertEqual(code, 200)
        self.session = result["session"]
        self.assertEqual(self.request("/api/save", {"profile": PROFILE, "version": 0})[0], 200)
        status = self.request("/api/status")[1]
        self.assertEqual((status["store"], status["session_valid"], status["remaining_seconds"]), ("session", True, 600))
        code, result = self.request("/api/end", {})
        self.assertEqual((code, result["revoked"], result["ended"]["reason"]), (200, None, "ended"))
        self.assertEqual(self.request("/api/profile")[0], 409)
        self.assertFalse(self.data.exists())

    def test_the_bundled_font_is_served_locally_under_the_page_policy(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port)
        try:
            conn.request("GET", "/fonts/EBGaramond-wght.ttf", headers={"Host": "127.0.0.1:%d" % self.port})
            response = conn.getresponse()
            body = response.read()
        finally:
            conn.close()
        self.assertEqual((response.status, response.getheader("Content-Type")), (200, "font/ttf"))
        self.assertEqual(body[:4], b"\x00\x01\x00\x00")
        self.assertIn("font-src 'self'", response.getheader("Content-Security-Policy"))
        self.assertIn("default-src 'none'", response.getheader("Content-Security-Policy"))

    def test_convert_and_delete_through_http(self):
        self.session = self.request("/api/start", {})[1]["session"]
        self.request("/api/save", {"profile": PROFILE, "version": 0})
        bad = {"acknowledged": True, "passphrase": PASS, "confirmation": PASS + "x"}
        self.assertEqual(self.request("/api/convert", bad)[0], 409)
        code, result = self.request("/api/convert", {"acknowledged": True, "passphrase": PASS, "confirmation": PASS})
        self.assertEqual(code, 200)
        self.session = result["session"]
        self.assertEqual(self.request("/api/status")[1]["store"], "vault")
        self.assertEqual(self.request("/api/delete", {"confirmation": "DELETE", "version": 0})[0], 409)
        code, result = self.request("/api/delete", {"confirmation": "DELETE", "version": 1})
        self.assertEqual((code, result["vault_exists"], result["revoked"]), (200, False, None))


class SelfSendTests(JourneyBase, unittest.TestCase):
    """P-1 "Send them yourself": no sender at all; the owner sends from their own mail app."""
    def setUp(self):
        super().setUp()
        self.connect(None)

    def fingerprint(self, broker):
        return self.case(broker)["execution"]["fingerprint"]

    def test_the_owner_reports_sending_an_approved_email(self):
        self.ready("apollo")
        self.run_("self_sent", "apollo", fingerprint=self.fingerprint("apollo"), result="sent")
        case = self.case("apollo")
        self.assertEqual(case["execution_status"], "user_sent")
        self.assertEqual((case["history"][-1]["kind"], case["history"][-1]["provenance"]), ("send_user_sent", "user_reported"))
        self.assertIn("Velum transmitted nothing", case["history"][-1]["note"])
        self.assertEqual(self.plan()["apollo"]["state"], "email_already_sent")
        with self.assertRaises(RuleError):  # Another request to the same broker is blocked.
            self.run_("prepare", "apollo", drop_acknowledged=False)
        self.cases.command(self.session, case["id"], case["version"], "response",
                           {"result": "acknowledged", "note": "Synthetic acknowledgment."})
        self.assertTrue(self.case("apollo")["outcome"]["acknowledged"])

    def test_not_sure_it_went_stays_uncertain_until_checked(self):
        self.ready("apollo")
        self.run_("self_sent", "apollo", fingerprint=self.fingerprint("apollo"), result="unsure")
        case = self.case("apollo")
        self.assertEqual(case["execution_status"], "uncertain")
        self.assertEqual(case["execution"]["result"]["reason"], "owner_unsure")
        self.run_("reconcile", "apollo", result="not_found_in_sent", note="Synthetic: not in Sent.")
        self.assertEqual(self.case("apollo")["execution_status"], "uncertain")
        self.run_("reconcile", "apollo", result="sent_found", note="Synthetic: found it.")
        self.assertEqual(self.case("apollo")["execution_status"], "user_confirmed_sent")

    def test_only_a_current_matching_approval_counts(self):
        self.flow_act("plan")
        self.flow_act("resume")
        self.run_("prepare", "apollo", drop_acknowledged=False)
        with self.assertRaises(RuleError):  # Prepared but not approved.
            self.run_("self_sent", "apollo", fingerprint=self.fingerprint("apollo"), result="sent")
        self.run_("approve", "apollo", fingerprint=self.fingerprint("apollo"), acknowledged=True)
        for bad in ({"fingerprint": "0" * 64, "result": "sent"}, {"fingerprint": self.fingerprint("apollo"), "result": "maybe"}):
            with self.assertRaises(RuleError):
                self.run_("self_sent", "apollo", **bad)
        self.flow_act("pause")
        with self.assertRaises(RuleError):
            self.run_("self_sent", "apollo", fingerprint=self.fingerprint("apollo"), result="sent")
        self.assertEqual(self.case("apollo")["execution_status"], "approved")

    def test_approval_expiry_still_applies(self):
        self.ready("apollo")
        self.time += 24 * 3600
        with self.assertRaises(RuleError):
            self.run_("self_sent", "apollo", fingerprint=self.fingerprint("apollo"), result="sent")


if __name__ == "__main__":
    unittest.main()
