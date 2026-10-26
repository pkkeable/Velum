"""Gmail connection and transport against a local fake Google. No request ever reaches Google."""
import base64
import copy
import email
import email.policy
import http.client
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

try:
    from privacy_cleanup.vault import Vault
except ImportError:
    raise unittest.SkipTest("Gmail tests require the encryption dependency")
from privacy_cleanup import contracts
from privacy_cleanup.cases import Cases
from privacy_cleanup.dispatch import WorkerClient
from privacy_cleanup.domain import RuleError
from privacy_cleanup.engine import ROOT
from privacy_cleanup.execution import Execution
from privacy_cleanup.worker import GmailTransport, id_token_email, mime, transport_for
from privacy_cleanup.workflow import Workflow
from scripts.fake_provider import FakeGoogle
from test_private import FAST, MemoryKeys, PASS, PROFILE, TMP
import test_private

NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc).timestamp()
CLIENT = "123456789-abcdefghijklmnopqrstu.apps.googleusercontent.com"
SECRET = "synthetic-client-secret"
ACCOUNT = PROFILE["emails"][0]["value"]


def b64(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


def self_test(address=ACCOUNT):
    return contracts.render(contracts.contract(contracts.SELF_TEST), {"email": address})


def browse(url):
    """Follow the fake Google consent redirect to the loopback callback, as a browser would."""
    parts = urlsplit(url)
    connection = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    connection.request("GET", parts.path + "?" + parts.query)
    response = connection.getresponse(); response.read()
    target = urlsplit(response.getheader("Location")); connection.close()
    return callback(target.port, target.query)


def callback(port, query, host=None):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    connection.request("GET", "/?" + query, headers={"Host": host or "127.0.0.1:%d" % port})
    response = connection.getresponse(); body = response.read()
    headers = dict(response.getheaders()); connection.close()
    return response.status, headers, body


class MessageTests(unittest.TestCase):
    def test_mime_has_only_the_rendered_headers_and_body(self):
        message = self_test()
        parsed = email.message_from_bytes(mime(message), policy=email.policy.default)
        self.assertEqual((parsed["From"], parsed["To"], parsed["Subject"]), (ACCOUNT, ACCOUNT, "Velum connection test"))
        self.assertIsNone(parsed["Message-ID"])
        self.assertIn("No data broker was contacted", parsed.get_content())
        with self.assertRaises(ValueError):
            mime(dict(message, subject="Hi\r\nBcc: attacker@example.invalid"))

    def test_id_token_claims_are_checked(self):
        good = {"iss": "https://accounts.google.com", "aud": CLIENT, "email": ACCOUNT, "email_verified": True}
        self.assertEqual(id_token_email("h." + b64(good) + ".s", CLIENT), ACCOUNT)
        for change in ({"aud": "someone-else"}, {"iss": "https://attacker.invalid"}, {"email_verified": False},
                       {"email": "not an email"}, {"email": None}):
            self.assertIsNone(id_token_email("h." + b64(dict(good, **change)) + ".s", CLIENT), change)
        for broken in (None, "", "no-dots", "h.%%%.s"):
            self.assertIsNone(id_token_email(broken, CLIENT))


class GmailTransportTests(unittest.TestCase):
    def setUp(self):
        self.google = FakeGoogle(account=ACCOUNT).start(); self.addCleanup(self.google.stop)
        self.google.refresh.add("refresh-synthetic")
        self.authority = {"client_id": CLIENT, "client_secret": SECRET, "refresh_token": "refresh-synthetic", "account_email": ACCOUNT}
        self.transport = GmailTransport.local(self.google.server_port, timeout=2)

    def test_self_test_is_sent_with_a_fresh_access_token(self):
        result = self.transport.send(self_test(), "a" * 32, self.authority)
        self.assertEqual(result, {"outcome": "accepted", "reason": "provider_accepted", "provider_message_id": "gm-1"})
        sent = email.message_from_bytes(self.google.received[0])
        self.assertEqual((sent["To"], sent["From"]), (ACCOUNT, ACCOUNT))

    def test_broker_messages_are_refused_before_contacting_google(self):
        broker = contracts.render(contracts.contract("apollo-delete-v1"), {"full_name": "Avery Example", "email": ACCOUNT})
        self.assertEqual(self.transport.send(broker, "b" * 32, self.authority)["reason"], "refused_broker_sending_disabled")
        self.assertEqual((self.google.received, self.google.access), ([], set()))
        other = dict(self.authority, account_email="someone-else@example.invalid")
        self.assertEqual(self.transport.send(self_test(), "c" * 32, other)["reason"], "refused_broker_sending_disabled")

    def test_outcomes_are_classified_conservatively(self):
        expected = {"invalid_grant": ("not_sent", "authorization_expired"), "send_400": ("not_sent", "provider_rejected_400"),
                    "send_403": ("not_sent", "provider_rejected_403"), "send_429": ("not_sent", "provider_rejected_429"),
                    "send_500": ("uncertain", "provider_status_500"), "send_disconnect": ("uncertain", "interrupted_after_request")}
        for mode, outcome in expected.items():
            self.google.mode = mode
            result = self.transport.send(self_test(), "d" * 32, self.authority)
            self.assertEqual((result["outcome"], result["reason"]), outcome, mode)
        self.assertEqual(len(self.google.received), 2)  # Only the 500 and the disconnect reached "sending".
        closed = FakeGoogle(); port = closed.server_port; closed.server_close()
        result = GmailTransport.local(port, timeout=1).send(self_test(), "e" * 32, self.authority)
        self.assertEqual((result["outcome"], result["reason"]), ("not_sent", "authorization_unavailable"))

    def test_real_gmail_transport_targets_only_google_hosts_over_tls(self):
        transport = transport_for("gmail")
        self.assertEqual(transport.http.network.hostnames, {("oauth2.googleapis.com", 443), ("gmail.googleapis.com", 443)})
        self.assertEqual(transport.http.network.literals, set())
        self.assertTrue(all(secure for _, _, secure in transport.endpoints.values()))
        for spec in ("gmail-local:10.0.0.1:443", "gmail:attacker.invalid", "gmail-local:127.0.0.1:0", "smtp"):
            with self.assertRaises(ValueError):
                transport_for(spec)

    def test_guard_pins_named_hosts_to_their_resolved_addresses(self):
        code = """
import sys
from privacy_cleanup.worker import GmailTransport, install_guard
network = install_guard(GmailTransport.network_for(GmailTransport.GOOGLE))
sys.audit('socket.getaddrinfo', 'oauth2.googleapis.com', 443, 0, 0, 0)
sys.audit('socket.getaddrinfo', 'gmail.googleapis.com', 443, 0, 0, 0)
for args in (('example.com', 443), ('oauth2.googleapis.com', 80), ('gmail.googleapis.com.attacker.invalid', 443)):
    try: sys.audit('socket.getaddrinfo', *args, 0, 0, 0)
    except PermissionError: pass
    else: raise AssertionError('resolved ' + repr(args))
try: sys.audit('socket.connect', None, ('203.0.113.5', 443))
except PermissionError: pass
else: raise AssertionError('unpinned connect allowed')
network.pinned.add(('203.0.113.5', 443))
sys.audit('socket.connect', None, ('203.0.113.5', 443))
try: sys.audit('socket.connect', None, ('203.0.113.5', 80))
except PermissionError: pass
else: raise AssertionError('wrong port allowed')
print('pinned')
"""
        result = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "pinned")


class ConnectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vault"
        self.vault = Vault(self.path, MemoryKeys(), kdf_log2n=FAST); self.addCleanup(lambda: self.vault.close())
        self.session = self.vault.unlock(PASS, create=True)["session"]
        identity = copy.deepcopy(PROFILE); identity["residence"] = {"country": "US", "region": "NY"}
        self.vault.save(self.session, identity, 0)
        self.google = FakeGoogle(account=ACCOUNT).start(); self.addCleanup(self.google.stop)
        self.worker = WorkerClient.spawn("gmail-local:127.0.0.1:%d" % self.google.server_port); self.addCleanup(self.worker.close)
        self.cases = Cases(self.vault, clock=lambda: NOW)
        self.execution = Execution(self.vault, self.cases, self.worker)
        self.flow = Workflow(self.vault, self.cases)
        self.connector = self.execution.gmail
        self.addCleanup(self.connector.close_listener)

    def sender(self):
        return self.cases.state(self.session)["sender"]

    def connect(self):
        url = self.connector.start(self.session, CLIENT, SECRET)["authorize_url"]
        return url, browse(url)

    def test_connect_stores_only_an_encrypted_grant_for_the_verified_account(self):
        url, (status, headers, body) = self.connect()
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["scope"], ["openid email https://www.googleapis.com/auth/gmail.send"])
        self.assertEqual((query["code_challenge_method"], query["response_type"]), (["S256"], ["code"]))
        self.assertTrue(query["redirect_uri"][0].startswith("http://127.0.0.1:"))
        self.assertEqual(status, 200)
        self.assertIn("default-src 'none'", headers["Content-Security-Policy"])
        self.assertEqual(headers["Cache-Control"], "no-store")
        sender = self.sender()
        self.assertEqual((sender["kind"], sender["configured"], sender["account"], sender["broker_sending"]),
                         ("gmail", True, ACCOUNT, False))
        self.assertEqual(sender["gmail"]["flow"]["state"], "connected")
        for item in self.path.iterdir():
            data = item.read_bytes()
            for value in ("refresh-1", SECRET, CLIENT):
                self.assertNotIn(value.encode(), data, "Sender grant leaked to disk")
        with self.assertRaisesRegex(RuleError, "already connected"):
            self.connector.start(self.session, CLIENT, SECRET)

    def test_stray_or_forged_callbacks_are_ignored(self):
        url = self.connector.start(self.session, CLIENT, SECRET)["authorize_url"]
        port = urlsplit(parse_qs(urlsplit(url).query)["redirect_uri"][0]).port
        self.assertEqual(callback(port, "state=guessed&code=attacker-code")[0], 400)
        self.assertEqual(callback(port, "code=attacker-code")[0], 400)
        self.assertEqual(callback(port, "state=x", host="localhost:%d" % port)[0], 403)
        self.assertEqual(self.sender()["gmail"]["flow"]["state"], "waiting")
        self.assertEqual(browse(url)[0], 200)
        self.assertTrue(self.sender()["configured"])

    def test_declined_consent_or_unexpected_grants_store_nothing(self):
        for mode, reason in (("deny_consent", "consent_declined"), ("wrong_audience", "unverified_account"),
                             ("unverified_email", "unverified_account"), ("broad_scope", "unexpected_scope"),
                             ("no_refresh", "no_refresh_token"), ("reject_code", "code_rejected")):
            self.google.mode = mode
            self.connect()
            sender = self.sender()
            self.assertEqual((sender["configured"], sender["gmail"]["flow"]["reason"]), (False, reason), mode)
        with self.assertRaisesRegex(RuleError, "Client ID"):
            self.connector.start(self.session, "not-a-client-id", SECRET)

    def test_grant_completed_while_locked_is_revoked_not_kept(self):
        url = self.connector.start(self.session, CLIENT, SECRET)["authorize_url"]
        self.vault.lock()
        self.assertEqual(browse(url)[0], 200)
        self.assertEqual(self.connector.flow, {"state": "failed", "reason": "vault_locked"})
        self.assertEqual(self.google.revoked, ["refresh-1"])
        self.session = self.vault.unlock(PASS)["session"]
        self.assertFalse(self.sender()["configured"])

    def test_self_test_sends_to_the_account_and_broker_sending_stays_locked(self):
        self.connect()
        result = self.execution.test_send(self.session, True)["test_result"]
        self.assertEqual((result["outcome"], result["provider_message_id"]), ("accepted", "gm-1"))
        sent = email.message_from_bytes(self.google.received[0])
        self.assertEqual((sent["To"], sent["From"], sent["Subject"]), (ACCOUNT, ACCOUNT, "Velum connection test"))
        self.assertEqual(self.sender()["gmail"]["last_test"]["outcome"], "accepted")
        with self.assertRaises(RuleError):
            self.execution.test_send(self.session, False)
        self.flow.command(self.session, 0, self.cases.state(self.session)["profile_version"], "plan", {})
        state = self.cases.state(self.session)
        self.flow.command(self.session, state["workflow"]["version"], state["profile_version"], "resume", {})
        case = next(c for c in self.cases.state(self.session)["cases"] if c["broker"] == "apollo")
        self.execution.command(self.session, case["id"], case["version"], "prepare", {"drop_acknowledged": False})
        case = next(c for c in self.cases.state(self.session)["cases"] if c["broker"] == "apollo")
        fp = case["execution"]["fingerprint"]
        self.execution.command(self.session, case["id"], case["version"], "approve", {"fingerprint": fp, "acknowledged": True})
        case = next(c for c in self.cases.state(self.session)["cases"] if c["broker"] == "apollo")
        with self.assertRaisesRegex(RuleError, "not enabled"):
            self.execution.command(self.session, case["id"], case["version"], "dispatch", {"fingerprint": fp})
        case = next(c for c in self.cases.state(self.session)["cases"] if c["broker"] == "apollo")
        self.assertEqual(case["execution_status"], "approved")
        self.assertEqual(len(self.google.received), 1)

    def test_disconnect_removes_the_grant_and_revokes_it(self):
        self.connect()
        self.assertTrue(self.connector.disconnect(self.session))
        self.assertEqual(self.google.revoked, ["refresh-1"])
        self.assertFalse(self.sender()["configured"])
        with self.assertRaisesRegex(RuleError, "Connect your Gmail"):
            self.execution.test_send(self.session, True)
        with self.assertRaisesRegex(RuleError, "No Gmail"):
            self.connector.disconnect(self.session)


class GmailHTTPTests(unittest.TestCase):
    stop = test_private.PrivateHTTPTests.stop
    request = test_private.PrivateHTTPTests.request

    def setUp(self):
        self.google = FakeGoogle(account=ACCOUNT).start(); self.addCleanup(self.google.stop)
        self.worker = WorkerClient.spawn("gmail-local:127.0.0.1:%d" % self.google.server_port); self.addCleanup(self.worker.close)
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.vault = Vault(Path(self.tmp.name) / "private", MemoryKeys(), kdf_log2n=FAST); self.addCleanup(self.vault.close)
        from privacy_cleanup.private_server import create_server
        with patch("privacy_cleanup.workspace.Cases", side_effect=lambda v: Cases(v, clock=lambda: NOW)):
            self.server = create_server(self.vault, 0, self.worker)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.stop)
        self.port, self.token, self.session = self.server.server_port, self.server.token, None

    def test_sender_api_connects_tests_and_revokes_on_local_deletion(self):
        self.session = self.request("/api/create", test_private.CREATE)[2]["session"]
        self.request("/api/save", {"profile": dict(copy.deepcopy(PROFILE), residence={"country": "US", "region": "NY"}), "version": 0})
        self.assertEqual(self.request("/api/sender", {"action": "connect_start", "data": {"client_id": CLIENT}})[0], 409)
        self.assertEqual(self.request("/api/sender", {"action": "connect_start", "data": {"client_id": CLIENT, "client_secret": SECRET}},
                                      {"X-App-Token": "wrong"})[0], 403)
        status, _, result = self.request("/api/sender", {"action": "connect_start", "data": {"client_id": CLIENT, "client_secret": SECRET}})
        self.assertEqual(status, 200)
        self.assertEqual(browse(result["authorize_url"])[0], 200)
        state = self.request("/api/cases")[2]
        self.assertEqual((state["sender"]["configured"], state["sender"]["account"]), (True, ACCOUNT))
        status, _, result = self.request("/api/sender", {"action": "test_send", "data": {"acknowledged": True}})
        self.assertEqual((status, result["test_result"]["outcome"]), (200, "accepted"))
        version = self.request("/api/profile")[2]["version"]
        self.assertEqual(self.request("/api/delete", {"confirmation": "DELETE", "version": version})[0], 200)
        self.assertEqual(self.google.revoked, ["refresh-1"])
