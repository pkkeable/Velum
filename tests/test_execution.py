"""R3 owner-email execution: synthetic identities, memory keys, a loopback fake provider only."""
import copy
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

try:
    from privacy_cleanup.vault import Vault
except ImportError:
    raise unittest.SkipTest("Execution tests require the encryption dependency")
from privacy_cleanup import contracts, requirements, routes
from privacy_cleanup.cases import Cases
from privacy_cleanup.dispatch import WorkerClient
from privacy_cleanup.domain import RuleError
from privacy_cleanup.engine import ROOT
from privacy_cleanup.execution import Execution
from privacy_cleanup.worker import FakeTransport, Worker
from privacy_cleanup.workflow import Workflow
from scripts.fake_provider import FakeProvider
from test_private import FAST, MemoryKeys, PASS, PROFILE, TMP
import test_private

NOW = datetime(2026, 10, 8, 12, tzinfo=timezone.utc).timestamp()
APOLLO = "apollo-delete-v1"
RECIPIENT = contracts.CONTRACTS[APOLLO]["recipient"]
ACCEPTED = {"outcome": "accepted", "reason": "provider_accepted", "provider_message_id": "stub-1"}
FIELDS = {"full_name": PROFILE["names"][0]["full_name"], "email": PROFILE["emails"][0]["value"]}


class StubWorker:
    """Stands in for WorkerClient where the real subprocess cannot see patched contracts."""
    kind, simulated, google_port = "fake", True, None

    def __init__(self, *results, delay=0.0, hook=None):
        self.results, self.delay, self.hook = list(results) or [ACCEPTED], delay, hook
        self.envelopes, self.available = [], True

    def send(self, envelope, timeout=None):
        self.envelopes.append(envelope)
        if self.hook:
            self.hook(envelope)
        time.sleep(self.delay)
        return self.results[min(len(self.envelopes), len(self.results)) - 1]


def synthetic_contract(key, broker, regions=None):
    item = copy.deepcopy(contracts.CONTRACTS[APOLLO])
    item.update(id=key, broker=broker, recipient="privacy@" + broker + ".invalid",
                purpose="Delete my synthetic record at " + broker)
    if regions:
        item["jurisdiction"] = {"countries": ["US"], "us_regions": regions, "basis": "Synthetic state-limited right"}
    route = copy.deepcopy(routes.ROUTES["apollo"])
    route.update(name=broker.title(), contract=key)
    return item, route


class ContractTests(unittest.TestCase):
    def test_render_is_exact_and_fingerprint_binds_every_part(self):
        item = contracts.contract(APOLLO)
        message = contracts.render(item, FIELDS)
        self.assertEqual(message["to"], RECIPIENT)
        self.assertEqual(message["from"], FIELDS["email"])
        self.assertIn("Name: " + FIELDS["full_name"] + "\n", message["body"])
        base = contracts.fingerprint(item, message)
        for key in message:
            changed = dict(message, **{key: message[key] + "x"})
            self.assertNotEqual(contracts.fingerprint(item, changed), base, key)
        for key, value in (("version", item["version"] + 1), ("purpose", "Opt out"), ("method", "web_form")):
            self.assertNotEqual(contracts.fingerprint(dict(item, **{key: value}), message), base, key)
        literal = contracts.render(item, dict(FIELDS, full_name="Avery {email} Example"))
        self.assertIn("Name: Avery {email} Example", literal["body"])
        for bad in (dict(FIELDS, full_name="Avery\r\nBcc: x@example.invalid"), dict(FIELDS, full_name="Tab\there"),
                    dict(FIELDS, email="not an email"), dict(FIELDS, email="a@b"), {"full_name": "Only name"},
                    dict(FIELDS, extra="x"), dict(FIELDS, full_name=" padded ")):
            with self.assertRaises(RuleError):
                contracts.render(item, bad)

    def test_jurisdiction_rules_fail_closed_only_where_restricted(self):
        apollo = contracts.contract(APOLLO)
        limited, _ = synthetic_contract("synth-ca-v1", "synthca", ["CA", "California"])
        for residence in ({"country": "", "region": ""}, {"country": "US", "region": "NY"}, {"country": "DE", "region": ""}):
            self.assertIsNone(contracts.eligible(apollo, residence))
        self.assertIsNotNone(contracts.eligible(limited, {"country": "", "region": ""}))
        self.assertIsNotNone(contracts.eligible(limited, {"country": "US", "region": ""}))
        self.assertIsNotNone(contracts.eligible(limited, {"country": "US", "region": "NY"}))
        self.assertIsNone(contracts.eligible(limited, {"country": "US", "region": "california"}))


class RecordingTransport:
    kind, needs_authority = "fake", False

    def __init__(self):
        self.messages = []

    def send(self, message, job_id, authority=None):
        self.messages.append(message)
        return {"outcome": "accepted", "reason": "provider_accepted", "provider_message_id": "rec-%d" % len(self.messages)}


class WorkerTests(unittest.TestCase):
    def envelope(self, **changes):
        item = contracts.contract(APOLLO)
        value = {"job_id": "a" * 32, "contract_id": APOLLO, "contract_version": item["version"], "fields": dict(FIELDS),
                 "fingerprint": contracts.fingerprint(item, contracts.render(item, FIELDS))}
        value.update(changes)
        return value

    def test_worker_sends_only_the_approved_contract_message(self):
        transport = RecordingTransport()
        worker = Worker(transport, sleep=lambda s: None, now=lambda: NOW)
        refusals = {
            "refused_fingerprint_mismatch": self.envelope(job_id="1" * 32, fields=dict(FIELDS, full_name="Someone Else")),
            "refused_unknown_contract": self.envelope(job_id="2" * 32, contract_id="attacker-contract"),
            "refused_contract_changed": self.envelope(job_id="3" * 32, contract_version=contracts.CONTRACTS[APOLLO]["version"] + 1),
            "refused_invalid_fields": self.envelope(job_id="4" * 32, fields={"full_name": "x\ny", "email": FIELDS["email"]}),
            "refused_malformed": dict(self.envelope(job_id="5" * 32), to="attacker@example.invalid"),
        }
        for reason, envelope in refusals.items():
            self.assertEqual(worker.handle({"type": "send", "envelope": envelope}),
                             {"job_id": envelope["job_id"], "outcome": "not_sent", "reason": reason})
        self.assertEqual(transport.messages, [])
        reply = worker.handle({"type": "send", "envelope": self.envelope()})
        self.assertEqual(reply["outcome"], "accepted")
        self.assertEqual(transport.messages[0]["to"], RECIPIENT)
        self.assertEqual(worker.handle({"type": "send", "envelope": self.envelope()})["reason"], "refused_duplicate_job")
        stale = Worker(transport, sleep=lambda s: None, now=lambda: NOW + 31 * 86400)
        self.assertEqual(stale.handle({"type": "send", "envelope": self.envelope(job_id="6" * 32)})["reason"], "refused_source_review_due")
        capped = Worker(transport, sleep=lambda s: None, now=lambda: NOW)
        capped.sent = 50
        self.assertEqual(capped.handle({"type": "send", "envelope": self.envelope(job_id="7" * 32)})["reason"], "refused_send_cap")
        self.assertEqual(len(transport.messages), 1)

    def test_transport_outcomes_are_classified_conservatively(self):
        provider = FakeProvider(hang_seconds=2).start(); self.addCleanup(provider.stop)
        expected = {"accept": "accepted", "reject": "not_sent", "rate_limited": "not_sent", "server_error": "uncertain",
                    "disconnect": "uncertain", "malformed": "uncertain", "oversized": "uncertain",
                    "redirect": "uncertain", "bad_id": "uncertain", "hang": "uncertain"}
        message = contracts.render(contracts.contract(APOLLO), FIELDS)
        for mode, outcome in expected.items():
            provider.mode = mode
            result = FakeTransport("127.0.0.1", provider.server_port, timeout=0.5).send(message, "b" * 32)
            self.assertEqual(result["outcome"], outcome, (mode, result))
        self.assertEqual(sum(m["to"] == RECIPIENT for m in provider.received), len(provider.received))
        closed = FakeProvider(); port = closed.server_port; closed.server_close()
        self.assertEqual(FakeTransport("127.0.0.1", port, timeout=0.5).send(message, "c" * 32)["outcome"], "not_sent")

    def test_worker_guard_allows_one_endpoint_and_nothing_else(self):
        provider = FakeProvider().start(); self.addCleanup(provider.stop)
        other = FakeProvider().start(); self.addCleanup(other.stop)
        code = """
import ctypes, os, socket, subprocess, sys, tempfile
from multiprocessing.util import spawnv_passfds
from privacy_cleanup.worker import install_guard
allowed, other, target = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
install_guard('127.0.0.1', allowed)
socket.create_connection(('127.0.0.1', allowed), timeout=2).close()
denied = [lambda: socket.create_connection(('127.0.0.1', other), timeout=2),
          lambda: socket.getaddrinfo('example.invalid', 443),
          lambda: socket.socket().bind(('127.0.0.1', 0)),
          lambda: subprocess.run(['/usr/bin/true']),
          lambda: spawnv_passfds(b'/usr/bin/true', [b'/usr/bin/true'], ()),
          lambda: os.fork(),
          lambda: open(target, 'w'),
          lambda: ctypes.CDLL(None)]
for op in denied:
    try: op()
    except PermissionError: pass
    else: raise AssertionError('worker guard failed')
print('guarded')
"""
        target = str(Path(tempfile.mkdtemp(dir=TMP)) / "worker-write-test")
        result = subprocess.run([sys.executable, "-c", code, str(provider.server_port), str(other.server_port), target],
                                cwd=str(ROOT), capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "guarded")
        self.assertFalse(Path(target).exists())


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vault"
        self.keys = MemoryKeys()
        self.vault = Vault(self.path, self.keys, kdf_log2n=FAST); self.addCleanup(lambda: self.vault.close())
        self.session = self.vault.unlock(PASS, create=True)["session"]
        self.identity = copy.deepcopy(PROFILE)
        self.identity["residence"] = {"country": "US", "region": "NY"}  # A non-California journey.
        self.vault.save(self.session, self.identity, 0)
        self.time = NOW
        self.connect(StubWorker())

    def connect(self, worker):
        self.worker = worker
        self.cases = Cases(self.vault, clock=lambda: self.time)
        self.execution = Execution(self.vault, self.cases, worker)
        self.flow = Workflow(self.vault, self.cases)

    def state(self):
        return self.cases.state(self.session)

    def case(self, broker="apollo"):
        return next(c for c in self.state()["cases"] if c["broker"] == broker)

    def flow_act(self, action, **data):
        state = self.state()
        if action == "dispatch" and "fingerprints" not in data:
            # What the owner saw in the send confirmation: every approved batch email.
            data["fingerprints"] = [c["execution"]["fingerprint"] for c in state["cases"]
                                    if c.get("execution_status") == "approved"] or ["none"]
        return self.flow.command(self.session, state["workflow"]["version"], state["profile_version"], action, data)

    def run_(self, action, broker="apollo", **data):
        c = self.case(broker)
        return self.execution.command(self.session, c["id"], c["version"], action, data)

    def ready(self, broker="apollo", resume=True):
        if not any(c["broker"] == broker for c in self.state()["cases"]):
            self.flow_act("plan")
        if resume and self.state()["workflow"]["paused"]:
            self.flow_act("resume")
        self.run_("prepare", broker, drop_acknowledged=False)
        fingerprint = self.case(broker)["execution"]["fingerprint"]
        self.run_("approve", broker, fingerprint=fingerprint, acknowledged=True)
        return fingerprint

    def send(self, broker="apollo"):
        return self.run_("dispatch", broker, fingerprint=self.case(broker)["execution"]["fingerprint"])

    def test_end_to_end_with_the_real_worker_process_and_fake_provider(self):
        provider = FakeProvider().start(); self.addCleanup(provider.stop)
        client = WorkerClient.spawn("fake:127.0.0.1:%d" % provider.server_port); self.addCleanup(client.close)
        self.connect(client)
        self.flow_act("plan")
        plan = {p["broker"]: p["state"] for p in self.state()["workflow"]["plan"]}
        self.assertEqual(plan["apollo"], "ready_to_prepare_email")
        self.run_("prepare", drop_acknowledged=False)
        c = self.case()
        self.assertEqual(c["execution_status"], "prepared")
        self.assertEqual(c["execution"]["message"]["to"], RECIPIENT)
        with self.assertRaisesRegex(RuleError, "approval"):
            self.send()
        self.run_("approve", fingerprint=c["execution"]["fingerprint"], acknowledged=True)
        self.flow_act("pause")
        with self.assertRaisesRegex(RuleError, "paused"):
            self.send()
        self.assertEqual(provider.received, [])
        self.flow_act("resume")
        self.assertEqual(self.send()["send_result"]["outcome"], "accepted")
        c = self.case()
        self.assertEqual(c["execution_status"], "transport_accepted")
        self.assertEqual(c["execution"]["result"]["provider_message_id"], "fake-1")
        self.assertEqual(len(provider.received), 1)
        sent = provider.received[0]
        self.assertEqual({k: sent[k] for k in ("from", "to", "subject", "body")}, c["execution"]["message"])
        with self.assertRaises(RuleError):
            self.send()
        with self.assertRaisesRegex(RuleError, "earlier sent"):
            self.run_("prepare", drop_acknowledged=False)
        self.assertEqual(len(provider.received), 1)
        self.assertEqual([e["kind"] for e in c["history"] if e["kind"].startswith("send_")],
                         ["send_prepared", "send_approved", "send_dispatched", "send_transport_accepted"])
        for path in self.path.iterdir():
            data = path.read_bytes()
            for value in (FIELDS["email"], FIELDS["full_name"], "Request to delete my personal information", RECIPIENT):
                self.assertNotIn(value.encode(), data, "Execution plaintext leaked to disk")

    def test_unresponsive_worker_is_uncertain_and_never_reused(self):
        provider = FakeProvider(mode="hang", hang_seconds=3).start(); self.addCleanup(provider.stop)
        client = WorkerClient.spawn("fake:127.0.0.1:%d" % provider.server_port); self.addCleanup(client.close)
        real_send = client.send
        client.send = lambda envelope, timeout=None: real_send(envelope, timeout=1)
        self.connect(client)
        self.ready()
        result = self.send()["send_result"]
        self.assertEqual((result["outcome"], result["reason"]), ("uncertain", "worker_unresponsive"))
        self.assertFalse(client.available)
        self.assertEqual(self.case()["execution_status"], "uncertain")
        self.assertFalse(self.state()["sender"]["configured"])

    def test_double_click_and_concurrent_dispatch_send_once(self):
        self.connect(StubWorker(delay=0.3))
        fingerprint = self.ready()
        c = self.case()
        outcomes = []
        def go():
            try:
                self.execution.command(self.session, c["id"], c["version"], "dispatch", {"fingerprint": fingerprint})
                outcomes.append("sent")
            except RuleError:
                outcomes.append("refused")
        threads = [threading.Thread(target=go) for _ in range(3)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(sorted(outcomes), ["refused", "refused", "sent"])
        self.assertEqual(len(self.worker.envelopes), 1)

    def test_definitive_rejection_needs_fresh_preparation_and_approval(self):
        self.connect(StubWorker({"outcome": "not_sent", "reason": "provider_rejected_400"}, ACCEPTED))
        first = self.ready()
        self.send()
        self.assertEqual(self.case()["execution_status"], "not_sent")
        with self.assertRaises(RuleError):
            self.send()
        self.run_("prepare", drop_acknowledged=False)
        c = self.case()
        self.assertNotEqual(c["execution"]["id"], c["past_executions"][0]["id"])
        self.assertEqual(c["past_executions"][0]["state"], "not_sent")
        self.assertEqual(c["execution_status"], "prepared")
        with self.assertRaises(RuleError):
            self.send()
        self.run_("approve", fingerprint=c["execution"]["fingerprint"], acknowledged=True)
        self.assertEqual(c["execution"]["fingerprint"], first)  # Same exact email, new authorization.
        self.send()
        self.assertEqual(self.case()["execution_status"], "transport_accepted")
        self.assertEqual(len(self.worker.envelopes), 2)

    def test_uncertain_blocks_retry_until_the_owner_reconciles(self):
        self.connect(StubWorker({"outcome": "uncertain", "reason": "interrupted_after_request"}))
        self.ready(); self.send()
        self.assertEqual(self.case()["execution_status"], "uncertain")
        for action, data in (("prepare", {"drop_acknowledged": False}), ("dispatch", {"fingerprint": self.case()["execution"]["fingerprint"]})):
            with self.assertRaises(RuleError):
                self.run_(action, **data)
        with self.assertRaises(RuleError):
            self.run_("reconcile", result="sent_found", note="")
        # Only a provider rejection proves "not sent": not finding it in Sent leaves it uncertain.
        self.run_("reconcile", result="not_found_in_sent", note="Synthetic: not in the Sent folder.")
        self.assertEqual(self.case()["execution_status"], "uncertain")
        self.assertEqual(self.case()["history"][-1]["kind"], "send_not_found_in_sent")
        with self.assertRaisesRegex(RuleError, "may duplicate"):
            self.run_("prepare", drop_acknowledged=False)
        self.run_("prepare", drop_acknowledged=False, duplicate_acknowledged=True)
        job = self.case()["execution"]
        self.assertTrue(job["duplicate_risk_acknowledged"])
        self.assertEqual(self.case()["past_executions"][-1]["state"], "uncertain", "The uncertain email is kept, not rewritten")
        self.assertIn("send_duplicate_risk_acknowledged", [e["kind"] for e in self.case()["history"]])
        self.connect(StubWorker())
        self.run_("approve", fingerprint=job["fingerprint"], acknowledged=True)
        self.send()
        self.assertEqual(self.case()["execution_status"], "transport_accepted")
        with self.assertRaisesRegex(RuleError, "earlier sent"):
            self.run_("prepare", drop_acknowledged=False, duplicate_acknowledged=True)

    def test_crash_before_reservation_sends_nothing_and_after_is_uncertain(self):
        self.ready()
        original = self.execution._store
        def crash(case):
            if case.get("execution", {}).get("state") == "dispatching":
                raise RuntimeError("synthetic crash before commit")
            return original(case)
        with patch.object(self.execution, "_store", side_effect=crash), self.assertRaises(RuntimeError):
            self.send()
        self.assertEqual(self.case()["execution_status"], "approved")
        self.assertEqual(self.worker.envelopes, [])
        def die(envelope):
            raise KeyboardInterrupt  # Process killed while the worker may be transmitting.
        self.connect(StubWorker(hook=die))
        with self.assertRaises(KeyboardInterrupt):
            self.send()
        self.vault.close()
        self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
        self.session = self.vault.unlock(PASS)["session"]
        self.connect(StubWorker())
        self.assertEqual(self.case()["execution_status"], "uncertain")
        with self.assertRaises(RuleError):
            self.send()
        self.assertEqual(self.case()["execution"]["state"], "uncertain")
        self.assertEqual(self.case()["execution"]["result"]["reason"], "interrupted_before_result")
        self.assertEqual(self.worker.envelopes, [])

    def test_lock_during_send_records_the_result_at_next_unlock(self):
        self.connect(StubWorker(hook=lambda envelope: self.vault.lock()))
        self.ready()
        result = self.send()
        self.assertTrue(result["locked"])
        self.assertEqual(result["send_result"]["outcome"], "accepted")
        self.session = self.vault.unlock(PASS)["session"]
        self.assertEqual(self.case()["execution_status"], "transport_accepted")
        with self.assertRaises(RuleError):
            self.run_("revoke")
        self.assertEqual(self.case()["execution"]["state"], "transport_accepted")
        self.assertEqual(self.case()["execution"]["result"]["provider_message_id"], "stub-1")

    def test_approval_invalidated_by_identity_contract_external_history_or_time(self):
        fingerprint = self.ready()
        self.vault.save(self.session, self.identity, self.state()["profile_version"])
        self.assertEqual(self.case()["execution_status"], "invalidated")
        self.ready()
        bumped = dict(contracts.CONTRACTS[APOLLO], version=contracts.CONTRACTS[APOLLO]["version"] + 1)
        with patch.dict(contracts.CONTRACTS, {APOLLO: bumped}):
            self.assertEqual(self.case()["execution_status"], "invalidated")
        self.flow_act("external", broker="drop", purpose="Synthetic DROP request", date="2026-10-01",
                      date_precision="approximate", state="submitted", note="Synthetic DROP history.", self_only=True)
        self.assertEqual(self.case()["execution_status"], "invalidated")
        with self.assertRaisesRegex(RuleError, "DROP"):
            self.run_("prepare", drop_acknowledged=False)
        self.run_("prepare", drop_acknowledged=True)
        self.run_("approve", fingerprint=self.case()["execution"]["fingerprint"], acknowledged=True)
        self.assertEqual(self.case()["execution_status"], "approved")
        self.time = NOW + 24 * 3600
        self.assertEqual(self.case()["execution_status"], "expired")
        self.time = NOW - 1
        self.assertEqual(self.case()["execution_status"], "expired")
        self.assertEqual(self.worker.envelopes, [])
        self.assertEqual(fingerprint, self.case()["execution"]["fingerprint"])

    def test_one_identity_feeds_distinct_contracts_and_jurisdiction_fails_closed_per_route(self):
        ca, ca_route = synthetic_contract("synth-ca-v1", "synthca", ["CA", "California"])
        other, other_route = synthetic_contract("synth-all-v1", "synthall")
        guide = copy.deepcopy(requirements.REQUIREMENTS["apollo"])
        with patch.dict(contracts.CONTRACTS, {"synth-ca-v1": ca, "synth-all-v1": other}), \
                patch.dict(contracts.BY_BROKER, {"synthca": "synth-ca-v1", "synthall": "synth-all-v1"}), \
                patch.dict(routes.ROUTES, {"synthca": ca_route, "synthall": other_route}), \
                patch.dict(requirements.REQUIREMENTS, {"synthca": guide, "synthall": guide}):
            self.flow_act("plan")
            plan = {p["broker"]: p for p in self.state()["workflow"]["plan"]}
            self.assertEqual(plan["synthca"]["state"], "route_not_available_in_jurisdiction")
            self.assertEqual({plan[b]["state"] for b in ("apollo", "synthall")}, {"ready_to_prepare_email"})
            self.assertFalse(any(c["broker"] == "synthca" for c in self.state()["cases"]))
            for broker in ("apollo", "synthall"):
                self.ready(broker)
            recipients = {c["broker"]: c["execution"]["message"]["to"] for c in self.state()["cases"] if c.get("execution")}
            self.assertEqual(recipients, {"apollo": RECIPIENT, "synthall": "privacy@synthall.invalid"})
            self.cases.create(self.session, "synthca", "", "Synthetic CA-only route.", True)
            with self.assertRaisesRegex(RuleError, "state"):
                self.run_("prepare", "synthca", drop_acknowledged=False)
            moved = dict(self.identity, residence={"country": "US", "region": "California"})
            self.vault.save(self.session, moved, self.state()["profile_version"])
            self.run_("prepare", "synthca", drop_acknowledged=False)
            self.assertEqual(self.case("synthca")["execution_status"], "prepared")
            self.assertEqual(self.case("apollo")["execution_status"], "invalidated")

    def test_manual_approval_never_becomes_send_authority(self):
        self.flow_act("plan")
        self.cases.create(self.session, "epsilon", "", "Synthetic manual-route case.", True)
        with self.assertRaisesRegex(RuleError, "guidance only|source review"):
            c = self.case()
            self.cases.command(self.session, c["id"], c["version"], "prepare",
                               {"fields": {"first_name": "Avery", "last_name": "Example", "email": FIELDS["email"]}, "self_only": True})
        with self.assertRaisesRegex(RuleError, "no reviewed sending contract"):
            self.run_("prepare", "epsilon", drop_acknowledged=False)
        with self.assertRaises(RuleError):
            self.run_("dispatch", "epsilon", fingerprint="0" * 64)
        self.assertEqual(self.worker.envelopes, [])

    def test_external_history_blocks_sending_across_paths(self):
        self.flow_act("plan")
        self.flow_act("external", broker="apollo", purpose="Synthetic earlier email", date="2026-10-02",
                      date_precision="exact", state="uncertain", note="Synthetic: sent from another app.", self_only=True)
        with self.assertRaisesRegex(RuleError, "external request"):
            self.run_("prepare", drop_acknowledged=False)
        entry = self.state()["workflow"]["external"][0]
        self.flow_act("reconcile", id=entry["id"], state="not_sent", note="Synthetic: never left the drafts folder.")
        self.ready()
        self.send()
        self.assertEqual(len(self.worker.envelopes), 1)

    def test_batch_dispatch_respects_pause_and_lock_and_continues_after_uncertain(self):
        other, other_route = synthetic_contract("synth-all-v1", "synthall")
        third, third_route = synthetic_contract("synth-more-v1", "synthmore")
        guide = copy.deepcopy(requirements.REQUIREMENTS["apollo"])
        with patch.dict(contracts.CONTRACTS, {"synth-all-v1": other, "synth-more-v1": third}), \
                patch.dict(contracts.BY_BROKER, {"synthall": "synth-all-v1", "synthmore": "synth-more-v1"}), \
                patch.dict(routes.ROUTES, {"synthall": other_route, "synthmore": third_route}), \
                patch.dict(requirements.REQUIREMENTS, {"synthall": guide, "synthmore": guide}):
            self.connect(StubWorker({"outcome": "uncertain", "reason": "interrupted_after_request"}, ACCEPTED, ACCEPTED))
            for broker in ("apollo", "synthall", "synthmore"):
                self.ready(broker)
            self.flow_act("pause")
            with self.assertRaisesRegex(RuleError, "paused"):
                self.flow_act("dispatch")
            self.assertEqual(self.worker.envelopes, [])
            self.flow_act("resume")
            results = self.flow_act("dispatch")["dispatch_results"]
            self.assertEqual([r["outcome"] for r in results], ["uncertain", "accepted", "accepted"])
            self.assertEqual(len(self.worker.envelopes), 3)
            self.assertEqual(self.flow_act("dispatch")["dispatch_results"], [])

    def test_batch_stops_when_paused_or_locked_mid_run(self):
        other, other_route = synthetic_contract("synth-all-v1", "synthall")
        guide = copy.deepcopy(requirements.REQUIREMENTS["apollo"])
        with patch.dict(contracts.CONTRACTS, {"synth-all-v1": other}), \
                patch.dict(contracts.BY_BROKER, {"synthall": "synth-all-v1"}), \
                patch.dict(routes.ROUTES, {"synthall": other_route}), \
                patch.dict(requirements.REQUIREMENTS, {"synthall": guide}):
            for broker in ("apollo", "synthall"):
                self.ready(broker)
            state = self.state()
            pause = lambda envelope: self.flow.command(self.session, -1, -1, "pause", {})  # noqa: E731
            self.connect(StubWorker(hook=pause))
            confirmed = {"fingerprints": [self.case(b)["execution"]["fingerprint"] for b in ("apollo", "synthall")]}
            results = self.flow.command(self.session, state["workflow"]["version"], state["profile_version"], "dispatch", confirmed)["dispatch_results"]
            self.assertEqual(len(results), 1)
            self.assertEqual(len(self.worker.envelopes), 1)
            self.flow_act("resume")
            self.connect(StubWorker(hook=lambda envelope: self.vault.lock()))
            state = self.state()
            results = self.flow.command(self.session, state["workflow"]["version"], state["profile_version"], "dispatch", confirmed)["dispatch_results"]
            self.assertEqual(len(results), 1)
            self.assertEqual(len(self.worker.envelopes), 1)

    # Batch 4, workstream 5: prepare all, approve each, send only what was confirmed.

    def synthetic_routes(self, *brokers):
        items = {b: synthetic_contract("synth-" + b + "-v1", b) for b in brokers}
        guide = copy.deepcopy(requirements.REQUIREMENTS["apollo"])
        return (patch.dict(contracts.CONTRACTS, {item["id"]: item for item, _ in items.values()}),
                patch.dict(contracts.BY_BROKER, {b: item["id"] for b, (item, _) in items.items()}),
                patch.dict(routes.ROUTES, {b: route for b, (_, route) in items.items()}),
                patch.dict(requirements.REQUIREMENTS, {b: guide for b in brokers}))

    def test_prepare_all_prepares_each_ready_email_and_approves_nothing(self):
        a, b, c, d = self.synthetic_routes("synthall", "synthmore")
        with a, b, c, d:
            self.flow_act("plan")
            self.assertFalse(self.state()["workflow"]["paused"], "A new batch starts ready")
            ids = {self.case(x)["id"] for x in ("apollo", "synthall", "synthmore")}
            self.assertEqual(set(self.state()["workflow"]["preparable"]), ids)
            results = self.flow_act("prepare_emails")["prepare_results"]
            self.assertEqual({r["case_id"] for r in results}, ids)
            self.assertTrue(all(r["outcome"] == "prepared" for r in results))
            for broker in ("apollo", "synthall", "synthmore"):
                self.assertEqual(self.case(broker)["execution_status"], "prepared")
                self.assertIsNone(self.case(broker)["execution"]["approval"])
            self.assertEqual(self.state()["workflow"]["preparable"], [])
            self.assertEqual(self.flow_act("prepare_emails")["prepare_results"], [], "Prepared emails are never re-prepared")
            self.assertEqual(self.worker.envelopes, [])

    def test_prepare_all_leaves_a_possible_drop_overlap_for_its_own_review(self):
        self.flow_act("plan")
        self.flow_act("external", broker="drop", purpose="Synthetic DROP request", date="2026-10-01",
                      date_precision="approximate", state="submitted", note="Synthetic DROP history.", self_only=True)
        self.assertEqual(self.state()["workflow"]["preparable"], [])
        self.assertEqual(self.flow_act("prepare_emails")["prepare_results"], [])
        self.assertEqual(self.case()["execution_status"], "not_prepared")

    def test_prepare_all_rejects_stale_revisions_and_extra_fields(self):
        self.flow_act("plan")
        state = self.state()
        with self.assertRaisesRegex(RuleError, "changed"):
            self.flow.command(self.session, state["workflow"]["version"] - 1, state["profile_version"], "prepare_emails", {})
        with self.assertRaisesRegex(RuleError, "fields"):
            self.flow.command(self.session, state["workflow"]["version"], state["profile_version"], "prepare_emails", {"approve": True})
        self.assertEqual(self.case()["execution_status"], "not_prepared")

    def test_batch_send_transmits_only_the_emails_the_owner_confirmed(self):
        a, b, c, d = self.synthetic_routes("synthall")
        with a, b, c, d:
            self.ready("apollo")
            shown = [self.case("apollo")["execution"]["fingerprint"]]  # The confirmation listed Apollo only.
            self.ready("synthall")  # Approved after the confirmation was shown.
            for bad in ([], "f", [1], shown * 2, ["x"] * 51):
                with self.assertRaisesRegex(RuleError, "Confirm"):
                    self.flow_act("dispatch", fingerprints=bad)
            self.assertEqual(self.worker.envelopes, [])
            results = self.flow_act("dispatch", fingerprints=shown)["dispatch_results"]
            self.assertEqual([r["case_id"] for r in results], [self.case("apollo")["id"]])
            self.assertEqual(len(self.worker.envelopes), 1)
            self.assertEqual(self.case("synthall")["execution_status"], "approved", "Unconfirmed emails stay unsent")
            stale = self.flow_act("dispatch", fingerprints=["0" * 64])["dispatch_results"]
            self.assertEqual(stale, [], "A fingerprint that no longer matches an approved email sends nothing")
            self.assertEqual(len(self.worker.envelopes), 1)


class ExecutionHTTPTests(unittest.TestCase):
    stop = test_private.PrivateHTTPTests.stop
    request = test_private.PrivateHTTPTests.request

    def setUp(self):
        with patch("privacy_cleanup.workspace.Cases", side_effect=lambda v: Cases(v, clock=lambda: NOW)):
            self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
            self.vault = Vault(Path(self.tmp.name) / "private", MemoryKeys(), kdf_log2n=FAST); self.addCleanup(self.vault.close)
            from privacy_cleanup.private_server import create_server
            self.worker = StubWorker()
            self.server = create_server(self.vault, 0, self.worker)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.addCleanup(self.stop)
        self.port, self.token, self.session = self.server.server_port, self.server.token, None

    def test_execution_endpoint_is_authenticated_bounded_and_complete(self):
        self.session = self.request("/api/create", test_private.CREATE)[2]["session"]
        identity = dict(copy.deepcopy(PROFILE), residence={"country": "US", "region": "NY"})
        self.request("/api/save", {"profile": identity, "version": 0})
        state = self.request("/api/cases")[2]
        self.assertEqual(state["sender"], {"configured": True, "kind": "fake", "simulated": True,
                                           "broker_sending": True, "account": None, "gmail": None})
        state = self.request("/api/workflow", {"version": state["workflow"]["version"], "profile_version": state["profile_version"], "action": "plan", "data": {}})[2]
        state = self.request("/api/workflow", {"version": state["workflow"]["version"], "profile_version": state["profile_version"], "action": "resume", "data": {}})[2]
        c = next(c for c in state["cases"] if c["broker"] == "apollo")
        body = {"id": c["id"], "version": c["version"], "action": "prepare", "data": {"drop_acknowledged": False}}
        for headers in ({"X-App-Token": "wrong"}, {"Origin": "https://attacker.invalid"}):
            self.assertEqual(self.request("/api/execution", body, headers)[0], 403)
        self.assertEqual(self.request("/api/execution", dict(body, data={"drop_acknowledged": False, "to": "x"}))[0], 409)
        c = next(c for c in self.request("/api/execution", body)[2]["cases"] if c["broker"] == "apollo")
        fp = c["execution"]["fingerprint"]
        c = next(c for c in self.request("/api/execution", {"id": c["id"], "version": c["version"], "action": "approve",
                                                            "data": {"fingerprint": fp, "acknowledged": True}})[2]["cases"] if c["broker"] == "apollo")
        status, _, result = self.request("/api/execution", {"id": c["id"], "version": c["version"], "action": "dispatch", "data": {"fingerprint": fp}})
        self.assertEqual((status, result["send_result"]["outcome"]), (200, "accepted"))
        self.assertEqual(len(self.worker.envelopes), 1)
        self.request("/api/lock", {})
        self.assertEqual(self.request("/api/execution", {"id": c["id"], "version": c["version"] + 3, "action": "dispatch", "data": {"fingerprint": fp}})[0], 409)
        self.assertEqual(len(self.worker.envelopes), 1)
