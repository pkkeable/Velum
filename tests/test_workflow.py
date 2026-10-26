"""R2 synthetic journeys. Memory key store; no broker or native Keychain traffic."""
import copy
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

try:
    from privacy_cleanup.vault import SCHEMA, Vault
except ImportError:
    raise unittest.SkipTest("Workflow tests require the encryption dependency")
from privacy_cleanup.cases import Cases
from privacy_cleanup.domain import RuleError
from privacy_cleanup.identity import entry
from privacy_cleanup.requirements import REQUIREMENTS
from privacy_cleanup.routes import ROUTES
from privacy_cleanup.workflow import Workflow, drop_status, mapping, read
from test_private import FAST, MemoryKeys, PASS, PROFILE, TMP
import test_private


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vault"
        self.keys = MemoryKeys()
        self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
        self.addCleanup(lambda: self.vault.close())
        self.session = self.vault.unlock(PASS, create=True)["session"]
        self.profile = copy.deepcopy(PROFILE)
        self.profile["names"][0].update(first_name="Avery", last_name="Example")
        self.profile["residence"] = {"country": "US", "region": "CA"}
        self.vault.save(self.session, self.profile, 0)
        self.time = datetime(2026, 10, 7, 12, tzinfo=timezone.utc).timestamp()
        self.connect()

    def connect(self):
        self.cases = Cases(self.vault, clock=lambda: self.time)
        self.flow = Workflow(self.vault, self.cases)

    def state(self):
        return self.cases.state(self.session)

    def act(self, action, **data):
        state = self.state()
        return self.flow.command(self.session, state["workflow"]["version"], state["profile_version"], action, data)

    def case(self, broker="epsilon"):
        return next(c for c in self.state()["cases"] if c["broker"] == broker)

    def command(self, action, broker="epsilon", **data):
        case = self.case(broker)
        return self.cases.command(self.session, case["id"], case["version"], action, data)

    def prepare(self, broker="epsilon", ack=False):
        c = self.case(broker)
        self.act("prepare", id=c["id"], case_version=c["version"], drop_acknowledged=ack)
        return self.case(broker)["request"]["fingerprint"]

    def approve(self, broker="epsilon", ack=False):
        fingerprint = self.prepare(broker, ack)
        self.command("approve", broker, fingerprint=fingerprint, acknowledged=True)
        return fingerprint

    def external(self, broker="epsilon", state="uncertain"):
        return self.act("external", broker=broker, purpose="Synthetic deletion request", date="2026-10-06",
                        date_precision="approximate", state=state, note="ExternalCanary fictional evidence only.", self_only=True)

    def test_shared_form_builds_minimal_batch_without_approval_and_repeat_is_idempotent(self):
        self.act("plan")
        case = self.case(); self.assertIsNone(case["request"])
        self.assertFalse(self.state()["workflow"]["paused"], "A new batch starts ready")
        self.act("pause"); self.act("plan"); self.assertEqual(len(self.state()["cases"]), 1)
        self.assertTrue(self.state()["workflow"]["paused"], "A refresh keeps the owner's own pause")
        self.act("resume"); self.act("plan")
        self.assertFalse(self.state()["workflow"]["paused"])
        self.prepare(); snapshot = self.case()["request"]["snapshot"]
        self.assertEqual(set(snapshot["fields"]), {"first_name", "last_name", "email", "country", "request_type"})
        self.assertEqual(set(snapshot["identifiers"]), {"first_name", "last_name", "email"})
        self.assertIsNone(self.case()["request"]["approval"])
        self.assertFalse(self.state()["automatic_submission"])
        self.assertTrue(all(p["state"] != "ready_for_local_preparation" for p in self.state()["workflow"]["plan"] if p["broker"] != "epsilon"))

    def test_ca_and_other_state_and_unknown_do_not_share_eligibility(self):
        self.assertEqual(drop_status(self.profile), "eligible_self_reported")
        for region in ("California", " ca "):
            self.profile["residence"]["region"] = region
            self.assertEqual(drop_status(self.profile), "eligible_self_reported")
        self.profile["residence"]["region"] = "NY"
        self.vault.save(self.session, self.profile, 1)
        self.assertEqual(self.state()["workflow"]["drop"]["state"], "not_eligible")
        self.act("plan"); self.prepare()  # US draft still works for another state.
        self.profile["residence"]["region"] = ""
        self.assertEqual(drop_status(self.profile), "needs_residence")
        self.profile["addresses"][0]["region"] = "California"
        self.assertEqual(drop_status(self.profile), "needs_residence")
        self.profile["residence"] = {"country": "GB", "region": "CA"}
        self.assertEqual(drop_status(self.profile), "not_eligible")

    def test_ambiguous_inaccessible_retired_or_missing_values_need_shared_form_edit(self):
        p = copy.deepcopy(self.profile)
        p["emails"][0]["preferred"] = False
        p["emails"].append(entry("emails", value="second@example.invalid", reachable=True))
        self.assertTrue(mapping(p, ROUTES["epsilon"])[2])
        p["emails"][1]["preferred"] = True
        self.assertEqual(mapping(p, ROUTES["epsilon"])[0]["email"], "second@example.invalid")
        p["emails"][1]["retired"] = True; p["emails"][0]["reachable"] = False
        self.assertNotIn("email", mapping(p, ROUTES["epsilon"])[0])
        p["names"][0]["last_name"] = ""
        self.assertNotIn("last_name", mapping(p, ROUTES["epsilon"])[0])

    def test_pause_blocks_direct_case_api_bypass_but_allows_dry_run_and_resume(self):
        self.act("plan"); fp = self.approve(); self.act("pause")
        with self.assertRaisesRegex(RuleError, "paused"):
            self.command("handoff", fingerprint=fp, dry_run=False)
        self.command("handoff", fingerprint=fp, dry_run=True)
        self.assertIsNone(self.case()["attempt"])
        self.act("resume"); self.command("handoff", fingerprint=fp, dry_run=False)
        with self.assertRaises(RuleError): self.command("handoff", fingerprint=fp, dry_run=False)
        self.act("pause")
        self.command("outcome", result="uncertain", note="Synthetic ambiguous handoff.")
        with self.assertRaises(RuleError): self.prepare()

    # Review R2-L1: pausing is the safety stop and must not be refusable.

    def test_pause_succeeds_at_history_limit_with_stale_revisions_and_incomplete_identity(self):
        self.act("plan"); self.act("resume")
        body, revision = read(self.vault)
        body["history"] = (body["history"] * 1000)[:1000]
        with self.vault.db:
            self.vault.db.execute("BEGIN IMMEDIATE"); self.vault._write_record("workflow", body, revision + 1)
        identity = copy.deepcopy(self.profile); identity["self_adult"] = False
        self.vault.save(self.session, identity, self.state()["profile_version"])
        with self.assertRaises(RuleError): self.act("resume")
        self.flow.command(self.session, -1, -1, "pause", {})
        body, after = read(self.vault)
        self.assertTrue(body["paused"]); self.assertEqual((len(body["history"]), after), (1001, revision + 2))
        self.flow.command(self.session, -1, -1, "pause", {})
        self.assertEqual(read(self.vault)[1], after)
        self.assertEqual(len(read(self.vault)[0]["history"]), 1001)
        with self.assertRaises(RuleError): self.act("resume")

    def test_pause_needs_a_session_and_never_writes_a_workflow_record_to_an_older_store(self):
        with self.assertRaises(RuleError): self.flow.command("not-a-session", 0, 0, "pause", {})
        with self.vault.db: self.vault.db.execute("PRAGMA user_version=3")
        self.assertTrue(self.vault.needs_upgrade())
        self.assertTrue(self.flow.command(self.session, 0, 0, "pause", {})["workflow"]["migration_required"])
        self.assertIsNone(self.vault.db.execute("SELECT 1 FROM records WHERE id='workflow'").fetchone())

    def test_three_distinct_mock_routes_partial_completion_survives_restart(self):
        routes, rules = {}, {}
        for number in range(2):
            key = "mock" + str(number)
            routes[key] = copy.deepcopy(ROUTES["epsilon"])
            routes[key].update(name="Synthetic mock " + str(number), destination="https://example.invalid/mock" + str(number))
            routes[key]["required_for_preparation"] = ["email"] if number == 0 else ["first_name", "email", "city"]
            rules[key] = copy.deepcopy(REQUIREMENTS["epsilon"])
        with patch.dict(ROUTES, routes), patch.dict(REQUIREMENTS, rules):
            self.act("plan"); self.assertEqual(len(self.state()["cases"]), 3)
            self.act("resume")
            for broker, result in [("epsilon", "uncertain"), ("mock0", "submitted"), ("mock1", "not_disclosed")]:
                fp = self.approve(broker)
                self.command("handoff", broker, fingerprint=fp, dry_run=False)
                self.command("outcome", broker, result=result, note="Synthetic route evidence.")
            self.command("response", "mock0", result="verification_required", note="Fictional verification requested.")
            self.act("pause")
            self.vault.close(); self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
            self.session = self.vault.unlock(PASS)["session"]; self.connect()
            counts = self.state()["workflow"]["counts"]
            self.assertEqual(counts["reconcile_uncertain"], 1)
            self.assertEqual(counts["waiting_for_verification"], 1)
            self.assertTrue(self.state()["workflow"]["paused"])
            with self.assertRaises(RuleError): self.prepare("epsilon")
            self.prepare("mock1")
            self.assertIsNone(self.case("mock1")["request"]["approval"])
            self.assertEqual(len(self.case("mock1")["past_attempts"]), 1)

    def test_profile_source_change_and_old_workflow_versions_fail_closed(self):
        old = self.state(); self.act("plan")
        with self.assertRaisesRegex(RuleError, "changed"):
            self.flow.command(self.session, old["workflow"]["version"], old["profile_version"], "resume", {})
        self.approve(); self.act("resume")
        p = copy.deepcopy(self.profile); p["names"][0]["last_name"] = "Changed"
        self.vault.save(self.session, p, 1)
        self.assertEqual(self.case()["request_status"], "invalidated")
        self.prepare()
        with patch.dict(ROUTES["epsilon"], {"destination": "https://example.invalid/changed"}):
            self.assertEqual(self.case()["request_status"], "invalidated")
        self.time += 40 * 86400
        self.assertEqual(self.case()["request_status"], "source_review_due")
        with self.assertRaises(RuleError): self.prepare()

    def test_external_uncertainty_blocks_duplicate_and_preserves_unknown_originals(self):
        self.act("plan"); self.approve()
        self.external(); e = self.state()["workflow"]["external"][0]
        self.assertEqual(e["original_payload"], "unknown")
        self.assertEqual(e["original_approval"], "unknown")
        self.assertEqual(self.case()["request_status"], "invalidated")
        with self.assertRaisesRegex(RuleError, "external request"): self.prepare()
        self.act("reconcile", id=e["id"], state="not_sent", note="Synthetic evidence confirms no disclosure.")
        self.assertEqual(self.case()["request_status"], "invalidated")
        self.prepare(); self.assertIsNone(self.case()["request"]["approval"])
        self.assertEqual(len(self.state()["workflow"]["external"][0]["history"]), 2)
        self.external(state="submitted")
        with self.assertRaises(RuleError): self.prepare()

    def test_drop_overlap_requires_review_and_new_record_invalidates_unused_approval(self):
        self.act("plan"); self.approve(); self.external("drop", "submitted")
        self.assertEqual(self.case()["request_status"], "invalidated")
        with self.assertRaisesRegex(RuleError, "overlap"): self.prepare()
        self.approve(ack=True)
        self.assertTrue(self.case()["request"]["snapshot"]["drop_overlap_acknowledged"])
        self.external("drop", "uncertain")
        self.assertEqual(self.case()["request_status"], "invalidated")

    def test_workflow_ciphertext_lock_and_delete_boundaries(self):
        self.act("plan"); self.external()
        for path in self.path.iterdir():
            if path.is_file(): self.assertNotIn(b"ExternalCanary", path.read_bytes())
        self.vault.lock()
        with self.assertRaises(RuleError): self.state()
        with self.assertRaises(RuleError): self.flow.command(self.session, 2, 1, "resume", {})
        self.session = self.vault.unlock(PASS)["session"]
        self.assertEqual(len(self.state()["workflow"]["external"]), 1)
        self.vault.delete(self.session, "DELETE", 1)
        self.assertEqual(self.vault.db.execute("SELECT count(*) FROM records").fetchone()[0], 0)

    def test_v3_upgrade_explicit_atomic_and_preserves_identity_and_inflight_attempt(self):
        self.cases.create(self.session, "epsilon", "", "Synthetic existing case.", True)
        c = self.case()
        fields, identifiers, _ = mapping(self.profile, ROUTES["epsilon"])
        self.command("prepare", fields=fields, identifiers=identifiers, self_only=True)
        fp = self.case()["request"]["fingerprint"]
        self.command("approve", fingerprint=fp, acknowledged=True)
        self.command("handoff", fingerprint=fp, dry_run=False)
        before = self.case()
        with self.vault.db: self.vault.db.execute("PRAGMA user_version=3")
        self.vault.lock(); self.session = self.vault.unlock(PASS)["session"]
        self.assertTrue(self.vault.read(self.session)["migration_required"])
        self.assertEqual(self.vault.read(self.session)["profile"], self.profile)
        with self.assertRaises(RuleError): self.flow.command(self.session, 0, 1, "plan", {})
        original = self.vault._write
        def fail_after_write(*args):
            original(*args); raise RuleError("Synthetic interrupted upgrade")
        with patch.object(self.vault, "_write", side_effect=fail_after_write), self.assertRaises(RuleError):
            self.vault.upgrade_identity(self.session, 1, True)
        self.assertEqual(self.vault.db.execute("PRAGMA user_version").fetchone()[0], 3)
        self.assertEqual(self.vault.read(self.session)["version"], 1)
        self.vault.upgrade_identity(self.session, 1, True)
        self.assertEqual(self.vault.read(self.session)["profile"], self.profile)
        self.assertEqual(self.case()["attempt"], before["attempt"])
        self.assertEqual(self.case()["request"], before["request"])
        self.assertEqual(self.vault.db.execute("PRAGMA user_version").fetchone()[0], SCHEMA)

    def test_batch_creation_transaction_rolls_back_on_workflow_write_failure(self):
        original = self.vault._write_record
        def fail_workflow(identifier, *args):
            if identifier == "workflow": raise RuleError("Synthetic write failure")
            return original(identifier, *args)
        with patch.object(self.vault, "_write_record", side_effect=fail_workflow), self.assertRaises(RuleError):
            self.act("plan")
        self.assertEqual(self.state()["cases"], [])
        self.assertEqual(read(self.vault)[1], 0)


class WorkflowHTTPTests(unittest.TestCase):
    def setUp(self):
        self.base = test_private.PrivateHTTPTests(); self.base.setUp(); self.addCleanup(self.base.doCleanups)

    def test_mutations_require_session_and_reject_extra_transport_fields(self):
        b = self.base
        code, _, _ = b.request("/api/workflow", {"version": 0, "profile_version": 0, "action": "plan", "data": {}})
        self.assertEqual(code, 409)
        b.session = b.request("/api/create", test_private.CREATE)[2]["session"]
        profile = copy.deepcopy(PROFILE)
        profile["names"][0].update(first_name="Avery", last_name="Example")
        b.request("/api/save", {"profile": profile, "version": 0})
        payload = {"version": 0, "profile_version": 1, "action": "plan", "data": {}}
        self.assertEqual(b.request("/api/workflow", {**payload, "send": True})[0], 409)
        self.assertEqual(b.request("/api/workflow", {**payload, "data": {"send": True}})[0], 409)
        self.assertEqual(b.request("/api/workflow", payload, {"Origin": "https://example.invalid"})[0], 403)
        result = b.request("/api/workflow", payload)
        self.assertEqual(result[0], 200)
        self.assertFalse(result[2]["workflow"]["paused"])
        self.assertEqual(b.request("/api/workflow", payload)[0], 409)
        b.request("/api/lock", {})
        self.assertEqual(b.request("/api/cases")[0], 409)

    def test_external_unicode_fields_fit_the_documented_bound(self):
        b = self.base
        b.session = b.request("/api/create", test_private.CREATE)[2]["session"]
        b.request("/api/save", {"profile": PROFILE, "version": 0})
        data = {"broker": "drop", "purpose": "🧪" * 200, "date": "2026-10-06", "date_precision": "approximate",
                "state": "uncertain", "note": "🧪" * 1500, "self_only": True}
        payload = {"version": 0, "profile_version": 1, "action": "external", "data": data}
        response = b.request("/api/workflow", payload)
        self.assertEqual(response[0], 200)
        self.assertEqual(response[2]["workflow"]["external"][0]["history"][0]["note"], data["note"])
        self.assertEqual(b.request("/api/workflow", {"oversized": "a" * 33000})[0], 413)
