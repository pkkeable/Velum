import copy
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from privacy_cleanup.engine import RuleError, apply, catalog, new_state
from privacy_cleanup.storage import Store

TMP = "/private/tmp" if Path("/private/tmp").exists() else "/tmp"


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP)
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name) / "runtime"
        self.store = Store(self.directory)
        self.act("load_demo")

    def candidate(self, cid="spokeo-1"):
        return next(c for c in self.store.read()["candidates"] if c["id"] == cid)

    def command(self, action, cid="spokeo-1", value=None):
        s = self.store.read()
        result = {"action": action, "expected_version": s["version"]}
        if action != "load_demo":
            result["candidate_id"] = cid
            if self.candidate(cid)["request"]:
                result["fingerprint"] = self.candidate(cid)["request"]["fingerprint"]
        if value is not None:
            result["value"] = value
        return result

    def act(self, action, cid="spokeo-1", value=None):
        # load_demo is also called before there are candidates.
        if action == "load_demo":
            return self.store.act({"action": action, "expected_version": self.store.read()["version"]})
        return self.store.act(self.command(action, cid, value))

    def prepared(self, cid="spokeo-1"):
        self.act("decide", cid, "confirmed")
        self.act("prepare", cid)

    def submitted(self, cid="spokeo-1", outcome="accepted"):
        self.prepared(cid)
        self.act("approve", cid)
        self.act("submit", cid, outcome)

    def test_all_candidates_start_pending_and_unknown(self):
        for c in self.store.read()["candidates"]:
            self.assertEqual((c["decision"], c["current_visibility"], c["request"]), ("pending", "unknown", None))

    def test_no_preparation_before_confirmation(self):
        with self.assertRaises(RuleError): self.act("prepare")

    def test_rejected_match_cannot_prepare(self):
        self.act("decide", value="rejected")
        with self.assertRaises(RuleError): self.act("prepare")

    def test_confirmation_is_not_approval(self):
        self.prepared()
        with self.assertRaises(RuleError): self.act("submit", value="accepted")
        self.assertEqual(self.candidate()["attempt_count"], 0)

    def test_approval_requires_exact_preview(self):
        self.prepared()
        cmd = self.command("approve"); cmd["fingerprint"] = "wrong"
        with self.assertRaises(RuleError): self.store.act(cmd)

    def test_request_changes_clear_approval_and_old_fingerprint_fails(self):
        for variant in ("alternate_email", "alternate_destination"):
            self.act("decide", value="confirmed")
            self.act("prepare")
            self.act("approve")
            old = self.candidate()["request"]["fingerprint"]
            self.act("prepare", value=variant)
            self.assertIsNone(self.candidate()["request"]["approval"])
            self.assertNotEqual(old, self.candidate()["request"]["fingerprint"])
            with self.assertRaises(RuleError): self.act("submit", value="accepted")
            command = self.command("approve"); command["fingerprint"] = old
            with self.assertRaises(RuleError): self.store.act(command)

    def test_reopening_match_invalidates_request(self):
        self.prepared(); self.act("approve"); self.act("decide", value="pending")
        self.assertIsNone(self.candidate()["request"])
        with self.assertRaises(RuleError): self.act("submit", value="accepted")

    def test_catalog_change_invalidates_even_approved_request(self):
        self.prepared(); self.act("approve")
        brokers = catalog(); brokers["spokeo"]["mock_destination"] += "/changed"
        with patch("privacy_cleanup.engine.catalog", return_value=brokers):
            with self.assertRaises(RuleError): self.act("submit", value="accepted")

    def test_payload_tampering_fails_even_if_old_approval_kept(self):
        self.prepared(); self.act("approve")
        with self.store.connect() as conn:
            state = json.loads(conn.execute("SELECT body FROM runtime").fetchone()[0])
            state["candidates"][0]["request"]["snapshot"]["fields"]["extra"] = "not permitted"
            conn.execute("UPDATE runtime SET body=?", (json.dumps(state),))
        with self.assertRaises(RuleError): self.act("submit", value="accepted")

    def test_dry_run_cannot_be_disabled(self):
        state = new_state(); state["mode"] = "live"
        with self.assertRaises(RuleError): apply(state, "load_demo")
        for extra in ({"mode": "live"}, {"identity": {}}, {"destination": "unapproved"}):
            cmd = self.command("prepare"); cmd.update(extra)
            with self.assertRaises(RuleError): self.store.act(cmd)

    def test_unsupported_bulk_and_identity_actions(self):
        for action in ("import_identity", "live_search", "bulk_submit", "schedule", "reset"):
            with self.assertRaises(RuleError): self.act(action)

    def test_complete_workflow_keeps_claims_distinct(self):
        self.submitted()
        c = self.candidate()
        self.assertEqual((c["request"]["status"], c["verification"], c["response"], c["current_visibility"]), ("submitted", "pending", "none", "unknown"))
        self.act("verify")
        self.act("response", value="broker_reports_deletion")
        self.assertEqual(self.candidate()["current_visibility"], "unknown")
        self.act("check", value="absent")
        c = self.candidate()
        self.assertEqual(c["current_visibility"], "absent")
        self.assertEqual(c["response"], "broker_reports_deletion")
        self.assertIn("synthetic", c["checks"][0]["detail"])
        self.assertTrue(c["checks"][0]["at"])

    def test_failed_blocked_ambiguous_checks_override_current_absence(self):
        self.submitted()
        for result in ("failed", "blocked", "ambiguous"):
            self.act("check", value="absent")
            self.act("check", value=result)
            self.assertEqual(self.candidate()["current_visibility"], "unknown")
            self.assertEqual(self.candidate()["checks"][-2]["conclusion"], "absent")

    def test_reappearance_is_visible_even_after_broker_deletion_report(self):
        self.submitted(); self.act("verify"); self.act("response", value="broker_reports_deletion")
        self.act("check", value="absent"); self.act("check", value="present")
        c = self.candidate()
        self.assertEqual(c["response"], "broker_reports_deletion")
        self.assertEqual(c["current_visibility"], "present")

    def test_response_requires_verification(self):
        self.submitted()
        with self.assertRaises(RuleError): self.act("response", value="broker_reports_deletion")
        self.act("verify"); self.act("response", value="declined")
        self.assertEqual(self.candidate()["current_visibility"], "unknown")
        with self.assertRaises(RuleError): self.act("response", value="broker_reports_deletion")

    def test_duplicate_and_uncertain_retry_prevented_across_restart(self):
        self.submitted(outcome="uncertain")
        self.store = Store(self.directory)
        self.assertIsNone(self.candidate()["request"]["submitted_at"])
        for action, value in (("submit", "accepted"), ("prepare", None), ("decide", "confirmed"), ("load_demo", None)):
            with self.assertRaises(RuleError): self.act(action, value=value)
        self.assertEqual(self.candidate()["attempt_count"], 1)

    def test_duplicate_accepted_submission_prevented(self):
        self.submitted()
        with self.assertRaises(RuleError): self.act("submit", value="accepted")

    def test_duplicate_record_under_another_candidate_id_is_blocked(self):
        self.submitted()
        with self.store.connect() as conn:
            state = json.loads(conn.execute("SELECT body FROM runtime").fetchone()[0])
            state["candidates"][1]["listing_url"] = state["candidates"][0]["listing_url"]
            conn.execute("UPDATE runtime SET body=?", (json.dumps(state),))
        self.prepared("spokeo-2"); self.act("approve", "spokeo-2")
        with self.assertRaises(RuleError): self.act("submit", "spokeo-2", "accepted")

    def test_concurrent_clicks_make_one_durable_attempt(self):
        self.prepared(); self.act("approve")
        cmd = self.command("submit", value="accepted")
        def submit():
            try: self.store.act(copy.deepcopy(cmd)); return True
            except RuleError: return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: submit(), range(2)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(self.candidate()["attempt_count"], 1)

    def test_unsupported_adapter_uses_manual_fallback(self):
        self.submitted("acxiom-1")
        c = self.candidate("acxiom-1")
        self.assertEqual(c["request"]["status"], "manual_required")
        self.assertIsNone(c["request"]["submitted_at"])
        self.assertEqual(c["current_visibility"], "unknown")

    def test_explicit_manual_fallback(self):
        self.submitted(outcome="manual")
        self.assertEqual(self.candidate()["request"]["status"], "manual_required")

    def test_stale_browser_cannot_approve_revised_request(self):
        self.prepared(); cmd = self.command("approve")
        self.act("prepare")  # Even identical payloads need a fresh review.
        with self.assertRaises(RuleError): self.store.act(cmd)

    def test_untrusted_evidence_is_not_executed(self):
        candidate = self.candidate("spokeo-2")
        self.assertIn("<script>", candidate["evidence"][-1]["listing"])
        self.assertEqual(candidate["decision"], "pending")
        self.assertIsNone(candidate["request"])

    def test_invalid_action_rolls_back_without_logging_payload(self):
        before = self.store.read()
        with self.assertRaises(RuleError): self.act("decide", value="unsupported")
        self.assertEqual(before, self.store.read())

    def test_history_contains_immutable_reviewed_snapshot(self):
        self.prepared(); old = self.candidate()["request"]["snapshot"]
        self.act("prepare", value="alternate_email")
        events = [e for e in self.store.read()["events"] if e["kind"] == "request_prepared"]
        self.assertEqual(events[0]["detail"]["snapshot"], old)
        self.assertNotEqual(events[-1]["detail"]["snapshot"], old)
