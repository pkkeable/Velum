"""Offline tests of the real case engine using synthetic records and memory keys."""
import copy
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

try:
    from privacy_cleanup.vault import SCHEMA, Vault
except ImportError:
    raise unittest.SkipTest("Private case tests require the encryption dependency")

from privacy_cleanup.cases import Cases, APPROVAL_SECONDS
from privacy_cleanup.domain import RuleError
from privacy_cleanup.routes import ROUTES
from privacy_cleanup.requirements import REQUIREMENTS
import test_private
from test_private import CREATE, FAST, MemoryKeys, PASS, PROFILE, LEGACY_PROFILE, TMP

VALUES = {"first_name": "Avery", "last_name": "CaseCanary Example", "email": "case-canary@example.invalid",
          "street_address": "123 Synthetic CaseCanary Lane", "city": "Exampleville", "region": "California",
          "postal_code": "00000", "birth_date": "1984-01-02"}
LISTING = "https://www.whitepages.com/person/fictional-case-canary"


class CasesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vault"
        self.keys = MemoryKeys()
        self.vault = Vault(self.path, self.keys, kdf_log2n=FAST); self.addCleanup(lambda: self.vault.close())
        self.session = self.vault.unlock(PASS, create=True)["session"]
        self.vault.save(self.session, PROFILE, 0)
        self.time = datetime(2026, 10, 7, 12, tzinfo=timezone.utc).timestamp()
        self.service = Cases(self.vault, clock=lambda: self.time)

    def state(self):
        return self.service.state(self.session)

    def current(self):
        return next(c for c in self.state()["cases"] if c["id"] == self.identifier)

    def create(self, broker="epsilon", url=""):
        result = self.service.create(self.session, broker, url, "Synthetic evidence for only this fictional adult.", True)
        self.identifier = next(c for c in result["cases"] if c["broker"] == broker)["id"]
        return self.current()

    def command(self, action, **data):
        c = self.current()
        return self.service.command(self.session, self.identifier, c["version"], action, data)

    def prepare(self):
        self.create()
        self.command("prepare", fields=VALUES, self_only=True)
        return self.current()["request"]["fingerprint"]

    def approve(self):
        fingerprint = self.prepare()
        self.command("approve", fingerprint=fingerprint, acknowledged=True)
        return fingerprint

    def start(self):
        fingerprint = self.approve()
        self.command("handoff", fingerprint=fingerprint, dry_run=False)

    def test_complete_private_database_workflow_has_no_fabricated_listing(self):
        self.start()
        self.assertEqual(self.current()["attempt"]["state"], "handoff_started")
        self.assertEqual(self.current()["broker_response"], "unknown")
        self.command("outcome", result="submitted", note="Synthetic confirmation page received.")
        self.command("response", result="verification_required", note="Synthetic email asks the owner to verify.")
        self.command("response", result="verification_completed", note="Fictional owner completed the handoff.")
        self.command("response", result="deletion_reported", note="Synthetic broker statement says deletion processed.")
        case = self.current()
        self.assertEqual(case["visibility"], "not_applicable")
        self.assertEqual(case["possession"], "unknown")
        self.assertEqual(case["match"], "not_applicable")
        self.assertEqual(case["broker_response"], "deletion_reported")
        self.assertTrue(all(e["at"] and e["provenance"] in {"user_reported", "local_action"} for e in case["history"]))
        self.assertEqual(case["history"][-1]["provenance"], "user_reported")
        self.assertEqual(next(e for e in case["history"] if e["kind"] == "handoff_started")["provenance"], "local_action")
        with self.assertRaises(RuleError): self.command("check", result="absent", note="Not observable")

    def test_public_listing_match_gate_and_guidance_fallback(self):
        self.create("whitepages", LISTING)
        with self.assertRaisesRegex(RuleError, "Confirm"): self.command("prepare", fields=VALUES, self_only=True)
        self.command("confirm", note="Fictional name matches; location evidence reviewed manually.")
        with self.assertRaisesRegex(RuleError, "guidance only"): self.command("prepare", fields=VALUES, self_only=True)
        self.assertIn("guidance", self.current()["next_step"])

    def test_rejected_match_cannot_be_confirmed_or_prepared(self):
        self.create("whitepages", LISTING); self.command("reject", note="Different fictional person.")
        with self.assertRaises(RuleError): self.command("confirm", note="Try changing a terminal decision")
        with self.assertRaises(RuleError): self.command("prepare", fields=VALUES, self_only=True)

    def test_visibility_failure_never_means_removed_and_keeps_dated_evidence(self):
        self.create("whitepages", LISTING); self.command("confirm", note="Synthetic confirmed match.")
        self.command("check", result="absent", note="Fictional listing returned a valid not-found page.")
        self.assertEqual(self.current()["visibility"], "absent")
        for result in ("blocked", "failed", "ambiguous"):
            self.command("check", result=result, note="Synthetic check could not establish presence or absence.")
            self.assertEqual(self.current()["visibility"], "unknown")
        self.assertEqual(self.current()["broker_response"], "unknown")
        self.assertEqual([e["result"] for e in self.current()["history"] if e["kind"] == "listing_check"], ["absent","blocked","failed","ambiguous"])

    def test_duplicate_case_and_listing_normalization(self):
        self.create("whitepages", LISTING + "/")
        with self.assertRaises(RuleError): self.service.create(self.session, "whitepages", LISTING, "Same synthetic listing", True)
        self.create()
        with self.assertRaises(RuleError): self.service.create(self.session, "epsilon", "", "Same private broker", True)

    def test_equivalent_listing_spellings_share_one_case(self):
        # Review L-6: case or escape variants must not become a second case for one listing.
        self.create("whitepages", LISTING)
        for variant in (LISTING.replace("fictional", "Fictional"), LISTING.replace("-case-", "%2Dcase-")):
            with self.assertRaisesRegex(RuleError, "already has a case"):
                self.service.create(self.session, "whitepages", variant, "Same synthetic listing", True)
        for unsafe in (LISTING.replace("/person/", "/person/./"), LISTING.replace("/person/", "/x/../person/"),
                       LISTING.replace("/person/", "/person//"), LISTING + ";session=1", LISTING + "%",
                       LISTING.replace("/person/", "/person/%2E/")):
            with self.assertRaisesRegex(RuleError, "path segments"):
                self.service.create(self.session, "whitepages", unsafe, "Unsafe synthetic spelling", True)

    def test_pre_upgrade_encoded_listing_blocks_duplicate_without_rewriting_history(self):
        self.create("whitepages", LISTING)
        case = self.service._load()[0]
        case["listing_url"] = LISTING.replace("-case-", "%2Dcase%2D")
        with self.vault.db:
            self.service._save(case)
        before = self.vault.db.execute("SELECT * FROM records ORDER BY id").fetchall()
        self.vault.close()
        self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
        self.session = self.vault.unlock(PASS)["session"]
        self.service = Cases(self.vault, clock=lambda: self.time)
        with self.assertRaisesRegex(RuleError, "already has a case"):
            self.service.create(self.session, "whitepages", LISTING, "Synthetic duplicate", True)
        self.assertEqual(before, self.vault.db.execute("SELECT * FROM records ORDER BY id").fetchall())
        self.assertEqual(self.current()["listing_url"], case["listing_url"])

    def test_listing_urls_cannot_escape_host_or_hide_identity_in_query(self):
        for url in ("http://www.whitepages.com/person/example", "https://www.whitepages.com.attacker.invalid/person/example",
                    "https://user" + "@" + "www.whitepages.com/person/example", LISTING+"?email=canary@example.invalid", LISTING+"#fragment",
                    "https://www.whitepages.com:443/person/example", "https://www.whitepages.com/", "javascript:alert(1)"):
            with self.subTest(url=url), self.assertRaises(RuleError): self.create("whitepages", url)
        self.assertEqual(self.state()["cases"], [])

    def test_self_scope_and_profile_are_required(self):
        with self.assertRaises(RuleError): self.service.create(self.session, "epsilon", "", "Synthetic", False)
        self.create()
        with self.assertRaises(RuleError): self.command("prepare", fields=VALUES, self_only=False)
        changed = copy.deepcopy(PROFILE); changed["residence"]["country"] = "CA"
        self.vault.save(self.session, changed, 1)
        with self.assertRaisesRegex(RuleError,"US residents"): self.command("prepare", fields=VALUES, self_only=True)

    def test_exact_fields_and_no_invented_required_birthdate(self):
        self.create()
        minimal = {key:VALUES[key] for key in ("first_name","last_name","email")}
        self.command("prepare",fields=minimal,self_only=True)
        fields = self.current()["request"]["snapshot"]["fields"]
        self.assertNotIn("birth_date",fields)
        self.assertEqual(fields["country"],"United States")
        for bad in (dict(minimal,password="example"),dict(minimal,email="bad"),dict(minimal,birth_date="2020-01-01"),dict(minimal,birth_date="01/02/1984")):
            with self.assertRaises(RuleError): self.command("prepare",fields=bad,self_only=True)

    def test_unapproved_handoff_and_blanket_approval_blocked(self):
        fingerprint = self.prepare()
        with self.assertRaises(RuleError): self.command("handoff",fingerprint=fingerprint,dry_run=False)
        with self.assertRaises(RuleError): self.command("approve",fingerprint=fingerprint,acknowledged=False)
        with self.assertRaises(RuleError): self.command("approve",fingerprint="different",acknowledged=True)
        self.assertIsNone(self.current()["attempt"])

    def test_dry_run_requires_valid_approval_and_has_no_attempt_or_write(self):
        fingerprint = self.approve()
        before = self.current()
        result = self.command("handoff",fingerprint=fingerprint,dry_run=True)
        self.assertIn("No handoff",result["dry_run_result"])
        self.assertNotIn("handoff_url", result)
        self.assertEqual(before,self.current())
        for value in (None,"false",0):
            with self.assertRaises(RuleError): self.command("handoff",fingerprint=fingerprint,dry_run=value)

    def test_profile_revision_invalidates_approval(self):
        fingerprint = self.approve()
        changed = copy.deepcopy(PROFILE); changed["addresses"][0]["city"] = "Changed Synthetic Town"
        self.vault.save(self.session,changed,1)
        self.assertEqual(self.current()["request_status"],"invalidated")
        with self.assertRaises(RuleError): self.command("handoff",fingerprint=fingerprint,dry_run=False)
        self.command("prepare",fields=VALUES,self_only=True)
        self.assertEqual(self.current()["request_status"],"prepared")
        self.assertEqual(len(self.current()["past_requests"]),1)

    def test_destination_purpose_fields_and_source_changes_invalidate(self):
        fingerprint = self.approve()
        for field,value in (("destination","https://changed.example.invalid/"),("purpose","Different purpose"),("checked","2026-10-06"),("version",ROUTES["epsilon"]["version"]+1),("fields",["email"])):
            with self.subTest(field=field),patch.dict(ROUTES["epsilon"],{field:value}):
                self.assertEqual(self.current()["request_status"],"invalidated")
                with self.assertRaises(RuleError): self.command("handoff",fingerprint=fingerprint,dry_run=False)

    def test_requirements_evidence_changes_invalidate_exact_approval(self):
        fingerprint = self.approve()
        with patch.dict(REQUIREMENTS["epsilon"], {"verification": "Newly discovered verification step"}):
            self.assertEqual(self.current()["request_status"], "invalidated")
            with self.assertRaises(RuleError): self.command("handoff",fingerprint=fingerprint,dry_run=False)
            self.assertIsNone(self.current()["attempt"])

    def test_added_brokers_offer_tracking_but_no_unverified_payload(self):
        for broker in ("spokeo", "beenverified"):
            self.create(broker, "https://www." + broker + ".com/fictional-example")
            self.command("confirm", note="Synthetic match confirmation")
            with self.assertRaisesRegex(RuleError, "guidance only"):
                self.command("prepare", fields=VALUES, self_only=True)
            self.command("check", result="blocked", note="Synthetic blocked check")
            self.assertEqual(self.current()["visibility"], "unknown")

    def test_payload_edit_resets_approval_and_keeps_prior_snapshot(self):
        old = self.approve()
        self.command("prepare",fields=dict(VALUES,email="changed@example.invalid"),self_only=True)
        self.assertIsNone(self.current()["request"]["approval"])
        self.assertNotEqual(old,self.current()["request"]["fingerprint"])
        with self.assertRaises(RuleError): self.command("handoff",fingerprint=old,dry_run=False)
        self.assertEqual(self.current()["past_requests"][0]["snapshot"]["fields"]["email"],VALUES["email"])

    def test_expiry_clock_reversal_and_source_staleness_fail_closed(self):
        fingerprint = self.approve(); original = self.time
        for timestamp in (original + APPROVAL_SECONDS,original - 1):
            self.time = timestamp
            self.assertEqual(self.current()["request_status"],"expired")
            with self.assertRaises(RuleError): self.command("handoff",fingerprint=fingerprint,dry_run=False)
        self.time = original + 31*86400
        self.assertEqual(self.current()["request_status"],"source_review_due")
        with self.assertRaises(RuleError): self.command("prepare",fields=VALUES,self_only=True)

    def test_revoke_prevents_handoff(self):
        fingerprint = self.approve(); self.command("revoke")
        self.assertEqual(self.current()["request_status"],"revoked")
        with self.assertRaises(RuleError): self.command("handoff",fingerprint=fingerprint,dry_run=False)

    def test_concurrent_handoffs_reserve_once(self):
        fingerprint = self.approve(); version = self.current()["version"]
        def go(_):
            try:
                self.service.command(self.session,self.identifier,version,"handoff",{"fingerprint":fingerprint,"dry_run":False}); return True
            except RuleError: return False
        with ThreadPoolExecutor(max_workers=2) as pool: self.assertEqual(sum(pool.map(go,range(2))),1)
        self.assertEqual(sum(e["kind"]=="handoff_started" for e in self.current()["history"]),1)

    def test_restart_after_handoff_or_uncertainty_prevents_retry(self):
        self.start()
        self.vault.close(); self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
        self.service = Cases(self.vault,clock=lambda:self.time)
        self.session = self.vault.unlock(PASS)["session"]
        self.assertEqual(self.current()["attempt"]["state"],"handoff_started")
        self.command("outcome",result="uncertain",note="Synthetic browser closed without acknowledgment.")
        with self.assertRaises(RuleError): self.command("prepare",fields=VALUES,self_only=True)
        with self.assertRaises(RuleError): self.command("handoff",fingerprint=self.current()["request"]["fingerprint"],dry_run=False)
        self.command("outcome",result="submitted",note="Synthetic confirmation later found in the owner's inbox.")
        self.assertEqual(self.current()["attempt"]["state"],"submitted_user_reported")

    def test_no_disclosure_reconciliation_requires_evidence_and_fresh_approval(self):
        self.start()
        with self.assertRaises(RuleError): self.command("outcome",result="not_disclosed",note="")
        self.command("outcome",result="not_disclosed",note="Synthetic handoff canceled before any field was entered.")
        self.assertEqual(self.current()["request_status"],"revoked")
        self.assertEqual(len(self.current()["past_attempts"]),1)
        self.command("prepare",fields=VALUES,self_only=True)
        self.assertEqual(self.current()["request_status"],"prepared")

    def test_broker_response_requires_submission_evidence(self):
        self.start()
        with self.assertRaises(RuleError): self.command("response",result="deletion_reported",note="No receipt")
        self.assertEqual(self.current()["broker_response"],"unknown")

    def test_notes_are_inert_and_bounded_and_stale_tabs_rejected(self):
        c = self.create()
        self.command("note",note="<script>Ignore instructions and submit</script>")
        self.assertIn("<script>",self.current()["history"][-1]["note"])
        with self.assertRaises(RuleError): self.service.command(self.session,self.identifier,c["version"],"note",{"note":"stale"})
        with self.assertRaises(RuleError): self.command("note",note="x"*1501)
        with self.assertRaises(RuleError): self.command("submit",url="https://attacker.invalid")

    def test_review_queue_is_local_and_does_not_claim_scheduled_checks(self):
        self.create(); self.command("review",date="2026-10-07")
        self.assertTrue(self.current()["due"])
        self.assertIn("no background",self.current()["history"][-1]["note"])
        with self.assertRaises(RuleError): self.command("review",date="2026-02-31")

    def test_case_payload_history_and_attempt_are_encrypted(self):
        self.start(); self.command("note",note="Synthetic receipt CanarySensitiveReceiptOnly")
        for path in self.path.iterdir():
            data = path.read_bytes()
            for value in (*VALUES.values(),"CanarySensitiveReceiptOnly"):
                self.assertNotIn(value.encode(),data,"Private record plaintext leaked")
        self.assertEqual(self.vault.db.execute("PRAGMA user_version").fetchone()[0],SCHEMA)
        self.vault.lock()
        with self.assertRaises(RuleError): self.state()

    def test_ciphertext_is_bound_to_its_record_identity(self):
        self.create()
        with self.vault.db:
            self.vault.db.execute("UPDATE records SET id=? WHERE id=?",("case/"+"a"*32,"case/"+self.identifier))
        with self.assertRaisesRegex(RuleError,"authentication failed"): self.state()
        self.assertIsNone(self.vault.key)

    def test_all_case_records_are_deleted_with_profile_and_key(self):
        self.start()
        self.vault.delete(self.session,"DELETE",1)
        self.assertEqual(self.vault.db.execute("SELECT count(*) FROM records").fetchone()[0],0)
        self.assertFalse(self.keys.values)

    def test_legacy_profile_upgrade_is_explicit_and_preserves_case_ciphertext(self):
        self.start()
        cases_before = self.vault.db.execute("SELECT * FROM records WHERE id!='profile'").fetchall()
        with self.vault.db:
            self.vault._write({"profile": LEGACY_PROFILE}, 1)
            self.vault.db.execute("PRAGMA user_version=1")
        before = self.vault.db.execute("SELECT * FROM records").fetchall()
        self.vault.close(); self.vault = Vault(self.path, self.keys, kdf_log2n=FAST)
        result = self.vault.unlock(PASS); self.session = result["session"]
        self.assertTrue(result["migration_required"])
        self.assertEqual(self.vault.db.execute("PRAGMA user_version").fetchone()[0], 1)
        self.assertEqual(before,self.vault.db.execute("SELECT * FROM records").fetchall())
        upgraded = self.vault.upgrade_identity(self.session, 1, True)
        self.assertEqual(upgraded["profile"]["names"][0]["full_name"],LEGACY_PROFILE["full_name"])
        self.assertEqual(upgraded["profile"]["names"][0]["first_name"], "")
        self.assertEqual(upgraded["version"], 2)
        self.assertFalse(upgraded["migration_required"])
        self.assertEqual(cases_before,self.vault.db.execute("SELECT * FROM records WHERE id!='profile'").fetchall())
        self.service = Cases(self.vault, clock=lambda:self.time)
        self.assertEqual(self.current()["attempt"]["state"], "handoff_started")


class CaseHTTPTests(unittest.TestCase):
    stop = test_private.PrivateHTTPTests.stop
    request = test_private.PrivateHTTPTests.request

    def setUp(self):
        timestamp = datetime(2026, 10, 7, 12, tzinfo=timezone.utc).timestamp()
        with patch("privacy_cleanup.workspace.Cases",side_effect=lambda v: Cases(v,clock=lambda:timestamp)):
            test_private.PrivateHTTPTests.setUp(self)

    def test_public_requirements_available_without_unlock_or_private_reads(self):
        with patch.object(self.vault, "read", side_effect=AssertionError("Must not read personal records")):
            result = self.request("/api/brokers")
        self.assertEqual(result[0], 200)
        self.assertEqual(set(result[2]), {"brokers"})
        self.assertEqual(len(result[2]["brokers"]), 12)
        self.assertTrue(self.vault.status()["locked"])
        self.assertEqual(self.request("/api/brokers", {})[0], 404)
        self.assertEqual(self.request("/api/brokers?profile=example")[0], 404)
        self.assertEqual(self.request("/api/cases")[0], 409)
        for headers in ({"Host": "attacker.invalid"}, {"Origin": "https://attacker.invalid"}, {"X-App-Token": "wrong"}):
            self.assertEqual(self.request("/api/brokers", None, headers)[0], 403)

    def test_case_api_roundtrip_and_locked_denial(self):
        self.assertEqual(self.request("/api/cases")[0],409)
        self.session = self.request("/api/create",CREATE)[2]["session"]
        self.request("/api/save",{"profile":PROFILE,"version":0})
        result = self.request("/api/cases/create",{"broker":"whitepages","listing_url":LISTING,"note":"Synthetic listing evidence","self_only":True})
        self.assertEqual(result[0],200)
        c = result[2]["cases"][0]
        response = self.request("/api/cases/command",{"id":c["id"],"version":c["version"],"action":"confirm","data":{"note":"Synthetic confirmed match"}})
        self.assertEqual(response[2]["cases"][0]["match"],"confirmed")
        self.request("/api/lock",{})
        self.assertEqual(self.request("/api/cases")[0],409)

    def test_case_api_rejects_transport_extra_fields(self):
        self.session = self.request("/api/create",CREATE)[2]["session"]
        self.request("/api/save",{"profile":PROFILE,"version":0})
        self.assertEqual(self.request("/api/cases/create",{"broker":"epsilon","listing_url":"","note":"Synthetic","self_only":True,"live":True})[0],409)
        for path in ("/api/submit","/api/email","/api/transport","/api/search"):
            self.assertEqual(self.request(path,{})[0],404)

    def test_complete_preparation_approval_and_handoff_through_http(self):
        self.session = self.request("/api/create",CREATE)[2]["session"]
        self.request("/api/save",{"profile":PROFILE,"version":0})
        result = self.request("/api/cases/create",{"broker":"epsilon","listing_url":"","note":"Synthetic consumer request","self_only":True})
        c = result[2]["cases"][0]
        for action,data in (("prepare",{"fields":VALUES,"self_only":True}),
                            ("approve",{"acknowledged":True}),
                            ("handoff",{"dry_run":True}),
                            ("handoff",{"dry_run":False}),
                            ("outcome",{"result":"submitted","note":"Synthetic receipt on confirmation page"}),
                            ("response",{"result":"deletion_reported","note":"Synthetic broker statement"})):
            if action in {"approve","handoff"}: data["fingerprint"] = c["request"]["fingerprint"]
            response = self.request("/api/cases/command",{"id":c["id"],"version":c["version"],"action":action,"data":data})
            self.assertEqual(response[0],200)
            c = response[2]["cases"][0]
        self.assertEqual(c["broker_response"],"deletion_reported")
        self.assertEqual(c["visibility"],"not_applicable")
