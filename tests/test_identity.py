"""R1 synthetic identity, migration and historical-disclosure regressions."""
import copy
import json
import contextlib
import io
import unittest
from unittest.mock import patch

try:
    from privacy_cleanup.vault import Vault
except ImportError:
    raise unittest.SkipTest("R1 encrypted identity tests require the private dependency")

from privacy_cleanup import identity
from privacy_cleanup.cases import Cases
from privacy_cleanup.domain import RuleError
import test_cases
import test_private


class IdentityTests(unittest.TestCase):
    def test_unicode_and_single_part_name_are_preserved_without_splitting(self):
        profile = identity.from_legacy({"full_name": "单名 O’Example"})
        result = identity.validate(profile)
        self.assertEqual(result["names"][0]["full_name"], "单名 O’Example")
        self.assertEqual(result["names"][0]["first_name"], "")
        self.assertFalse(result["self_adult"])
        self.assertEqual(result["emails"], [])

    def test_bounds_unknown_fields_and_duplicate_ids_are_rejected(self):
        for change in (
            lambda p: p["names"].extend(identity.entry("names", full_name="Synthetic") for _ in range(10)),
            lambda p: p["names"].append(copy.deepcopy(p["names"][0])),
            lambda p: p["names"][0].update(password="SyntheticNotASecret"),
            lambda p: p["names"][0].update(label=[]),
            lambda p: p.update(schema=True),
            lambda p: p["names"][0].update(preferred=1),
        ):
            profile = copy.deepcopy(test_private.PROFILE); change(profile)
            with self.assertRaises(RuleError): identity.validate(profile)

    def test_preferred_retired_and_dates_are_consistent(self):
        profile = copy.deepcopy(test_private.PROFILE)
        profile["addresses"][0].update(from_date="2026-01-01", to_date="2025-01-01", label="past", preferred=False)
        with self.assertRaisesRegex(RuleError, "start date"): identity.validate(profile)
        profile["addresses"][0].update(from_date="2024-01-01", label="current", preferred=True)
        with self.assertRaisesRegex(RuleError, "end date"): identity.validate(profile)
        profile["addresses"][0].update(to_date="", retired=True)
        with self.assertRaisesRegex(RuleError, "preferred"): identity.validate(profile)

    def test_duplicate_warning_keeps_display_values_and_phone_country(self):
        profile = copy.deepcopy(test_private.PROFILE)
        profile["phones"] = [identity.entry("phones",value="+1 (555) 010-0101",country="US"),identity.entry("phones",value="+1-555-010-0101",country="US")]
        saved = identity.validate(profile)
        self.assertEqual(saved["phones"][0]["value"], "+1 (555) 010-0101")
        self.assertTrue(identity.warnings(saved))
        saved["phones"][0]["country"] = ""
        with self.assertRaisesRegex(RuleError, "country context"): identity.validate(saved)

    def test_saved_ids_cannot_be_removed_or_moved_but_can_be_retired(self):
        previous = copy.deepcopy(test_private.PROFILE)
        current = copy.deepcopy(previous); current["emails"] = []
        with self.assertRaisesRegex(RuleError, "Retire"): identity.validate(current, previous)
        current = copy.deepcopy(previous); current["emails"][0].update(retired=True, preferred=False)
        self.assertTrue(identity.validate(current, previous)["emails"][0]["retired"])


class R1StorageTests(unittest.TestCase):
    def setUp(self):
        self.base = test_cases.CasesTests()
        self.base.setUp()
        self.addCleanup(self.base.doCleanups)
        self.vault = self.base.vault
        self.session = self.base.session
        self.service = self.base.service

    def test_selected_values_are_minimized_and_snapshot_survives_profile_edit(self):
        b = self.base; b.create()
        p = copy.deepcopy(test_private.PROFILE)
        p["names"][0].update(first_name="Avery",last_name="Example")
        p["emails"].append(identity.entry("emails",value="unselected-canary@example.invalid"))
        p["phones"].append(identity.entry("phones",value="5550101234",country="US"))
        self.vault.save(self.session,p,1)
        values = {"first_name":"Avery","last_name":"Example","email":p["emails"][0]["value"]}
        refs = {"first_name":p["names"][0]["id"],"last_name":p["names"][0]["id"],"email":p["emails"][0]["id"]}
        b.command("prepare",fields=values,self_only=True,identifiers=refs)
        request = copy.deepcopy(b.current()["request"])
        self.assertNotIn("unselected-canary",json.dumps(request))
        self.assertNotIn("5550101234",json.dumps(request))
        self.assertEqual(request["snapshot"]["identifiers"],refs)
        b.command("approve",fingerprint=request["fingerprint"],acknowledged=True)
        p["emails"][0]["value"]="edited-canary@example.invalid"
        self.vault.save(self.session,p,2)
        self.assertEqual(b.current()["request_status"],"invalidated")
        history = self.service.submissions(self.session)["entries"]
        self.assertEqual(history[0]["request"]["snapshot"]["fields"]["email"],values["email"])
        self.vault.lock()
        with self.assertRaises(RuleError): self.service.submissions(self.session)

    def test_retired_unreachable_and_mismatched_identifiers_cannot_be_bound(self):
        p = copy.deepcopy(test_private.PROFILE); email=p["emails"][0]
        self.base.create()
        values={**test_cases.VALUES,"email":email["value"]}
        for change in (lambda p:p["emails"][0].update(retired=True,preferred=False),lambda p:p["emails"][0].update(reachable=False)):
            current=copy.deepcopy(p);change(current)
            self.vault.save(self.session,current,self.vault.read(self.session)["version"])
            with self.assertRaises(RuleError): self.base.command("prepare",fields=values,self_only=True,identifiers={"email":email["id"]})
        self.vault.save(self.session,p,self.vault.read(self.session)["version"])
        with self.assertRaisesRegex(RuleError,"changed"):
            self.base.command("prepare",fields=test_cases.VALUES,self_only=True,identifiers={"email":email["id"]})

    def test_history_distinguishes_identical_request_revisions_and_attempts(self):
        b=self.base;b.start()
        first=b.current()["request"]["id"]
        b.command("outcome",result="not_disclosed",note="Fictional form was never filled.")
        b.command("prepare",fields=test_cases.VALUES,self_only=True)
        second=b.current()["request"]["id"]
        self.assertNotEqual(first,second)
        fp=b.current()["request"]["fingerprint"]
        b.command("approve",fingerprint=fp,acknowledged=True)
        b.command("handoff",fingerprint=fp,dry_run=False)
        result=self.service.submissions(self.session)
        self.assertEqual(len(result["histories"]),1)
        self.assertEqual(json.dumps(result).count("Fictional form was never filled."),1)
        rows=result["entries"]
        self.assertEqual(len(rows),2)
        self.assertEqual([r["revision"] for r in rows],[1,2])
        self.assertIn("Reconcile",rows[1]["next_step"])
        self.assertFalse(rows[0]["due"])
        self.assertEqual(rows[0]["attempts"][0]["state"],"closed_without_disclosure_user_reported")
        self.assertEqual(rows[1]["attempts"][0]["state"],"handoff_started")
        self.assertEqual(rows[0]["broker_response"],"see_dated_history")

    def legacy(self):
        self.base.prepare()
        with self.vault.db:
            self.vault._write({"profile":test_private.LEGACY_PROFILE},1)
            self.vault.db.execute("PRAGMA user_version=2")

    def test_legacy_identical_revisions_remain_unassigned_in_history(self):
        b=self.base;b.start()
        b.command("outcome",result="not_disclosed",note="Synthetic no disclosure.")
        b.command("prepare",fields=test_cases.VALUES,self_only=True)
        case=self.service._load()[0]
        for request in case["past_requests"]+[case["request"]]:request.pop("id")
        for attempt in case["past_attempts"]:attempt.pop("request_id")
        with self.vault.db:self.service._save(case)
        rows=self.service.submissions(self.session)["entries"]
        self.assertEqual(len(rows),2)
        self.assertTrue(all(r["legacy_attempt_alignment_unknown"] for r in rows))
        self.assertTrue(all(not r["attempts"] for r in rows))

    def test_migration_failure_rolls_back_records_nonces_schema_and_retries(self):
        self.legacy()
        before = {table:self.vault.db.execute("SELECT * FROM "+table).fetchall() for table in ("records","used_nonces","meta")}
        write=self.vault._write
        def interrupted(*args):
            write(*args)
            raise RuntimeError("Synthetic interrupted migration")
        with patch.object(self.vault,"_write",side_effect=interrupted):
            with self.assertRaises(RuntimeError): self.vault.upgrade_identity(self.session,1,True)
        self.assertEqual(self.vault.db.execute("PRAGMA user_version").fetchone()[0],2)
        for table,rows in before.items():self.assertEqual(rows,self.vault.db.execute("SELECT * FROM "+table).fetchall())
        self.vault.close()
        self.base.vault=Vault(self.base.path,self.base.keys,kdf_log2n=test_private.FAST)
        self.vault=self.base.vault
        result=self.vault.unlock(test_private.PASS)
        self.assertEqual(result["profile"],test_private.LEGACY_PROFILE)
        migrated=self.vault.upgrade_identity(result["session"],1,True)
        self.assertEqual(migrated["version"],2)
        self.assertFalse(migrated["profile"]["self_adult"])
        self.assertFalse(migrated["profile"]["emails"][0]["reachable"])

    def test_migration_requires_ack_session_and_version_and_invalidates_unused_approval(self):
        self.legacy();fp=self.base.current()["request"]["fingerprint"]
        for session,version,ack in ((None,1,True),(self.session,0,True),(self.session,1,False)):
            with self.assertRaises(RuleError): self.vault.upgrade_identity(session,version,ack)
        with self.assertRaises(RuleError): self.base.command("approve",fingerprint=fp,acknowledged=True)
        self.vault.upgrade_identity(self.session,1,True)
        self.assertEqual(self.base.current()["request_status"],"invalidated")
        with self.assertRaises(RuleError):self.vault.upgrade_identity(self.session,2,True)

    def test_maximum_identity_request_roundtrip_and_ciphertext(self):
        p=copy.deepcopy(test_private.PROFILE)
        for i in range(9):p["addresses"].append(identity.entry("addresses",street_address="SyntheticMaximumCanary"+str(i)+"x"*210,address_line2="y"*240,city="z"*120,region="q"*120))
        self.vault.save(self.session,p,1)
        self.assertEqual(len(self.vault.read(self.session)["profile"]["addresses"]),10)
        for path in self.base.path.iterdir():
            if path.is_file():self.assertNotIn(b"SyntheticMaximumCanary",path.read_bytes())


class R1HTTPTests(unittest.TestCase):
    def setUp(self):
        self.base=test_private.PrivateHTTPTests();self.base.setUp();self.addCleanup(self.base.doCleanups)
        self.base.session=self.base.request("/api/create",test_private.CREATE)[2]["session"]

    def test_submissions_require_unlocked_matching_session(self):
        self.assertEqual(self.base.request("/api/submissions")[0],200)
        self.base.request("/api/lock",{})
        self.assertEqual(self.base.request("/api/submissions")[0],409)

    def test_large_identity_save_is_allowed_but_not_large_other_commands(self):
        p=copy.deepcopy(test_private.PROFILE)
        for i in range(9):p["addresses"].append(identity.entry("addresses",street_address="Synthetic"+str(i)+"x"*225,address_line2="y"*240,city="z"*120,region="q"*120))
        body={"profile":p,"version":0}
        self.assertGreater(len(json.dumps(body)),8192)
        self.assertEqual(self.base.request("/api/save",body)[0],200)
        self.assertEqual(self.base.request("/api/upgrade",{"version":1,"acknowledged":"x"*9000})[0],413)
        self.assertEqual(self.base.request("/api/save",{"version":1,"profile":"x"*262144})[0],413)

    def test_all_categories_at_unicode_limits_fit_the_save_boundary(self):
        p=identity.empty()
        p["names"]=[identity.entry("names",full_name="😀"*120,first_name="😀"*120,last_name="😀"*120) for _ in range(10)]
        p["emails"]=[identity.entry("emails",value="a"*240+"@example.com") for _ in range(10)]
        p["phones"]=[identity.entry("phones",value="5550100101",country="US") for _ in range(10)]
        p["addresses"]=[identity.entry("addresses",street_address="😀"*240,address_line2="😀"*240,city="😀"*120,region="😀"*120,postal_code="x"*32,country="US") for _ in range(10)]
        body={"profile":p,"version":0}
        self.assertGreater(len(json.dumps(body)),65536)
        self.assertEqual(self.base.request("/api/save",body)[0],200)


class R1LaunchTests(unittest.TestCase):
    def test_default_or_unacknowledged_workspace_refused_before_keychain(self):
        from privacy_cleanup import private_server
        for args in ([],["--synthetic-workspace"],["--data-dir","/private/tmp/synthetic-r1-unused"]):
            with patch("sys.argv",["private",*args]), patch.object(private_server,"MacKeyStore") as keys, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as result: private_server.main()
                self.assertEqual(result.exception.code,2)
                keys.assert_not_called()

    def test_case_or_spelling_variant_of_personal_store_is_refused(self):
        # Review R2-L2: a synthetic stand-in for the personal default directory.
        import tempfile
        from pathlib import Path
        from privacy_cleanup import private_server
        with tempfile.TemporaryDirectory(dir=test_private.TMP) as temp:
            default = Path(temp) / "Library/Application Support/PrivacyCleanup/private"
            default.mkdir(parents=True, mode=0o700)
            text = str(default)
            variants = [text, text + "/", text.lower(), text + "/../private",
                        text.replace("PrivacyCleanup", "privacycleanup").replace("/private", "/PRIVATE")]
            with patch.object(private_server, "default_directory", return_value=default):
                for variant in variants:
                    self.assertTrue(private_server.is_personal_store(variant), variant)
                self.assertFalse(private_server.is_personal_store(str(Path(temp) / "synthetic-other")))
                with patch("sys.argv", ["private", "--synthetic-workspace", "--data-dir", variants[2]]), \
                        patch.object(private_server, "MacKeyStore") as keys, patch.object(private_server, "install") as guard, \
                        contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as result: private_server.main()
                self.assertEqual(result.exception.code, 2)
                keys.assert_not_called(); guard.assert_not_called()
