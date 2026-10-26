"""Offline evidence-contract tests; no broker or private store is accessed."""
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from privacy_cleanup.domain import digest
from privacy_cleanup.requirements import REQUIREMENTS
from privacy_cleanup.routes import FIELDS, ROUTES, catalog, route

NOW = datetime(2026, 10, 9, tzinfo=timezone.utc).timestamp()  # Latest catalog research date.


class RequirementsTests(unittest.TestCase):
    def test_each_catalog_broker_has_purpose_evidence_gaps_and_a_next_step(self):
        self.assertEqual(set(ROUTES), set(REQUIREMENTS))
        self.assertEqual(len(ROUTES), 12)
        for item in catalog(NOW):
            guide = item["requirements"]
            for key in ("scope", "route_evidence", "verification", "completion", "follow_up", "fallback", "gaps", "next_action", "acceptance", "pilot_checks"):
                self.assertTrue(guide[key], (item["id"], key))
            self.assertEqual(guide["server_validation"], "untested")

    def test_known_requirements_have_evidence_unknown_is_never_optional(self):
        for item in catalog(NOW):
            inputs = item["requirements"]["inputs"]
            self.assertEqual(len({f["id"] for f in inputs}), len(inputs))
            for f in inputs:
                self.assertIn(f["need"], {"required", "conditional", "optional", "unknown"})
                self.assertIn(f["basis"], {"official_documentation", "observed_form", "unverified"})
                if f["need"] != "unknown":
                    self.assertTrue(f["sources"])
                    self.assertNotEqual(f["basis"], "unverified")
                if f["basis"] == "unverified":
                    self.assertEqual(f["need"], "unknown")
                for source in f["sources"]:
                    self.assertTrue(source.startswith("https://"))
                    self.assertIn(source, item["sources"])

    def test_epsilon_draft_rules_do_not_claim_broker_required_or_optional(self):
        item = route("epsilon")
        fields = {f["id"]: f for f in item["draft_fields"]}
        self.assertEqual(set(fields), set(item["fields"]))
        self.assertEqual({key for key, f in fields.items() if f["local_required"]}, set(item["required_for_preparation"]))
        self.assertEqual(fields["email"]["broker_need"], "required")
        for key in ("first_name", "last_name", "street_address", "city", "region", "postal_code", "birth_date"):
            self.assertEqual(fields[key]["broker_need"], "unknown")
        for key, f in fields.items():
            self.assertEqual(f["max_length"], FIELDS[key][1])
        self.assertNotIn("optional", fields["birth_date"]["label"].lower())

    def test_unknown_flows_cannot_silently_gain_preparation(self):
        for broker in ("peopleconnect", "acxiom", "whitepages", "peoplefinders", "spokeo", "beenverified"):
            item = route(broker)
            self.assertEqual(item["readiness"], "guidance_only")
            self.assertEqual(item["draft_fields"], [])
            self.assertNotIn("fields", item)

    def test_digest_binds_requirements_and_draft_rules(self):
        item = next(r for r in catalog(NOW) if r["id"] == "epsilon")
        self.assertEqual(item["source_digest"], digest(route("epsilon")))
        with patch.dict(REQUIREMENTS["epsilon"], {"verification": "Changed requirement, still unverified"}):
            changed = next(r for r in catalog(NOW) if r["id"] == "epsilon")
            self.assertNotEqual(item["source_digest"], changed["source_digest"])

    def test_client_edits_do_not_mutate_registry(self):
        item = route("epsilon")
        item["requirements"]["inputs"][0]["need"] = "optional"
        item["draft_fields"][0]["local_required"] = False
        self.assertEqual(route("epsilon")["requirements"]["inputs"][0]["need"], "required")
        self.assertTrue(route("epsilon")["draft_fields"][0]["local_required"])

    def test_source_freshness_does_not_imply_route_verified(self):
        for item in catalog(NOW):
            self.assertTrue(item["source_fresh"])
            self.assertEqual(item["requirements"]["server_validation"], "untested")
        self.assertTrue(all(not item["source_fresh"] for item in catalog(NOW + 31 * 86400)))
