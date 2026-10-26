"""Batch 4 workstream 4: a live preview of what unsaved information would make available.
Synthetic vault only. The preview validates and plans in memory and never writes."""
import copy
import unittest

from privacy_cleanup.domain import RuleError
from test_coverage import JourneyBase, Vault


@unittest.skipIf(Vault is None, "Preview journeys require the encryption dependency")
class PreviewTests(JourneyBase, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.connect(None)

    def preview(self, draft, session=None):
        return self.flow.preview(session or self.session, draft)

    def states(self, result):
        return {row["broker"]: row["state"] for row in result["rows"]}

    def test_the_saved_identity_previews_as_unchanged_and_matches_the_plan(self):
        result = self.preview(copy.deepcopy(self.identity))
        self.assertTrue(result["ready"])
        self.assertFalse(result["changed"])
        self.assertEqual(self.states(result), {p["broker"]: p["state"] for p in self.state()["workflow"]["plan"]})

    def test_a_draft_shows_what_it_would_unlock_without_saving_anything(self):
        before = (self.state()["profile_version"], self.vault.db.total_changes)
        draft = copy.deepcopy(self.identity)
        draft["residence"] = {"country": "US", "region": "TX"}
        result = self.preview(draft)
        self.assertTrue(result["changed"])
        states = self.states(result)
        self.assertEqual(states["lusha"], "route_not_available_in_jurisdiction")  # California only.
        self.assertEqual(states["hunter"], "ready_to_prepare_email")  # A work address marked as such.
        self.assertEqual(states["cognism"], "ready_to_prepare_email")
        self.assertEqual((self.state()["profile_version"], self.vault.db.total_changes), before)
        self.assertEqual(self.vault.read(self.session)["profile"]["residence"], {"country": "US", "region": "CA"})

    def test_missing_information_says_what_would_unlock_it(self):
        draft = copy.deepcopy(self.identity)
        draft["residence"] = {"country": "", "region": ""}
        rows = {row["broker"]: row for row in self.preview(draft)["rows"]}
        self.assertEqual(rows["cognism"]["state"], "needs_information")
        self.assertTrue(any("residence" in need.lower() for need in rows["cognism"]["missing"]))

    def test_an_invalid_draft_pauses_the_preview_and_writes_nothing(self):
        before = self.vault.db.total_changes
        draft = copy.deepcopy(self.identity)
        draft["emails"] = []  # Saved identifiers are retired, never deleted.
        result = self.preview(draft)
        self.assertEqual((result["ready"], result["rows"]), (False, []))
        self.assertTrue(result["problem"])
        self.assertEqual(self.vault.db.total_changes, before)

    def test_preview_needs_the_current_session(self):
        with self.assertRaises(RuleError):
            self.preview(copy.deepcopy(self.identity), session="stale")


class StateListTests(unittest.TestCase):
    def test_the_page_state_list_matches_the_contracts_table(self):
        import re
        from pathlib import Path
        from privacy_cleanup import contracts
        source = (Path(__file__).resolve().parent.parent / "privacy_cleanup/static/private.js").read_text()
        block = re.search(r"const US_STATES = \[(.*?)\];", source, re.S).group(1)
        pairs = dict(re.findall(r'\["([A-Z]{2})","([^"]+)"\]', block))
        self.assertEqual(pairs, contracts.US_STATES)


if __name__ == "__main__":
    unittest.main()
