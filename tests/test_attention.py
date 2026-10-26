"""Batch 4 workstream 3: the attention home. Synthetic vault, no sender; the owner sends emails
from their own mail app and records broker replies."""
import unittest

from test_coverage import JourneyBase, Vault


def groups(state):
    return {a["broker"]: (a["group"], a["label"]) for a in state["attention"]["items"]}


@unittest.skipIf(Vault is None, "Attention journeys require the encryption dependency")
class AttentionTests(JourneyBase, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.connect(None)

    def item(self, broker):
        return next(a for a in self.state()["attention"]["items"] if a["broker"] == broker)

    def send(self, broker, result="sent"):
        self.run_("self_sent", broker, fingerprint=self.case(broker)["execution"]["fingerprint"], result=result)

    def reply(self, broker, result, received_on=None):
        case = self.case(broker)
        data = {"result": result, "note": "Synthetic reply."}
        if received_on:
            data["received_on"] = received_on
        self.cases.command(self.session, case["id"], case["version"], "response", data)

    def review_on(self, broker, date):
        case = self.case(broker)
        self.cases.command(self.session, case["id"], case["version"], "review", {"date": date})

    def test_nothing_needs_attention_is_a_real_state(self):
        home = self.state()["attention"]
        self.assertEqual(home, {"items": [], "counts": {"do": 0, "review": 0, "waiting": 0, "recorded": 0}})

    def test_a_request_moves_through_every_group(self):
        self.flow_act("plan")
        self.flow_act("resume")
        self.run_("prepare", "apollo", drop_acknowledged=False)
        self.assertEqual(groups(self.state())["apollo"], ("review", "Ready to review"))
        self.run_("approve", "apollo", fingerprint=self.case("apollo")["execution"]["fingerprint"], acknowledged=True)
        self.assertEqual(groups(self.state())["apollo"], ("review", "Approved, not sent"))
        self.send("apollo")
        waiting = self.item("apollo")
        self.assertEqual((waiting["group"], waiting["label"], waiting["detail"]), ("waiting", "Waiting on broker", "No deadline was stated."))
        self.assertTrue(waiting["date"].startswith("2026-10-09T"), "A recorded moment stays a full timestamp")
        self.reply("apollo", "acknowledged")
        self.assertEqual(groups(self.state())["apollo"], ("waiting", "Waiting on broker"))
        self.reply("apollo", "verification_required", received_on="2026-10-09")
        action = self.item("apollo")
        self.assertEqual((action["group"], action["label"], action["source"], action["date"]),
                         ("do", "Verify with broker", "reply you recorded", "2026-10-09"))
        self.reply("apollo", "verification_completed")
        self.assertEqual(groups(self.state())["apollo"], ("waiting", "Waiting on broker"))
        self.reply("apollo", "deletion_reported")
        done = self.item("apollo")
        self.assertEqual((done["group"], done["label"], done["tone"]), ("recorded", "Broker reports deletion", "done"))
        self.assertIn("not proof", done["detail"])
        counts = self.state()["attention"]["counts"]
        self.assertEqual(counts["recorded"], 1)

    def test_waiting_is_never_overdue_without_a_chosen_date(self):
        self.ready("apollo")
        self.send("apollo")
        for days in (0, 30, 365):
            self.time += days * 86400
            item = self.item("apollo")
            self.assertEqual(item["group"], "waiting")
            self.assertNotIn("overdue", (item["label"] + item["detail"]).lower())

    def test_a_chosen_review_date_waits_then_asks_for_you(self):
        self.ready("apollo")
        self.send("apollo")
        self.review_on("apollo", "2026-10-20")
        waiting = self.item("apollo")
        self.assertEqual((waiting["group"], waiting["check_on"]), ("waiting", "2026-10-20"))
        self.assertEqual(waiting["detail"], "You chose a date to check again.")
        self.time += 11 * 86400
        due = self.item("apollo")
        self.assertEqual((due["group"], due["label"], due["source"], due["date"]), ("do", "Review date", "date you chose", "2026-10-20"))

    def test_uncertain_and_refused(self):
        self.ready("apollo", "contactout")
        self.send("apollo", result="unsure")
        self.assertEqual(groups(self.state())["apollo"], ("do", "Uncertain"))
        self.send("contactout")
        self.reply("contactout", "denied")
        refused = self.item("contactout")
        self.assertEqual((refused["group"], refused["label"], refused["tone"]), ("recorded", "Refused", "error"))


if __name__ == "__main__":
    unittest.main()
