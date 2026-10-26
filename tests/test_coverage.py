"""R4 coverage: reviewed owner-email contracts, per-route jurisdiction and freshness.

Synthetic identities, memory keys and a loopback fake provider only. No broker is contacted.
"""
import copy
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from privacy_cleanup import contracts, identity, requirements, routes
from privacy_cleanup.domain import RuleError, digest
from privacy_cleanup.worker import GmailTransport, Worker
from scripts.check_public_tree import REVIEWED, audit
from test_public_tree import safe_files

try:
    from privacy_cleanup.vault import Vault
except ImportError:
    Vault = None

def at(day):
    return datetime.fromisoformat(day + "T12:00:00+00:00").timestamp()


NOW = at("2026-10-09")  # Latest contract check date.
DAY = 86400
SENDING = {"apollo": "apollo-delete-v1", "cognism": "cognism-delete-v1", "lusha": "lusha-erasure-v1",
           "contactout": "contactout-erasure-v1", "hunter": "hunter-delete-v1"}
# Content digest of every contract revision. Any edit (recipient, wording, jurisdiction, dates or
# sources) must bump the version, add a "changes" entry and a new digest here; the version bump
# invalidates approvals of the old revision. A pinned recipient is never edited silently.
PINNED = {
    "apollo-delete-v1": (2, "169a7609a3d3b88f875d1cb46ad566e5728c8b47da6e6a27d8e5799f94d9b8db"),
    "cognism-delete-v1": (1, "14a9e91a695b037547348a0c3ade3214b22e92eeda4711f11d9f43c61a76837e"),
    "lusha-erasure-v1": (1, "7c8a4a2bfdb6f49c77b890733c0cba27d11c2f34601cfe5df0d25f1ee0230e3c"),
    "contactout-erasure-v1": (1, "ee4acd6f6b99cc8c011807e44a738a72b4a6c4a2211ed544d70313e75f2002ae"),
    "hunter-delete-v1": (3, "97bbd3751451f9690b0d53e18c66ed7b0bd87ad5d840ed80789f3344b2d98106"),
    "self-test-v1": (1, "b1bf2b934208eba92288a5db5a1ff39725daf0db417d62e6ceacbabe5b800943"),
}
NAME, EMAIL = "Avery CipherCanary Example", "cipher-canary@example.invalid"
COGNISM_STATES = {"CA": "California", "CO": "Colorado", "CT": "Connecticut", "FL": "Florida", "MT": "Montana",
                  "OR": "Oregon", "TX": "Texas", "VA": "Virginia", "UT": "Utah"}
# California is excluded: its notice lists only a web link or phone for deletion requests (v2).
HUNTER_STATES = {"TX", "VA", "CO", "DE", "IA", "NH", "NJ", "NE", "MN", "MD", "OR", "MT", "KY", "IN", "RI"}
CA_ROUTES = [b for b in SENDING if b != "hunter"]  # Every route a California resident qualifies for.


def outcomes(cognism, lusha, hunter, anywhere="eligible"):
    return {"apollo": anywhere, "contactout": anywhere, "cognism": cognism, "lusha": lusha, "hunter": hunter}


# Residence → expected per-route outcome. New Jersey is named by Hunter but not by Cognism: one
# route's evidence never extends another's.
RESIDENCES = {
    "ca": ({"country": "US", "region": "California"}, outcomes("eligible", "eligible", "not_covered")),
    "tx": ({"country": "US", "region": "TX"}, outcomes("eligible", "not_covered", "eligible")),
    "nj": ({"country": "US", "region": "New Jersey"}, outcomes("not_covered", "not_covered", "eligible")),
    "ny": ({"country": "US", "region": "NY"}, outcomes("not_covered", "not_covered", "not_covered")),
    "no_state": ({"country": "US", "region": ""}, outcomes("needs_residence", "needs_residence", "needs_residence")),
    "unrecognized": ({"country": "US", "region": "Calif."}, outcomes("needs_residence", "needs_residence", "needs_residence")),
    "unknown": ({"country": "", "region": ""}, outcomes("needs_residence", "needs_residence", "needs_residence")),
    "de": ({"country": "DE", "region": ""}, outcomes("not_covered", "not_covered", "not_covered")),
}


def fields(contract_id, state=None):
    item = contracts.CONTRACTS[contract_id]
    state = state or ("Texas" if contract_id == "hunter-delete-v1" else "California")
    return {key: value for key, value in (("full_name", NAME), ("email", EMAIL), ("us_state", state)) if key in item["fields"]}


class ContractEvidenceTests(unittest.TestCase):
    def test_every_sending_route_has_one_reviewed_contract_and_its_own_evidence(self):
        self.assertEqual({k for k, r in routes.ROUTES.items() if r["readiness"] == "owner_email"}, set(SENDING))
        self.assertEqual({c["recipient"] for c in contracts.CONTRACTS.values() if c["broker"]}, REVIEWED)
        for broker, contract_id in SENDING.items():
            item, route = contracts.contract(contract_id), routes.route(broker)
            self.assertEqual((contracts.BY_BROKER[broker], route["contract"], item["broker"]), (contract_id,) * 2 + (broker,))
            self.assertEqual((route["method"], item["method"]), ("owner_email", "owner_email"))
            self.assertEqual(route["checked"], item["checked"], broker)
            self.assertEqual(route["sources"], item["sources"], broker)
            self.assertEqual(route["purpose"], item["purpose"], broker)
            self.assertEqual(routes.capability(broker), "automated_simulation")
            self.assertIn("simulation", route["automation"].lower())
            self.assertEqual([f["id"] for f in requirements.requirements(broker)["inputs"]], item["fields"])
            # Each contract cites only its own broker's official domain (subdomains such as a help center included).
            domain = item["sources"][0].split("/")[2].removeprefix("www.")
            self.assertTrue(all(s.split("/")[2] == domain or s.split("/")[2].endswith("." + domain) for s in item["sources"]), broker)
            self.assertTrue(item["recipient"].endswith("@" + domain), broker)
            for other, other_id in SENDING.items():
                if other != broker:
                    self.assertNotIn(contracts.CONTRACTS[other_id]["entity"].split()[0], item["jurisdiction"]["basis"])
            self.assertEqual(item.get("email_use"), "professional" if broker == "hunter" else None, broker)

    def test_capability_levels_are_authored_for_every_route_and_never_above_simulation(self):
        self.assertEqual(set(routes.CAPABILITY), set(routes.ROUTES))
        ladder = ["research_only", "guided_manual", "local_preparation", "automated_simulation", "pilot_tested", "maintained_operation"]
        for key, level in routes.CAPABILITY.items():
            self.assertLessEqual(ladder.index(level), ladder.index("automated_simulation"), key)
            if routes.ROUTES[key]["readiness"] == "guidance_only":
                self.assertEqual(level, "research_only", key)
        self.assertEqual(routes.capability("not-a-route"), "research_only")

    def test_contract_revisions_are_pinned_and_changes_are_recorded(self):
        self.assertEqual(set(contracts.CONTRACTS), set(PINNED))
        for key, item in contracts.CONTRACTS.items():
            self.assertEqual((item["version"], digest(item)), PINNED[key],
                             key + " changed: bump its version, record the change and pin the new digest")
            versions = [c["version"] for c in item["changes"]]
            self.assertEqual(versions, sorted(set(versions)))
            self.assertEqual(versions[-1], item["version"])
            self.assertEqual(item["changes"][-1]["checked"], item["checked"])

    def test_reviewed_recipients_are_allowed_only_in_the_contract_file(self):
        for contract_id in SENDING.values():
            address = contracts.CONTRACTS[contract_id]["recipient"].encode()
            files = safe_files(); files["privacy_cleanup/contracts.py"] = address
            self.assertEqual(audit(files), [])
            for name in ("README.md", "tests/test_coverage.py", "docs/ARCHITECTURE.md", "privacy_cleanup/routes.py"):
                files = safe_files(); files[name] = address
                self.assertIn("non-example email (match withheld)", audit(files), name)


class DocumentedMatrixTests(unittest.TestCase):
    def test_documented_capability_matrix_matches_the_code(self):
        from pathlib import Path as _Path
        from privacy_cleanup.workflow import RESEARCH
        text = (_Path(__file__).resolve().parent.parent / "docs" / "COVERAGE.md").read_text()
        table = text.split("## Capability matrix", 1)[1].split("\n## ", 1)[0]
        rows = [line for line in table.splitlines() if line.startswith("| ") and not line.startswith("| Route") and "---" not in line]
        labels = {"research_only": "Research only", "local_preparation": "Local preparation", "automated_simulation": "Automated simulation"}
        for key, item in routes.ROUTES.items():
            row = next((r for r in rows if item["name"] in r.split("|")[1]), None)
            self.assertIsNotNone(row, key)
            freshness = routes.freshness(key, NOW)
            self.assertIn("| " + labels[routes.capability(key)] + " |", row, key)
            self.assertIn(item["checked"], row, key)
            if freshness["review_by"]:
                self.assertIn(freshness["review_by"], row, key)
        for key, name in RESEARCH.items():
            if key not in routes.ROUTES:
                row = next((r for r in rows if name in r.split("|")[1]), None)
                self.assertIsNotNone(row, key)
                self.assertIn("| Research only |", row, key)


class JurisdictionTests(unittest.TestCase):
    def test_state_limits_fail_closed_per_route(self):
        for label, (residence, expected) in RESIDENCES.items():
            for broker, outcome in expected.items():
                item = contracts.contract(SENDING[broker])
                self.assertEqual(contracts.eligibility(item, residence)[0], outcome, (label, broker))
                self.assertEqual(contracts.eligible(item, residence) is None, outcome == "eligible", (label, broker))
        cognism, lusha = contracts.contract("cognism-delete-v1"), contracts.contract("lusha-erasure-v1")
        for code, name in COGNISM_STATES.items():
            for spelling in (code, code.lower(), name, name.upper(), " " + name + " "):
                self.assertIsNone(contracts.eligible(cognism, {"country": "US", "region": spelling}), spelling)
        covered = [code for code in contracts.US_STATES if contracts.eligible(cognism, {"country": "US", "region": code}) is None]
        self.assertEqual(sorted(covered), sorted(COGNISM_STATES))
        covered = [code for code in contracts.US_STATES if contracts.eligible(lusha, {"country": "US", "region": code}) is None]
        self.assertEqual(covered, ["CA"])
        hunter = contracts.contract("hunter-delete-v1")
        covered = {code for code in contracts.US_STATES if contracts.eligible(hunter, {"country": "US", "region": code}) is None}
        self.assertEqual(covered, HUNTER_STATES)

    def test_the_stated_residence_is_bound_to_each_contracts_own_evidence(self):
        cognism, lusha = contracts.contract("cognism-delete-v1"), contracts.contract("lusha-erasure-v1")
        self.assertIn("I am a resident of Texas.", contracts.render(cognism, fields("cognism-delete-v1", "Texas"))["body"])
        self.assertIn("I am a resident of California.", contracts.render(lusha, fields("lusha-erasure-v1"))["body"])
        # Texas is covered by Cognism's evidence, which proves nothing for Lusha.
        for item, state in ((lusha, "Texas"), (cognism, "New York"), (cognism, "TX"), (cognism, "Calif."), (lusha, "california")):
            with self.assertRaises(RuleError, msg=(item["id"], state)):
                contracts.render(item, fields(item["id"], state))
        hunter = contracts.contract("hunter-delete-v1")
        self.assertIn("I am a resident of New Jersey.", contracts.render(hunter, fields("hunter-delete-v1", "New Jersey"))["body"])
        with self.assertRaises(RuleError):
            contracts.render(hunter, fields("hunter-delete-v1", "New York"))
        for contract_id in ("apollo-delete-v1", "contactout-erasure-v1"):
            with self.assertRaises(RuleError):
                contracts.render(contracts.contract(contract_id), dict(fields(contract_id), us_state="California"))
        self.assertNotIn("resident", contracts.render(contracts.contract("apollo-delete-v1"), fields("apollo-delete-v1"))["body"])
        self.assertEqual(contracts.state_name({"country": "US", "region": "tx"}), "Texas")
        for residence in ({"country": "US", "region": ""}, {"country": "CA", "region": "ON"}, {}, None):
            self.assertIsNone(contracts.state_name(residence))

    def test_one_identity_renders_five_distinct_exact_messages(self):
        messages = {broker: contracts.render(contracts.contract(cid), fields(cid)) for broker, cid in SENDING.items()}
        self.assertEqual({m["from"] for m in messages.values()}, {EMAIL})
        self.assertEqual({b: m["to"] for b, m in messages.items()}, {b: contracts.CONTRACTS[c]["recipient"] for b, c in SENDING.items()})
        self.assertEqual(len({m["body"] for m in messages.values()}), 5)
        for broker, message in messages.items():
            self.assertIn("Email address: " + EMAIL + "\n", message["body"])
            # Hunter's record is the professional address itself; no name is disclosed.
            self.assertEqual(NAME in message["body"], broker != "hunter", broker)


class CoverageLineTests(unittest.TestCase):
    """Batch 4, workstream 7: each route says who it covers, from its own contract or scope."""

    def test_each_route_states_who_it_covers_from_its_contract(self):
        self.assertEqual(routes.coverage("apollo"), "Anyone, wherever they live")
        self.assertEqual(routes.coverage("lusha"), "Residents of California")
        cognism = routes.coverage("cognism")
        self.assertTrue(cognism.startswith("Residents of 9 US states: California, Colorado"))
        self.assertIn("Texas", cognism)
        hunter = routes.coverage("hunter")
        self.assertTrue(hunter.startswith("Residents of 15 US states:") and hunter.endswith("; work email addresses only"))
        self.assertIn("United States", routes.coverage("epsilon"))
        self.assertEqual(routes.coverage("acxiom"), "Set by the broker; see its official guidance")

    def test_the_line_follows_the_contract_and_never_binds_approvals(self):
        narrowed = copy.deepcopy(contracts.CONTRACTS[contracts.BY_BROKER["apollo"]])
        narrowed["jurisdiction"] = {"countries": ["US"], "us_regions": ["NY"], "basis": "Synthetic"}
        with patch.dict(contracts.CONTRACTS, {narrowed["id"]: narrowed}):
            self.assertEqual(routes.coverage("apollo"), "Residents of New York")
        item = next(i for i in routes.catalog(NOW) if i["id"] == "hunter")
        self.assertEqual(item["covers"], routes.coverage("hunter"))
        self.assertNotIn("covers", routes.route("hunter"))
        self.assertEqual(item["source_digest"], digest(routes.route("hunter")))


class FreshnessTests(unittest.TestCase):
    def test_freshness_explains_why_a_route_is_paused(self):
        item = contracts.contract("cognism-delete-v1")
        self.assertEqual(contracts.freshness(item, at("2026-10-08")), {"fresh": True, "checked": "2026-10-08", "review_by": "2026-11-07", "reason": None})
        self.assertTrue(contracts.fresh(item, at("2026-11-07")))
        late = contracts.freshness(item, at("2026-11-08"))
        self.assertFalse(late["fresh"])
        self.assertIn("2026-10-08", late["reason"]); self.assertIn("2026-11-07", late["reason"])
        self.assertIn("this route only", late["reason"])
        self.assertIn("clock", contracts.freshness(item, at("2026-10-07"))["reason"])
        self.assertTrue(all(contracts.fresh(contracts.contract(c), NOW) for c in SENDING.values()))
        self.assertTrue(contracts.fresh(contracts.contract(contracts.SELF_TEST), NOW + 400 * DAY))

    def test_a_stale_contract_marks_only_its_own_route(self):
        stale = dict(contracts.CONTRACTS["cognism-delete-v1"], checked="2026-09-01")
        with patch.dict(contracts.CONTRACTS, {"cognism-delete-v1": stale}):
            catalog = {r["id"]: r for r in routes.catalog(NOW)}
        self.assertFalse(catalog["cognism"]["freshness"]["fresh"])
        self.assertIn("2026-09-01", catalog["cognism"]["freshness"]["reason"])
        self.assertTrue(all(r["freshness"]["fresh"] for k, r in catalog.items() if k != "cognism"))

    def test_worker_refuses_only_the_stale_or_changed_contract(self):
        class Recording:
            kind, needs_authority = "fake", False

            def __init__(self):
                self.messages = []

            def send(self, message, job_id, authority=None):
                self.messages.append(message)
                return {"outcome": "accepted", "reason": "provider_accepted", "provider_message_id": "rec-%d" % len(self.messages)}

        def envelope(n, contract_id, version=None, values=None):
            item = contracts.contract(contract_id)
            version = item["version"] if version is None else version
            values = values or fields(contract_id)
            return {"type": "send", "envelope": {"job_id": str(n) * 32, "contract_id": contract_id, "contract_version": version,
                    "fields": values, "fingerprint": contracts.fingerprint(item, contracts.render(item, values))}}

        transport = Recording()
        worker = Worker(transport, sleep=lambda s: None, now=lambda: NOW)
        stale = dict(contracts.CONTRACTS["cognism-delete-v1"], checked="2026-09-01")
        with patch.dict(contracts.CONTRACTS, {"cognism-delete-v1": stale}):
            replies = [worker.handle(envelope(n, cid)) for n, cid in enumerate(SENDING.values(), 1)]
        self.assertEqual([r["reason"] for r in replies], ["provider_accepted", "refused_source_review_due"] + ["provider_accepted"] * 3)
        self.assertEqual(worker.handle(envelope(6, "lusha-erasure-v1", version=2))["reason"], "refused_contract_changed")
        self.assertEqual(worker.handle(envelope(8, "hunter-delete-v1", version=1))["reason"], "refused_contract_changed")
        bad = envelope(7, "cognism-delete-v1")
        bad["envelope"]["fields"]["us_state"] = "New York"
        self.assertEqual(worker.handle(bad)["reason"], "refused_invalid_fields")
        self.assertEqual([m["to"] for m in transport.messages],
                         [contracts.CONTRACTS[c]["recipient"] for b, c in SENDING.items() if b != "cognism"])


class EmailUseRecordTests(unittest.TestCase):
    def test_email_use_is_recorded_by_the_owner_and_never_inferred(self):
        legacy = {"full_name": NAME, "email": "work-canary@synthetic-employer.invalid", "city": "", "region": "",
                  "postal_code": "", "country": ""}
        self.assertEqual(identity.from_legacy(legacy)["emails"][0]["use"], "unknown")
        current = identity.empty()
        current["names"] = [identity.entry("names", full_name=NAME, preferred=True)]
        current["emails"] = [identity.entry("emails", value="work-canary@synthetic-employer.invalid", reachable=True),
                             identity.entry("emails", value=EMAIL, reachable=True, use="personal")]
        self.assertEqual(identity.validate(current)["emails"][0]["use"], "unknown")
        older = copy.deepcopy(current)
        older["schema"] = 1
        for row in older["emails"]:
            del row["use"]
        upgraded = identity.upgrade(older)
        self.assertEqual((upgraded["schema"], [r["use"] for r in upgraded["emails"]]), (2, ["unknown", "unknown"]))
        self.assertEqual(identity.upgrade(current), identity.validate(current))
        for bad in (older, dict(current, emails=[dict(current["emails"][0], use="work")]),
                    dict(current, emails=[{k: v for k, v in current["emails"][0].items() if k != "use"}])):
            with self.assertRaises(RuleError):
                identity.validate(bad)


class FakeProviderSequenceTests(unittest.TestCase):
    def test_a_scripted_sequence_drives_partial_failure_then_falls_back_to_the_mode(self):
        from privacy_cleanup.worker import FakeTransport
        from scripts.fake_provider import FakeProvider
        provider = FakeProvider(sequence=["accept", "reject", "server_error"]).start(); self.addCleanup(provider.stop)
        message = contracts.render(contracts.contract("apollo-delete-v1"), fields("apollo-delete-v1"))
        outcomes = [FakeTransport("127.0.0.1", provider.server_port, timeout=2).send(message, str(n) * 32)["outcome"]
                    for n in range(1, 5)]
        self.assertEqual(outcomes, ["accepted", "not_sent", "uncertain", "accepted"])
        self.assertEqual(provider.sequence, [])


class GmailGateTests(unittest.TestCase):
    def test_gmail_still_refuses_every_broker_contract_before_contacting_google(self):
        transport = GmailTransport.local(1)
        authority = {"client_id": "synthetic-client", "client_secret": "synthetic-secret",
                     "refresh_token": "synthetic-refresh", "account_email": EMAIL}
        with patch.object(transport.http, "post", side_effect=AssertionError("no network for broker contracts")):
            for n, contract_id in enumerate(SENDING.values(), 1):
                message = contracts.render(contracts.contract(contract_id), fields(contract_id))
                self.assertEqual(transport.send(message, str(n) * 32, authority),
                                 {"outcome": "not_sent", "reason": "refused_broker_sending_disabled"})


class JourneyBase:
    """A synthetic memory-key vault, a stub sender and helpers shared by the journey tests."""
    def setUp(self):
        from privacy_cleanup.cases import Cases
        from privacy_cleanup.execution import Execution
        from privacy_cleanup.workflow import Workflow
        from test_execution import ACCEPTED, StubWorker
        from test_private import FAST, MemoryKeys, PASS, PROFILE, TMP
        self.Cases, self.Execution, self.Workflow, self.StubWorker, self.ACCEPTED = Cases, Execution, Workflow, StubWorker, ACCEPTED
        self.tmp = tempfile.TemporaryDirectory(dir=TMP); self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "vault"
        self.keys, self.FAST, self.PASS = MemoryKeys(), FAST, PASS
        self.vault = Vault(self.path, self.keys, kdf_log2n=FAST); self.addCleanup(lambda: self.vault.close())
        self.session = self.vault.unlock(PASS, create=True)["session"]
        self.identity = copy.deepcopy(PROFILE)
        self.identity["residence"] = {"country": "US", "region": "CA"}
        self.identity["emails"][0]["use"] = "professional"  # The owner's own choice; never inferred.
        self.vault.save(self.session, self.identity, 0)
        self.time = NOW
        self.connect(StubWorker())

    def connect(self, worker):
        self.worker = worker
        self.cases = self.Cases(self.vault, clock=lambda: self.time)
        self.execution = self.Execution(self.vault, self.cases, worker)
        self.flow = self.Workflow(self.vault, self.cases)

    def state(self):
        return self.cases.state(self.session)

    def case(self, broker):
        return next(c for c in self.state()["cases"] if c["broker"] == broker)

    def plan(self):
        return {p["broker"]: p for p in self.state()["workflow"]["plan"]}

    def flow_act(self, action, **data):
        state = self.state()
        if action == "dispatch" and "fingerprints" not in data:
            # What the owner saw in the send confirmation: every approved batch email.
            data["fingerprints"] = [c["execution"]["fingerprint"] for c in state["cases"]
                                    if c.get("execution_status") == "approved"] or ["none"]
        return self.flow.command(self.session, state["workflow"]["version"], state["profile_version"], action, data)

    def run_(self, action, broker, **data):
        c = self.case(broker)
        return self.execution.command(self.session, c["id"], c["version"], action, data)

    def move(self, residence):
        self.identity["residence"] = residence
        self.vault.save(self.session, self.identity, self.state()["profile_version"])

    def ready(self, *brokers):
        self.flow_act("plan")
        if self.state()["workflow"]["paused"]:
            self.flow_act("resume")
        for broker in brokers:
            self.run_("prepare", broker, drop_acknowledged=False)
            self.run_("approve", broker, fingerprint=self.case(broker)["execution"]["fingerprint"], acknowledged=True)

    def emails(self, *rows):
        """Set the active emails to synthetic (value, use, preferred, reachable) rows. Saved entries are
        edited in place or retired, never deleted, as the identity rules require."""
        saved = self.identity["emails"]
        for index, (value, use, preferred, reachable) in enumerate(rows):
            if index == len(saved):
                saved.append(identity.entry("emails"))
            saved[index].update(value=value, use=use, preferred=preferred, reachable=reachable, retired=False, label="current")
        for row in saved[len(rows):]:
            row.update(retired=True, preferred=False)
        self.vault.save(self.session, self.identity, self.state()["profile_version"])


@unittest.skipIf(Vault is None, "Coverage journeys require the encryption dependency")
class CoverageJourneyTests(JourneyBase, unittest.TestCase):
    def test_one_identity_reaches_every_qualifying_contract_through_the_real_worker(self):
        from privacy_cleanup.dispatch import WorkerClient
        from scripts.fake_provider import FakeProvider
        provider = FakeProvider().start(); self.addCleanup(provider.stop)
        client = WorkerClient.spawn("fake:127.0.0.1:%d" % provider.server_port); self.addCleanup(client.close)
        self.connect(client)
        self.flow_act("plan")
        self.assertEqual({b: self.plan()[b]["state"] for b in SENDING},
                         dict(dict.fromkeys(SENDING, "ready_to_prepare_email"), hunter="route_not_available_in_jurisdiction"))
        self.assertEqual({b: self.plan()[b]["capability"] for b in SENDING}, dict.fromkeys(SENDING, "automated_simulation"))
        self.ready(*CA_ROUTES)
        approved = {b: self.case(b)["execution"]["message"] for b in CA_ROUTES}
        results = self.flow_act("dispatch")["dispatch_results"]
        self.assertEqual(sorted(r["outcome"] for r in results), ["accepted"] * 4)
        # After a move to Texas, the same identity now qualifies for Hunter; earlier history stays as sent.
        self.move({"country": "US", "region": "Texas"})
        self.ready("hunter")
        approved["hunter"] = self.case("hunter")["execution"]["message"]
        self.assertEqual([r["outcome"] for r in self.flow_act("dispatch")["dispatch_results"]], ["accepted"])
        received = {m["to"]: {k: m[k] for k in ("from", "to", "subject", "body")} for m in provider.received}
        self.assertEqual(received, {m["to"]: m for m in approved.values()})
        self.assertEqual(set(received), {contracts.CONTRACTS[c]["recipient"] for c in SENDING.values()})
        self.assertIn("I am a resident of California.", approved["cognism"]["body"])
        self.assertIn("I am a resident of Texas.", approved["hunter"]["body"])
        self.assertNotIn("resident", approved["apollo"]["body"])
        self.assertNotIn(NAME, approved["hunter"]["body"])
        self.assertEqual(self.case("cognism")["execution"]["identifiers"]["us_state"], "profile_residence")
        self.assertEqual(self.flow_act("dispatch")["dispatch_results"], [])
        for path in self.path.iterdir():
            data = path.read_bytes()
            for message in approved.values():
                for value in (message["to"], message["subject"], NAME, "I am a resident of California."):
                    self.assertNotIn(value.encode(), data, "Execution plaintext leaked to disk")

    def test_each_residence_gives_the_correct_per_route_result(self):
        states = {"eligible": "ready_to_prepare_email", "needs_residence": "needs_information",
                  "not_covered": "route_not_available_in_jurisdiction"}
        for label, (residence, expected) in RESIDENCES.items():
            self.move(residence)
            plan = self.plan()
            for broker, outcome in expected.items():
                self.assertEqual(plan[broker]["state"], states[outcome], (label, broker))
                self.assertIsNone(plan[broker]["route_issue"], (label, broker))
                if outcome != "eligible":
                    self.assertTrue(plan[broker]["missing"], (label, broker))
        self.move({"country": "US", "region": "Texas"})
        self.flow_act("plan")
        self.assertFalse(any(c["broker"] == "lusha" for c in self.state()["cases"]))
        self.cases.create(self.session, "lusha", "", "Synthetic out-of-scope case.", True)
        with self.assertRaisesRegex(RuleError, "do not cover your current state"):
            self.run_("prepare", "lusha", drop_acknowledged=False)
        self.ready("cognism")
        self.assertIn("I am a resident of Texas.", self.case("cognism")["execution"]["message"]["body"])
        self.assertEqual(self.worker.envelopes, [])

    def test_moving_states_invalidates_approvals_and_re_evaluates_each_route(self):
        self.ready(*CA_ROUTES)
        self.assertEqual(self.plan()["hunter"]["state"], "route_not_available_in_jurisdiction")
        self.move({"country": "US", "region": "TX"})
        self.assertEqual({b: self.case(b)["execution_status"] for b in CA_ROUTES}, dict.fromkeys(CA_ROUTES, "invalidated"))
        self.assertEqual(self.plan()["hunter"]["state"], "ready_to_prepare_email")
        with self.assertRaisesRegex(RuleError, "do not cover"):
            self.run_("prepare", "lusha", drop_acknowledged=False)
        self.run_("prepare", "cognism", drop_acknowledged=False)
        self.assertIn("Texas", self.case("cognism")["execution"]["message"]["body"])
        self.assertEqual(self.flow_act("dispatch")["dispatch_results"], [])
        self.assertEqual(self.worker.envelopes, [])

    def test_a_stale_contract_pauses_only_its_own_route(self):
        self.ready(*CA_ROUTES)
        stale = dict(contracts.CONTRACTS["cognism-delete-v1"], checked="2026-09-01")
        with patch.dict(contracts.CONTRACTS, {"cognism-delete-v1": stale}):
            self.assertEqual({b: self.case(b)["execution_status"] for b in CA_ROUTES},
                             dict(dict.fromkeys(CA_ROUTES, "approved"), cognism="source_review_due"))
            self.assertIn("2026-09-01", self.case("cognism")["next_step"])
            self.assertIn("Other routes are unaffected", self.case("cognism")["next_step"])
            plan = self.plan()
            self.assertEqual(plan["cognism"]["state"], "source_review_due")
            self.assertIn("this route only", plan["cognism"]["route_issue"])
            self.assertEqual(plan["cognism"]["missing"], [], "Route evidence is never reported as missing user data")
            self.assertEqual({plan[b]["state"] for b in CA_ROUTES if b != "cognism"}, {"ready_to_prepare_email"})
            with self.assertRaisesRegex(RuleError, "other routes are unaffected"):
                self.run_("prepare", "cognism", drop_acknowledged=False)
            with self.assertRaisesRegex(RuleError, "approval"):
                self.run_("dispatch", "cognism", fingerprint=self.case("cognism")["execution"]["fingerprint"])
            results = self.flow_act("dispatch")["dispatch_results"]
        self.assertEqual(len(results), 3)
        sent = {e["contract_id"] for e in self.worker.envelopes}
        self.assertEqual(sent, {SENDING[b] for b in CA_ROUTES} - {"cognism-delete-v1"})
        self.assertEqual(self.case("cognism")["execution_status"], "approved", "Staleness is evaluated live and never rewrites the job")

    def test_a_stale_route_is_paused_before_anything_is_prepared(self):
        self.flow_act("plan")
        stale = dict(contracts.CONTRACTS["lusha-erasure-v1"], checked="2026-08-01")
        with patch.dict(contracts.CONTRACTS, {"lusha-erasure-v1": stale}):
            self.assertEqual(self.case("lusha")["execution_status"], "source_review_due")
            self.assertEqual(self.case("cognism")["execution_status"], "not_prepared")
            self.assertEqual(self.plan()["lusha"]["state"], "source_review_due")
        self.time = NOW + 31 * DAY
        self.assertEqual({b: self.case(b)["execution_status"] for b in CA_ROUTES}, dict.fromkeys(CA_ROUTES, "source_review_due"))

    def test_a_contract_version_bump_invalidates_only_that_routes_approval(self):
        self.ready(*CA_ROUTES)
        bumped = dict(contracts.CONTRACTS["lusha-erasure-v1"], version=2)
        with patch.dict(contracts.CONTRACTS, {"lusha-erasure-v1": bumped}):
            self.assertEqual({b: self.case(b)["execution_status"] for b in CA_ROUTES},
                             dict(dict.fromkeys(CA_ROUTES, "approved"), lusha="invalidated"))
            self.run_("prepare", "lusha", drop_acknowledged=False)
            job = self.case("lusha")["execution"]
            self.assertEqual((job["contract_version"], job["contract"]["version"]), (2, 2))
            self.run_("approve", "lusha", fingerprint=job["fingerprint"], acknowledged=True)
            self.run_("dispatch", "lusha", fingerprint=job["fingerprint"])
        self.assertEqual([(e["contract_id"], e["contract_version"]) for e in self.worker.envelopes], [("lusha-erasure-v1", 2)])

    def test_submissions_show_each_email_as_stored_never_as_today(self):
        self.ready("cognism", "apollo")
        self.run_("dispatch", "cognism", fingerprint=self.case("cognism")["execution"]["fingerprint"])
        sent = copy.deepcopy(self.case("cognism")["execution"]["message"])
        renamed = copy.deepcopy(self.identity)
        renamed["names"][0]["full_name"] = "Robin Renamed Example"
        renamed["residence"] = {"country": "US", "region": "Oregon"}
        self.vault.save(self.session, renamed, self.state()["profile_version"])
        # Simulate an older R3 entry stored before contract details were kept with each email.
        with self.vault.mutex, self.vault.db:
            self.vault.db.execute("BEGIN IMMEDIATE")
            case = next(c for c in self.cases._load() if c["broker"] == "apollo")
            del case["execution"]["contract"]
            self.cases._save(case)
        changed = dict(contracts.CONTRACTS["cognism-delete-v1"], version=2, purpose="A later, different purpose")
        with patch.dict(contracts.CONTRACTS, {"cognism-delete-v1": changed}):
            history = self.cases.submissions(self.session)
        emails = {e["broker"]: e for e in history["emails"]}
        self.assertEqual(set(emails), {"apollo", "cognism"})
        cognism = emails["cognism"]
        self.assertEqual(cognism["message"], sent)
        self.assertIn("Name: " + NAME, cognism["message"]["body"])
        self.assertIn("California", cognism["message"]["body"])
        self.assertEqual((cognism["contract"]["version"], cognism["contract"]["purpose"]),
                         (1, contracts.CONTRACTS["cognism-delete-v1"]["purpose"]))
        self.assertEqual((cognism["status"], cognism["result"]["outcome"]), ("transport_accepted", "accepted"))
        self.assertEqual(cognism["selected"], ["email", "full_name", "us_state"])
        self.assertIsNone(emails["apollo"]["contract"], "An older entry shows no contract rather than today's")
        self.assertIn(NAME, emails["apollo"]["message"]["body"])
        self.assertIn(cognism["case_id"], history["histories"])
        self.assertEqual(history["entries"], [], "Owner emails are not request revisions")

    def test_after_a_restart_the_first_action_on_an_interrupted_send_succeeds(self):
        """Batch 2 walkthrough defect: the interrupted send was settled by the next command, which
        bumped the case version the page had just loaded and refused that command as stale."""
        self.ready("apollo")
        with self.vault.mutex, self.vault.db:  # A crash after the reservation was committed.
            self.vault.db.execute("BEGIN IMMEDIATE")
            case = next(c for c in self.cases._load() if c["broker"] == "apollo")
            case["execution"]["state"] = "dispatching"
            self.cases._save(case)
        self.connect(self.StubWorker())  # A restarted process waits on nothing.
        loaded = self.case("apollo")
        self.assertEqual(loaded["execution_status"], "uncertain")
        self.assertEqual(loaded["execution"]["result"]["reason"], "interrupted_before_result")
        self.execution.command(self.session, loaded["id"], loaded["version"], "reconcile",
                               {"result": "sent_found", "note": "Synthetic: found in Sent."})
        self.assertEqual(self.case("apollo")["execution_status"], "user_confirmed_sent")
        self.assertEqual(self.worker.envelopes, [])

    def test_route_table_shows_an_existing_email_instead_of_ready(self):
        self.connect(self.StubWorker(self.ACCEPTED, {"outcome": "uncertain", "reason": "interrupted_after_request"}))
        self.ready("apollo", "cognism")
        for broker in ("apollo", "cognism"):  # One at a time: batch order follows random case IDs.
            self.run_("dispatch", broker, fingerprint=self.case(broker)["execution"]["fingerprint"])
        plan = self.plan()
        self.assertEqual((plan["apollo"]["state"], plan["cognism"]["state"]), ("email_already_sent", "email_outcome_uncertain"))
        self.assertEqual(plan["lusha"]["state"], "ready_to_prepare_email")

    def reply(self, broker, result, note="Synthetic broker reply.", **extra):
        c = self.case(broker)
        return self.cases.command(self.session, c["id"], c["version"], "response", dict(result=result, note=note, **extra))

    def test_email_replies_are_appended_and_keep_each_stage_distinct(self):
        self.ready("apollo")
        self.run_("dispatch", "apollo", fingerprint=self.case("apollo")["execution"]["fingerprint"])
        sent = copy.deepcopy(self.case("apollo")["execution"]["message"])
        self.reply("apollo", "acknowledged", received_on="2026-10-08")
        c = self.case("apollo")
        self.assertIn("acknowledged", c["next_step"])
        self.assertEqual((c["outcome"]["sent"], c["outcome"]["acknowledged"], c["outcome"]["broker_reported"]),
                         ("transport_accepted", True, None))
        self.reply("apollo", "verification_required")
        self.assertIn("asked you to verify", self.case("apollo")["next_step"])
        self.assertEqual(self.case("apollo")["outcome"]["verification"], "requested")
        self.reply("apollo", "verification_completed")
        self.assertEqual(self.case("apollo")["outcome"]["verification"], "completed")
        self.reply("apollo", "deletion_reported", note="Synthetic: broker says the profile was deleted.")
        c = self.case("apollo")
        self.assertEqual(c["outcome"]["broker_reported"], "deletion_reported")
        self.assertEqual(c["outcome"]["observed"], "not_applicable", "A broker's report is not an observation")
        self.assertIn("Keep the dated broker statement", c["next_step"])
        replies = [e for e in c["history"] if e["kind"].startswith("broker_")]
        self.assertEqual([e["kind"] for e in replies], ["broker_acknowledged", "broker_verification_required",
                                                        "broker_verification_completed", "broker_deletion_reported"])
        self.assertEqual({e["via"] for e in replies}, {"email"})
        self.assertEqual(replies[0]["received_on"], "2026-10-08")
        self.assertEqual(c["execution"]["message"], sent, "Replies never rewrite what was sent")
        self.assertIn("send_transport_accepted", [e["kind"] for e in c["history"]])
        for bad in ("2026-10-10", "10/08/2026", "2026-02-30"):
            with self.assertRaisesRegex(RuleError, "date the reply arrived"):
                self.reply("apollo", "acknowledged", received_on=bad)

    def test_replies_need_a_sent_request_and_a_reply_confirms_an_uncertain_send(self):
        self.ready("cognism")
        with self.assertRaisesRegex(RuleError, "after the request was sent"):
            self.reply("cognism", "acknowledged")
        self.connect(self.StubWorker({"outcome": "uncertain", "reason": "interrupted_after_request"}))
        self.run_("dispatch", "cognism", fingerprint=self.case("cognism")["execution"]["fingerprint"])
        with self.assertRaisesRegex(RuleError, "after the request was sent"):
            self.reply("cognism", "acknowledged")
        self.run_("reconcile", "cognism", result="broker_replied", note="Synthetic: the broker answered this email.")
        self.assertEqual(self.case("cognism")["execution_status"], "user_confirmed_sent")
        self.assertIn("send_confirmed_by_broker_reply", [e["kind"] for e in self.case("cognism")["history"]])
        self.reply("cognism", "no_record_reported")
        c = self.case("cognism")
        self.assertIn("not proof it never held your data", c["next_step"])
        self.assertEqual(c["outcome"]["broker_reported"], "no_record_reported")

    def test_manual_and_email_replies_share_one_record(self):
        self.identity["names"][0].update(first_name="Avery", last_name="Example")
        self.vault.save(self.session, self.identity, self.state()["profile_version"])
        self.ready()
        epsilon = self.case("epsilon")
        self.flow_act("prepare", id=epsilon["id"], case_version=epsilon["version"], drop_acknowledged=False)
        for action, data in (("approve", {"acknowledged": True}), ("handoff", {"dry_run": False}),
                             ("outcome", {"result": "submitted", "note": "Synthetic confirmation page."})):
            c = self.case("epsilon")
            if action in {"approve", "handoff"}:
                data["fingerprint"] = c["request"]["fingerprint"]
            self.cases.command(self.session, c["id"], c["version"], action, data)
        self.reply("epsilon", "no_record_reported", received_on="2026-10-09")
        c = self.case("epsilon")
        last = c["history"][-1]
        self.assertEqual((last["kind"], last["via"], last["received_on"]), ("broker_no_record_reported", "manual", "2026-10-09"))
        self.assertEqual((c["outcome"]["sent"], c["outcome"]["broker_reported"]), ("submitted_user_reported", "no_record_reported"))
        self.assertEqual(c["outcome"]["last_reply"]["received_on"], "2026-10-09")

    def test_hunter_needs_an_email_the_owner_marked_professional(self):
        work, home = "work-canary@synthetic-employer.invalid", "home-canary@example.invalid"
        self.move({"country": "US", "region": "Texas"})
        failing = [([(work, "unknown", True, True)], True), ([(work, "personal", True, True)], True),
                   ([(work, "professional", True, False)], False),
                   ([(work, "professional", False, True), ("work-two@synthetic-employer.invalid", "professional", False, True)], False)]
        for rows, others_ready in failing:
            self.emails(*rows)
            plan = self.plan()
            self.assertEqual(plan["hunter"]["state"], "needs_information", rows)
            self.assertIn("type of address Work", " ".join(plan["hunter"]["missing"]), rows)
            if others_ready:
                self.assertEqual(plan["apollo"]["state"], "ready_to_prepare_email", rows)
        self.cases.create(self.session, "hunter", "", "Synthetic Hunter case.", True)
        with self.assertRaisesRegex(RuleError, "type of address Work"):
            self.run_("prepare", "hunter", drop_acknowledged=False)
        # A preferred personal email still feeds other routes; Hunter uses the sole professional one.
        self.emails((home, "personal", True, True), (work, "professional", False, True))
        self.ready("hunter", "apollo")
        self.assertEqual(self.case("hunter")["execution"]["message"]["from"], work)
        self.assertEqual(self.case("apollo")["execution"]["message"]["from"], home)
        self.emails((home, "personal", True, True), (work, "personal", False, True))
        self.assertEqual(self.case("hunter")["execution_status"], "invalidated")
        with self.assertRaisesRegex(RuleError, "type of address Work"):
            self.run_("prepare", "hunter", drop_acknowledged=False)
        self.assertEqual(self.worker.envelopes, [])

    def reopen(self):
        self.vault.close()
        self.vault = Vault(self.path, self.keys, kdf_log2n=self.FAST)
        self.session = self.vault.unlock(self.PASS)["session"]
        self.connect(self.worker)

    def test_v4_identity_upgrades_explicitly_and_atomically_to_v5(self):
        from privacy_cleanup import vault as vault_module
        self.move({"country": "US", "region": "Texas"})
        self.emails((EMAIL, "personal", True, True), ("work-canary@synthetic-employer.invalid", "professional", False, True))
        self.ready("apollo")
        # Rewrite the saved identity as an R4-era record (schema 1, no email use) in a v4 store.
        body, revision = self.vault._read_record("profile")
        older = copy.deepcopy(body["profile"])
        older["schema"] = 1
        for row in older["emails"]:
            del row["use"]
        with self.vault.db:
            self.vault._write({"profile": older}, revision)
            self.vault.db.execute("PRAGMA user_version=4")
        shown = self.vault.read(self.session)
        self.assertTrue(shown["migration_required"])
        self.assertEqual([r["use"] for r in shown["profile"]["emails"]], ["unknown", "unknown"])
        self.assertEqual(self.vault._read_record("profile")[0]["profile"]["schema"], 1, "Reading never writes")
        self.assertEqual(self.case("apollo")["execution_status"], "approved")
        for attempt in (lambda: self.vault.save(self.session, self.identity, revision),
                        lambda: self.run_("prepare", "cognism", drop_acknowledged=False)):
            with self.assertRaisesRegex(RuleError, "Upgrade"):
                attempt()
        # A crash after the write leaves the v4 store exactly as it was.
        tables = ("records", "used_nonces", "meta")
        before = {t: self.vault.db.execute("SELECT * FROM " + t).fetchall() for t in tables}
        original = self.vault._write

        def interrupted(*args):
            original(*args)
            raise RuntimeError("Synthetic interrupted upgrade")
        with patch.object(self.vault, "_write", side_effect=interrupted), self.assertRaises(RuntimeError):
            self.vault.upgrade_identity(self.session, revision, True)
        self.assertEqual(self.vault.db.execute("PRAGMA user_version").fetchone()[0], 4)
        self.assertEqual(before, {t: self.vault.db.execute("SELECT * FROM " + t).fetchall() for t in tables})
        self.reopen()
        upgraded = self.vault.upgrade_identity(self.session, revision, True)
        self.assertEqual((self.vault.db.execute("PRAGMA user_version").fetchone()[0], upgraded["version"]), (5, revision + 1))
        stored = self.vault._read_record("profile")[0]["profile"]
        self.assertEqual((stored["schema"], [r["use"] for r in stored["emails"]]), (2, ["unknown", "unknown"]))
        self.assertEqual(self.case("apollo")["execution_status"], "invalidated", "Upgrading invalidates unused approvals")
        self.assertEqual(self.plan()["hunter"]["state"], "needs_information", "Unknown use fails closed after upgrade")
        # A build that accepts only stores up to v4 refuses this one; this build refuses a newer one.
        self.vault.close()
        with patch.object(vault_module, "SCHEMA", 4), self.assertRaisesRegex(RuleError, "Unsupported private database version"):
            Vault(self.path, self.keys, kdf_log2n=self.FAST)
        connection = sqlite3.connect(str(self.path / "vault.sqlite3"))
        connection.execute("PRAGMA user_version=6"); connection.commit(); connection.close()
        with self.assertRaisesRegex(RuleError, "Unsupported private database version"):
            Vault(self.path, self.keys, kdf_log2n=self.FAST)


@unittest.skipIf(Vault is None, "Sender binding requires the encryption dependency")
class SenderBindingTests(JourneyBase, unittest.TestCase):
    """An account-backed sender sends only as its connected address. A saved email, including a
    professional one, never becomes the From address of a message sent through another account."""
    WORK, HOME = "work-canary@synthetic-employer.invalid", "home-canary@example.invalid"

    def setUp(self):
        super().setUp()
        class GmailStub(self.StubWorker):
            kind, simulated, google_port = "gmail", True, 1
        self.connect(GmailStub())
        self.move({"country": "US", "region": "Texas"})  # Covered by Apollo, Cognism, ContactOut and Hunter.

    def connect_account(self, address):
        """Store a synthetic connected-account record, as a completed sign-in would."""
        with self.vault.mutex, self.vault.db:
            self.vault.db.execute("BEGIN IMMEDIATE")
            self.vault.db.execute("DELETE FROM records WHERE id='sender'")
            self.vault._write_record("sender", {"schema": 1, "kind": "gmail", "client_id": "synthetic-client",
                                                "client_secret": "synthetic-secret", "refresh_token": "synthetic-refresh",
                                                "account_email": address, "scope": "synthetic", "connected_at": "t",
                                                "last_test": None}, 1)

    def test_nothing_is_prepared_before_an_account_is_connected(self):
        self.emails((self.WORK, "professional", True, True))
        self.flow_act("plan")
        plan = self.plan()
        for broker in ("apollo", "hunter"):
            self.assertEqual(plan[broker]["state"], "needs_information", broker)
            self.assertIn("Connect your sending account", " ".join(plan[broker]["missing"]))
        self.cases.create(self.session, "apollo", "", "Synthetic Apollo case.", True)
        with self.assertRaisesRegex(RuleError, "Connect your sending account"):
            self.run_("prepare", "apollo", drop_acknowledged=False)

    def test_a_professional_email_never_becomes_the_from_address_of_a_personal_account(self):
        # The owner's work address is saved and marked professional, but the connected account is personal.
        self.emails((self.WORK, "professional", True, True), (self.HOME, "personal", False, True))
        self.connect_account(self.HOME)
        plan = self.plan()
        self.assertEqual(plan["hunter"]["state"], "needs_information")
        self.assertIn("connected sending address", " ".join(plan["hunter"]["missing"]))
        self.assertEqual(plan["apollo"]["state"], "ready_to_prepare_email")
        self.ready("apollo")
        # Apollo is sent from the connected account even though the work address is preferred.
        self.assertEqual(self.case("apollo")["execution"]["message"]["from"], self.HOME)
        self.assertEqual(self.case("apollo")["execution"]["sender_account"], self.HOME)
        self.cases.create(self.session, "hunter", "", "Synthetic Hunter case.", True)
        with self.assertRaisesRegex(RuleError, "connected sending address"):
            self.run_("prepare", "hunter", drop_acknowledged=False)

    def test_the_connected_address_must_be_saved_and_qualify_for_the_route(self):
        self.emails((self.HOME, "personal", True, True))
        self.connect_account("someone-else@example.invalid")
        self.assertEqual({self.plan()[b]["state"] for b in SENDING if b != "lusha"}, {"needs_information"})
        self.emails((self.HOME, "personal", True, True), (self.WORK, "professional", False, True))
        self.connect_account(self.WORK.upper())  # Addresses compare without regard to case.
        self.ready("hunter")
        job = self.case("hunter")["execution"]
        self.assertEqual(job["message"]["from"], self.WORK)
        self.assertIn("Email address: " + self.WORK, job["message"]["body"])

    def test_changing_the_connected_account_invalidates_and_the_broker_gate_still_holds(self):
        self.emails((self.WORK, "professional", True, True), (self.HOME, "personal", False, True))
        self.connect_account(self.WORK)
        self.ready("apollo", "hunter")
        self.assertEqual({self.case(b)["execution_status"] for b in ("apollo", "hunter")}, {"approved"})
        # Sending to a broker through Gmail stays disabled whatever the binding says.
        with self.assertRaisesRegex(RuleError, "not enabled"):
            self.run_("dispatch", "apollo", fingerprint=self.case("apollo")["execution"]["fingerprint"])
        self.connect_account(self.HOME)
        self.assertEqual({self.case(b)["execution_status"] for b in ("apollo", "hunter")}, {"invalidated"})
        with self.vault.mutex, self.vault.db:
            self.vault.db.execute("DELETE FROM records WHERE id='sender'")
        self.assertEqual({self.case(b)["execution_status"] for b in ("apollo", "hunter")}, {"invalidated"})
        with self.assertRaisesRegex(RuleError, "approval"):
            self.run_("dispatch", "hunter", fingerprint=self.case("hunter")["execution"]["fingerprint"])
        self.assertEqual(self.worker.envelopes, [])

    def test_the_fake_provider_binds_no_account_and_an_unbound_job_cannot_move_to_one(self):
        self.emails((self.WORK, "professional", True, True))
        self.connect(self.StubWorker())  # Local fake provider: simulation, no account.
        self.ready("apollo")
        self.assertIsNone(self.case("apollo")["execution"]["sender_account"])
        class GmailStub(self.StubWorker):
            kind, simulated, google_port = "gmail", True, 1
        self.connect(GmailStub())
        self.connect_account(self.WORK)
        self.assertEqual(self.case("apollo")["execution_status"], "invalidated")


if __name__ == "__main__":
    unittest.main()
