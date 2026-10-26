"""Authored broker fixtures and outcomes; no private-store or transport imports."""
import json
from importlib.resources import files
from pathlib import Path

from ..domain import RuleError

ROOT = Path(__file__).resolve().parents[2]


def fixture(name):
    if name not in {"demo.json", "brokers.json"}:
        raise RuleError("Unknown bundled fixture")
    source = ROOT / "fixtures" / name
    if not source.is_file():
        source = files("privacy_cleanup.fixtures").joinpath(name)
    return json.loads(source.read_text())


def catalog():
    return fixture("brokers.json")


def prepare(state, candidate, variant, brokers):
    broker = brokers[candidate["broker"]]
    if variant not in {"standard", "alternate_email", "alternate_destination"}:
        raise RuleError("Unknown synthetic request variant")
    destination = broker["mock_destination"]
    if variant == "alternate_destination":
        destination += "/revised"
    email_key = "alternate_email" if variant == "alternate_email" else "email"
    return {
        "mode": "mock-only", "identity_id": state["identity"]["id"],
        "candidate_id": candidate["id"], "broker": candidate["broker"],
        "destination": destination, "method": broker["mock_method"],
        "purpose": "Simulate a request to suppress this fictional record",
        "fields": {"listing_reference": candidate["listing_url"],
                   "contact_email": state["identity"][email_key]},
        "destination_evidence": "Checked against the bundled mock allowlist; NOT a verified live destination",
        "official_reference": broker["official_reference"],
        "research_checked_on": broker["checked_on"],
        "research_status": broker["research_status"],
        "disclosure": "No transmission. These two fields are illustrative, not verified live requirements.",
        "variant": variant,
    }


def outcome(broker, value):
    if value not in {"accepted", "uncertain", "manual"}:
        raise RuleError("Select a mock submission scenario")
    return "manual" if broker == "acxiom" else value
