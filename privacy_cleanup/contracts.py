"""Executable owner-email route contracts. Authored and reviewed; never derived from broker text.

A contract fixes the legal entity, recipient, purpose, jurisdiction rule, field list and exact
message template. The UI process and the separate sending worker both render messages from
this module, so the worker can check that an envelope is exactly what the owner approved.
This module performs no I/O.
"""
import copy
import re
from datetime import date, datetime, timedelta, timezone

from .domain import RuleError, digest

REVIEW_DAYS = 30  # Product freshness policy, as for manual routes; not a broker deadline.
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})+")
LIMITS = {"full_name": 120, "email": 254, "us_state": 40}
PLACEHOLDER = re.compile(r"\{(full_name|email|us_state)\}")
# Recognizes a saved current residence. Recognizing a state never makes it eligible: each
# contract lists only the states its own official source names.
US_STATES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas", "CA": "California", "CO": "Colorado",
    "CT": "Connecticut", "DE": "Delaware", "DC": "District of Columbia", "FL": "Florida", "GA": "Georgia",
    "HI": "Hawaii", "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa", "KS": "Kansas",
    "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine", "MD": "Maryland", "MA": "Massachusetts",
    "MI": "Michigan", "MN": "Minnesota", "MS": "Mississippi", "MO": "Missouri", "MT": "Montana",
    "NE": "Nebraska", "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico",
    "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio", "OK": "Oklahoma",
    "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island", "SC": "South Carolina", "SD": "South Dakota",
    "TN": "Tennessee", "TX": "Texas", "UT": "Utah", "VT": "Vermont", "VA": "Virginia", "WA": "Washington",
    "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming", "AS": "American Samoa", "GU": "Guam",
    "MP": "Northern Mariana Islands", "PR": "Puerto Rico", "VI": "U.S. Virgin Islands",
}
_STATE_KEYS = {**{code.casefold(): code for code in US_STATES}, **{name.casefold(): code for code, name in US_STATES.items()}}

CONTRACTS = {
    "apollo-delete-v1": {
        "id": "apollo-delete-v1", "version": 2, "broker": "apollo",
        "entity": "Apollo.io (ZenLeads Inc.)", "method": "owner_email",
        # Reviewed recipient, pinned from the official policy. See docs/COVERAGE.md.
        "recipient": "privacy@apollo.io",
        "purpose": "Delete my personal information from Apollo's records",
        "jurisdiction": {
            "countries": None, "us_regions": None,
            "basis": "Apollo's privacy policy (Section 5, Right to Delete) offers deletion without limiting it "
                     "to a jurisdiction; U.S. state and EEA/UK rights are described as additional.",
        },
        "fields": ["full_name", "email"],
        "sender_field": "email",
        "subject": "Request to delete my personal information",
        "body": ("Hello Apollo Privacy team,\n\n"
                 "I am asking Apollo to delete my personal information from its records, as offered in the "
                 "Right to Delete section of your privacy policy. Please apply this request to any profile "
                 "matching:\n\n"
                 "Name: {full_name}\n"
                 "Email address: {email}\n\n"
                 "I am making this request for myself from the email address above. If you need to verify my "
                 "identity, please reply to this address. I understand that you may keep the minimum "
                 "information needed to honor this request on a suppression list.\n\n"
                 "Thank you,\n"
                 "{full_name}\n"),
        "checked": "2026-10-08", "source_date": "2026-08-10",
        "sources": ["https://www.apollo.io/privacy-policy"],
        "verification": "Apollo says it may verify identity and authority. Any verification message arrives in "
                        "your own inbox; handle it there. Velum never reads your mailbox.",
        "acceptance": "Transport acceptance means your mail provider accepted the message for delivery. It is "
                      "not Apollo's acknowledgment, completed verification or deletion.",
        "changes": [{"version": 1, "checked": "2026-10-08",
                     "summary": "First contract, from Apollo's privacy policy updated 2026-08-10."},
                    {"version": 2, "checked": "2026-10-08",
                     "summary": "Wording only: \"making this request for myself\" replaces \"sending this request "
                                "myself\", which stays true when Velum sends the approved email from your account. "
                                "Sources were not re-checked."}],
    },
    "cognism-delete-v1": {
        "id": "cognism-delete-v1", "version": 1, "broker": "cognism",
        "entity": "Cognism Limited and its U.S. affiliates", "method": "owner_email",
        # Reviewed recipient, pinned from the official US notice. See docs/COVERAGE.md.
        "recipient": "privacy@cognism.com",
        "purpose": "Delete my personal information from Cognism's business-professional data",
        "jurisdiction": {
            "countries": ["US"], "us_regions": ["CA", "CO", "CT", "FL", "MT", "OR", "TX", "VA", "UT"],
            "basis": "Cognism's US State-Specific Privacy Notice (version October 6, 2026) gives California "
                     "residents a right to deletion and names Colorado, Connecticut, Florida, Montana, Oregon, Texas, "
                     "Virginia and Utah for its other-state right to delete. Its general mention of other comparable "
                     "state laws is not treated as covering any further state.",
        },
        "fields": ["full_name", "email", "us_state"],
        "sender_field": "email",
        "subject": "Request to delete my personal information",
        "body": ("Hello Cognism Privacy team,\n\n"
                 "I am a resident of {us_state}. As described in Cognism's US State-Specific Privacy Notice, I am "
                 "asking Cognism to delete the personal information it has collected or maintains about me, including "
                 "any business-professional profile on your platform matching:\n\n"
                 "Name: {full_name}\n"
                 "Email address: {email}\n\n"
                 "I am making this request for myself from the email address above. If you need more information to "
                 "verify my identity or to find my record, please reply to this address.\n\n"
                 "Thank you,\n"
                 "{full_name}\n"),
        "checked": "2026-10-08", "source_date": "2026-10-06",
        "sources": ["https://www.cognism.com/en/us-privacy-policy"],
        "verification": "Cognism says it will verify your identity where the law requires and may ask for more "
                        "information to match its records. Any request arrives in your own inbox; Velum never reads it.",
        "acceptance": "Transport acceptance means your mail provider accepted the message for delivery. It is not "
                      "Cognism's acknowledgment, completed verification or deletion. Cognism counts requests with no "
                      "information found or no verified identity as denied, so record its actual wording.",
        "changes": [{"version": 1, "checked": "2026-10-08",
                     "summary": "First contract, from the US State-Specific Privacy Notice version October 6, 2026."}],
    },
    "lusha-erasure-v1": {
        "id": "lusha-erasure-v1", "version": 1, "broker": "lusha",
        "entity": "Lusha Systems Inc. and Lusha Systems Ltd. (joint controllers of contact data)", "method": "owner_email",
        # Reviewed recipient, read from the official notice in a normal browser. See docs/COVERAGE.md.
        "recipient": "privacy@lusha.com",
        "purpose": "Erase my personal data from the Lusha B2B Database",
        "jurisdiction": {
            "countries": ["US"], "us_regions": ["CA"],
            "basis": "Lusha's Privacy Notice (last updated September 2026) lets California residents exercise their "
                     "rights, which include erasure, by emailing its Privacy Team. Other residents are directed to "
                     "Privacy Center forms, so this email route covers California residents only.",
        },
        "fields": ["full_name", "email", "us_state"],
        "sender_field": "email",
        "subject": "Request to erase my personal data",
        "body": ("Hello Lusha Privacy Team,\n\n"
                 "I am a resident of {us_state}. Under the erasure right and the California privacy rights described "
                 "in Lusha's Privacy Notice, I am asking Lusha to erase my personal data, including any Business "
                 "Contact Card in the Lusha B2B Database matching:\n\n"
                 "Name: {full_name}\n"
                 "Email address: {email}\n\n"
                 "I am making this request for myself from the email address above. If you need to verify my "
                 "identity, please send the verification link to this address.\n\n"
                 "Thank you,\n"
                 "{full_name}\n"),
        "checked": "2026-10-08", "source_date": "2026-09",  # The notice gives a month, not a day.
        "sources": ["https://www.lusha.com/legal/privacy-notice/"],
        "verification": "Lusha says it will send a link to verify your email address and may ask for more "
                        "information to verify your identity. Handle it in your own inbox; Velum never reads it.",
        "acceptance": "Transport acceptance means your mail provider accepted the message for delivery. It is not "
                      "Lusha's acknowledgment, completed verification or erasure. Lusha may keep data it has legal or "
                      "legitimate reasons to retain; record its actual wording.",
        "changes": [{"version": 1, "checked": "2026-10-08",
                     "summary": "First contract, from the Privacy Notice last updated September 2026; California only."}],
    },
    "contactout-erasure-v1": {
        "id": "contactout-erasure-v1", "version": 1, "broker": "contactout",
        "entity": "ContactOut Limited", "method": "owner_email",
        # Reviewed recipient, read from the official data-subject page in a normal browser. It is
        # ContactOut's general support inbox, which the page names for every data-protection right.
        "recipient": "support@contactout.com",
        "purpose": "Erase my personal data from ContactOut's Service",
        "jurisdiction": {
            "countries": None, "us_regions": None,
            "basis": "ContactOut's Privacy Data Subjects policy (last updated June 25, 2024) lists a right to "
                     "erasure without limiting it to a jurisdiction and directs requests to this email; its "
                     "California section names the same address.",
        },
        "fields": ["full_name", "email"],
        "sender_field": "email",
        "subject": "Request to erase my personal data",
        "body": ("Hello ContactOut team,\n\n"
                 "I am asking ContactOut to erase my personal data, under the right to erasure described in your "
                 "Privacy Data Subjects policy. Please apply this request to any business-professional record in "
                 "your Service matching:\n\n"
                 "Name: {full_name}\n"
                 "Email address: {email}\n\n"
                 "I am making this request for myself from the email address above. If you need to verify my "
                 "identity, please reply to this address.\n\n"
                 "Thank you,\n"
                 "{full_name}\n"),
        "checked": "2026-10-09", "source_date": "2024-06-25",
        "sources": ["https://contactout.com/privacy_data_subjects"],
        "verification": "ContactOut asks for enough information to verify that you are the person concerned and a "
                        "clear description of the request. Any follow-up arrives in your own inbox; Velum never reads it.",
        "acceptance": "Transport acceptance means your mail provider accepted the message for delivery. It is not "
                      "ContactOut's acknowledgment, completed verification or erasure. ContactOut says it has one "
                      "month to respond; record its actual wording.",
        "changes": [{"version": 1, "checked": "2026-10-09",
                     "summary": "First contract, from the Privacy Data Subjects policy last updated June 25, 2024."}],
    },
    "hunter-delete-v1": {
        "id": "hunter-delete-v1", "version": 3, "broker": "hunter",
        "entity": "Hunter Web Services, Inc.", "method": "owner_email",
        # Reviewed recipient, pinned from the official policy's US state-rights section. See docs/COVERAGE.md.
        "recipient": "privacy@hunter.io",
        "purpose": "Delete my personal data from Hunter, including my professional email profile",
        "jurisdiction": {
            "countries": ["US"],
            "us_regions": ["TX", "VA", "CO", "DE", "IA", "NH", "NJ", "NE", "MN", "MD", "OR", "MT", "KY", "IN", "RI"],
            "basis": "Hunter's Privacy Policy (last updated April 13, 2026) gives residents of Texas, Virginia, "
                     "Colorado, Delaware, Iowa, New Hampshire, New Jersey, Nebraska, Minnesota, Maryland, Oregon, "
                     "Montana, Kentucky, Indiana and Rhode Island a right to delete, defines its database subjects "
                     "(Business Profiles) as covered, and says to submit requests to its privacy email. California "
                     "is excluded: its notice (January 3, 2023) lists only a web link or telephone for deletion "
                     "requests. EEA and UK profile holders are directed to the Claim page, so they are not covered.",
        },
        "fields": ["email", "us_state"],
        "email_use": "professional",  # Only an email the owner marked professional; never inferred.
        "sender_field": "email",
        "subject": "Request to delete my personal data",
        "body": ("Hello Hunter Privacy team,\n\n"
                 "I am a resident of {us_state}. Under the US state privacy rights described in Hunter's Privacy "
                 "Policy, I am asking Hunter to delete my personal data, including this professional email address "
                 "and any Business Profile linked to it in your database:\n\n"
                 "Email address: {email}\n\n"
                 "I am making this request for myself from that address. If you need to verify my identity, please "
                 "reply to this address.\n\n"
                 "Thank you.\n"),
        "checked": "2026-10-09", "source_date": "2026-04-13",
        "sources": ["https://hunter.io/privacy-policy", "https://hunter.io/privacy-policy/california",
                    "https://help.hunter.io/en/articles/2020343-remove-your-data-from-hunter"],
        "verification": "Hunter says it may verify your identity before fulfilling a request. The email is sent from "
                        "the professional address itself, as your connected sending account, which shows you control "
                        "it. Hunter does not list webmail addresses, so a personal mail account cannot send this "
                        "request. Any follow-up arrives in that inbox; Velum never reads it.",
        "acceptance": "Transport acceptance means your mail provider accepted the message for delivery. It is not "
                      "Hunter's acknowledgment, completed verification or deletion. Hunter's deletion wording covers "
                      "data collected from you, and its removal guide documents the Claim page as the way to "
                      "remove a listed address, so it may point you there instead; record its actual wording and "
                      "complete any Claim step yourself.",
        "changes": [{"version": 1, "checked": "2026-10-09",
                     "summary": "First contract, from the Privacy Policy last updated April 13, 2026 and the "
                                "California notice of January 3, 2023."},
                    {"version": 2, "checked": "2026-10-09",
                     "summary": "Removed California: its notice lists only a web link or telephone for deletion "
                                "requests. Cited the removal guide, which documents the Claim page for listed "
                                "addresses and says webmail is not listed."},
                    {"version": 3, "checked": "2026-10-09",
                     "summary": "Wording only: \"making this request for myself\" replaces \"sending this request "
                                "myself\", which stays true when Velum sends the approved email from your account. "
                                "Sources were not re-checked."}],
    },
    # Not a broker route: checks a connected mail account by sending to that account itself.
    "self-test-v1": {
        "id": "self-test-v1", "version": 1, "broker": None, "entity": "You", "method": "owner_email",
        "recipient": None,  # The sender's own address.
        "purpose": "Check that Velum can send through your connected mail account",
        "jurisdiction": {"countries": None, "us_regions": None, "basis": "No broker is contacted."},
        "fields": ["email"], "sender_field": "email",
        "subject": "Velum connection test",
        "body": ("This test message was sent by Velum through your connected mail account to yourself.\n\n"
                 "No data broker was contacted and no personal details are included. "
                 "You can delete this message.\n"),
        "checked": None, "source_date": None, "sources": [], "verification": "", "acceptance": "",
        "changes": [{"version": 1, "checked": None, "summary": "Fixed connection test; no broker is contacted."}],
    },
}
BY_BROKER = {c["broker"]: key for key, c in CONTRACTS.items() if c["broker"]}
SELF_TEST = "self-test-v1"


def contract(identifier):
    if not isinstance(identifier, str) or identifier not in CONTRACTS:
        raise RuleError("Unknown or retired sending contract")
    return copy.deepcopy(CONTRACTS[identifier])


def for_broker(broker):
    return contract(BY_BROKER[broker]) if broker in BY_BROKER else None


def requirement(item, sender=None):
    """What workflow.mapping needs to fill this contract from the saved identity. With an
    account-backed sender, the sending email must be that account's own saved entry."""
    return {"required_for_preparation": list(item["fields"]), "email_use": item.get("email_use"), "sender": sender}


def freshness(item, timestamp):
    """Whether this contract's own official source is within its review window, and why not.

    A stale contract pauses only its own route: preparing and sending are refused for it alone."""
    if item["checked"] is None:  # The self-test cites no external source.
        return {"fresh": True, "checked": None, "review_by": None, "reason": None}
    checked = date.fromisoformat(item["checked"])
    review_by = (checked + timedelta(days=REVIEW_DAYS)).isoformat()
    days = (datetime.fromtimestamp(timestamp, timezone.utc).date() - checked).days
    reason = None
    if days < 0:
        reason = "This route's source check date is later than this computer's clock. Check the system date."
    elif days > REVIEW_DAYS:
        reason = ("This route's official source was last checked on " + item["checked"] + " and was due for "
                  "review by " + review_by + ". Preparing and sending are paused for this route only.")
    return {"fresh": reason is None, "checked": item["checked"], "review_by": review_by, "reason": reason}


def fresh(item, timestamp):
    return freshness(item, timestamp)["fresh"]


def us_state(region):
    """The two-letter code for a saved state code or name, or None when it is not recognized."""
    return _STATE_KEYS.get(region.strip().casefold()) if isinstance(region, str) else None


def _covered(rule):
    return {us_state(r) for r in rule["us_regions"]} - {None}


def eligibility(item, residence):
    """(outcome, reason) for the saved current residence: eligible, needs_residence or not_covered.

    Unknown residence fails closed only for contracts that restrict jurisdiction. Each contract
    is judged on its own list; a state another route covers proves nothing here."""
    rule = item["jurisdiction"]
    if rule["countries"] is None:
        return "eligible", None
    country = (residence or {}).get("country", "")
    region = (residence or {}).get("region", "").strip()
    if not country:
        return "needs_residence", "Add your current country of residence to check this route"
    if country not in rule["countries"]:
        return "not_covered", "This route's documented rights do not cover your current country"
    if rule["us_regions"] is not None and country == "US":
        if not region:
            return "needs_residence", "Add your current state to check this route"
        code = us_state(region)
        if code is None:
            return "needs_residence", "Velum could not recognize your saved state; use its two-letter code or full name"
        if code not in _covered(rule):
            return "not_covered", "This route's documented rights do not cover your current state"
    return "eligible", None


def eligible(item, residence):
    """None when the saved current residence fits the contract; otherwise a reason."""
    return eligibility(item, residence)[1]


def _value(key, value):
    if (not isinstance(value, str) or not value or len(value) > LIMITS[key] or value != value.strip()
            or any(not c.isprintable() for c in value)):
        raise RuleError("A sending field is missing, too long or contains unsupported characters")
    if key == "email" and not EMAIL.fullmatch(value):
        raise RuleError("Check the sending email address format")
    if key == "us_state" and value not in US_STATES.values():
        raise RuleError("Use the full name of your current state")
    return value


def render(item, fields):
    """The exact message for these fields. Single-pass substitution; values are never re-scanned.

    A stated residence must be one this contract's own source covers, so neither process can
    render a message that asserts rights the route's evidence does not support."""
    if not isinstance(fields, dict) or set(fields) != set(item["fields"]):
        raise RuleError("Use exactly the fields reviewed for this sending contract")
    values = {key: _value(key, fields[key]) for key in item["fields"]}
    if "us_state" in values:
        rule = item["jurisdiction"]
        if not rule["us_regions"] or us_state(values["us_state"]) not in _covered(rule):
            raise RuleError("This route's documented rights do not cover that state")
    fill = lambda template: PLACEHOLDER.sub(lambda match: values[match.group(1)], template)  # noqa: E731
    return {"from": values[item["sender_field"]], "to": item["recipient"] or values[item["sender_field"]],
            "subject": fill(item["subject"]), "body": fill(item["body"])}


def fingerprint(item, message):
    return digest({"contract": item["id"], "version": item["version"], "method": item["method"],
                   "purpose": item["purpose"], "message": message})


def state_name(residence):
    """The full state name rendered for a saved current US residence, or None."""
    residence = residence or {}
    code = us_state(residence.get("region", "")) if residence.get("country") == "US" else None
    return US_STATES[code] if code else None


def snapshot(item):
    """The contract details an email was prepared under, kept with it so history never borrows a later revision."""
    return {"id": item["id"], "version": item["version"], "entity": item["entity"], "purpose": item["purpose"],
            "method": item["method"], "jurisdiction_basis": item["jurisdiction"]["basis"],
            "checked": item["checked"], "source_date": item["source_date"], "sources": list(item["sources"])}
