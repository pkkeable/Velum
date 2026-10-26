"""Authored official-source registry. These are manual routes, not API endpoints."""
from copy import deepcopy
from datetime import date, datetime, timezone

from . import contracts
from .domain import RuleError, digest
from .requirements import requirements

CHECKED = "2026-10-07"
REVIEW_DAYS = 30  # Product freshness policy, not a broker deadline.
FIELDS = {
    "first_name": ("First name", 120), "last_name": ("Last name", 120),
    "email": ("Email", 254), "street_address": ("Street address", 240),
    "city": ("City", 120), "region": ("State", 120),
    "postal_code": ("ZIP code", 32), "birth_date": ("Birth date (YYYY-MM-DD)", 10),
}

ROUTES = {
    "epsilon": {
        "name": "Epsilon", "kind": "private_database", "listing_hosts": [],
        "destination": "https://legal.epsilon.com/dsr", "purpose": "Delete my personal information",
        "method": "manual_web_form", "readiness": "manual_preparation", "version": 2,
        "checked": CHECKED, "sources": ["https://legal.epsilon.com/dsr",
            "https://legal.epsilon.com/us/NA-products-privacy-policy",
            "https://legal.epsilon.com/us/terms-and-conditions"],
        "fields": list(FIELDS), "required_for_preparation": ["first_name", "last_name", "email"],
        "fixed_fields": {"country": "United States", "request_type": "Delete my Personal Information"},
        "direct_steps": ["Complete any CAPTCHA directly with the broker.",
                         "Confirm the verification email yourself; never paste a code or link here."],
        "disclosure_notice": "Epsilon's page says submission attempts to read this browser's cookie ID. The page includes Google reCAPTCHA. External browsing exposes IP/browser data and may use additional service providers; this app cannot enumerate or control that traffic.",
        "limits": "US self-service deletion drafts only. Email verification is documented; the broker's mandatory status for name, address and birth date is unconfirmed. Local validation is not broker acceptance. Check the requirements guide before disclosure. Database possession is unknown; public listing absence is not applicable.",
        "automation": "Unavailable. No permitted automatic interface established; terms restrict automated monitoring/copying. Manual entry and submission only.",
        "steps": ["Open the official form; choose United States and the deletion request type.",
                  "Compare its fields and destination with this preview before entering anything. Stop on a changed form or destination.",
                  "Enter only the reviewed values. Handle verification directly. Record the outcome here afterward."],
    },
    "apollo": {
        # Executed by Velum through the owner's mail account under contracts.py; no manual draft.
        "name": "Apollo", "kind": "private_database", "listing_hosts": [], "version": 1,
        "destination": "https://www.apollo.io/privacy-policy", "purpose": "Delete my personal information from Apollo's records",
        "method": "owner_email", "readiness": "owner_email", "checked": "2026-10-08",
        "sources": ["https://www.apollo.io/privacy-policy"], "contract": "apollo-delete-v1",
        "limits": "Professional contact database. Velum sends one exact, owner-approved deletion email from your own mail account to the privacy address pinned from Apollo's policy. Apollo may verify identity by replying to you. Transport acceptance is not deletion; Apollo may keep a suppression record.",
        "automation": "Automated simulation only: owner-email sending exercised against a local fake provider. No Apollo platform access, scraping or Privacy Center automation.",
    },
    "cognism": {
        # Executed by Velum through the owner's mail account under contracts.py; no manual draft.
        "name": "Cognism", "kind": "private_database", "listing_hosts": [], "version": 1,
        "destination": "https://www.cognism.com/en/us-privacy-policy",
        "purpose": "Delete my personal information from Cognism's business-professional data",
        "method": "owner_email", "readiness": "owner_email", "checked": "2026-10-08",
        "sources": ["https://www.cognism.com/en/us-privacy-policy"], "contract": "cognism-delete-v1",
        "limits": "Business-professional contact database. Only for current residents of California, Colorado, Connecticut, Florida, Montana, Oregon, Texas, Virginia or Utah, the states Cognism's US notice names. Velum sends one exact, owner-approved deletion email naming your current state. Cognism may ask for more information to verify you. Transport acceptance is not deletion.",
        "automation": "Automated simulation only: owner-email sending exercised against a local fake provider. No Cognism platform access, scraping or Privacy Center automation.",
    },
    "lusha": {
        # Executed by Velum through the owner's mail account under contracts.py; no manual draft.
        "name": "Lusha", "kind": "private_database", "listing_hosts": [], "version": 1,
        "destination": "https://www.lusha.com/legal/privacy-notice/",
        "purpose": "Erase my personal data from the Lusha B2B Database",
        "method": "owner_email", "readiness": "owner_email", "checked": "2026-10-08",
        "sources": ["https://www.lusha.com/legal/privacy-notice/"], "contract": "lusha-erasure-v1",
        "limits": "Business contact database. Email requests are documented for California residents only; everyone else uses Lusha's own Privacy Center forms, which Velum does not automate. Lusha sends a link to verify your email address. Transport acceptance is not erasure, and erasure differs from Lusha's opt-out suppression list.",
        "automation": "Automated simulation only: owner-email sending exercised against a local fake provider. No Lusha platform access, scraping or Privacy Center automation.",
    },
    "contactout": {
        # Executed by Velum through the owner's mail account under contracts.py; no manual draft.
        "name": "ContactOut", "kind": "private_database", "listing_hosts": [], "version": 1,
        "destination": "https://contactout.com/privacy_data_subjects",
        "purpose": "Erase my personal data from ContactOut's Service",
        "method": "owner_email", "readiness": "owner_email", "checked": "2026-10-09",
        "sources": ["https://contactout.com/privacy_data_subjects"], "contract": "contactout-erasure-v1",
        "limits": "Business-professional contact data. ContactOut's data-subject policy offers erasure without a jurisdiction limit and names its general support inbox for requests. Velum sends one exact, owner-approved erasure email. ContactOut may ask for more information to verify you. Transport acceptance is not erasure.",
        "automation": "Automated simulation only: owner-email sending exercised against a local fake provider. No ContactOut platform access, scraping or opt-out page automation.",
    },
    "hunter": {
        # Executed by Velum through the owner's mail account under contracts.py; no manual draft.
        "name": "Hunter", "kind": "private_database", "listing_hosts": [], "version": 1,
        "destination": "https://hunter.io/privacy-policy",
        "purpose": "Delete my personal data from Hunter, including my professional email profile",
        "method": "owner_email", "readiness": "owner_email", "checked": "2026-10-09",
        "sources": ["https://hunter.io/privacy-policy", "https://hunter.io/privacy-policy/california",
                    "https://help.hunter.io/en/articles/2020343-remove-your-data-from-hunter"], "contract": "hunter-delete-v1",
        "limits": "Professional email database. Only for current residents of the 15 states Hunter's policy names (not California, whose notice lists a web link or phone), and only when your connected sending account is the address you marked professional. Velum sends one exact deletion email from that address, naming your current state; it sends no name. Hunter documents its Claim page for removing a listed address and may point you there. Transport acceptance is not deletion.",
        "automation": "Automated simulation only: owner-email sending exercised against a local fake provider. No Hunter platform access, scraping or Claim page automation.",
    },
    "peopleconnect": {
        "name": "PeopleConnect", "kind": "public_listing", "version": 1,
        "listing_hosts": ["www.intelius.com", "www.truthfinder.com", "www.instantcheckmate.com", "www.ussearch.com"],
        "destination": "https://suppression.peopleconnect.us/", "purpose": "Suppress covered name-search reports",
        "method": "manual_guidance", "readiness": "guidance_only", "checked": CHECKED,
        "sources": ["https://suppression.peopleconnect.us/", "https://peopleconnect.us/terms-of-use/"],
        "limits": "Free suppression for covered name-search reports on Intelius, TruthFinder, Instant Checkmate and US Search. Email verification starts the flow; later fields are not verified. This is not deletion from all products or source records.",
        "automation": "Unavailable. Terms restrict automated access. Complete this service yourself.",
    },
    "acxiom": {
        "name": "Acxiom", "kind": "private_database", "listing_hosts": [], "version": 1,
        "destination": "https://www.acxiom.com/optout/", "purpose": "Review opt-out or deletion options",
        "method": "manual_guidance", "readiness": "guidance_only", "checked": CHECKED,
        "sources": ["https://www.acxiom.com/optout/"],
        "limits": "Earlier official documentation described online email confirmation, phone and postal alternatives; opt-out and deletion differ. Full form fields remain unknown. Browser safety blocked further inspection. No prepared request is enabled.",
        "automation": "Unavailable; current form and permission unverified.",
    },
    "whitepages": {
        "name": "Whitepages", "kind": "public_listing", "listing_hosts": ["www.whitepages.com"], "version": 1,
        "destination": "https://support.whitepages.com/hc/en-us/articles/115010106908-How-do-I-edit-or-remove-a-personal-listing",
        "purpose": "Review personal listing removal", "method": "manual_guidance", "readiness": "guidance_only", "checked": CHECKED,
        "sources": ["https://cppa.ca.gov/data_broker_registry/"],
        "limits": "Company verified in the California registry; official help page inspection blocked by browser safety. Current fields, submission route and verification are unknown. Track a listing locally; review instructions yourself.",
        "automation": "Unavailable; route unverified.",
    },
    "peoplefinders": {
        "name": "PeopleFinders", "kind": "public_listing", "listing_hosts": ["www.peoplefinders.com"], "version": 1,
        "destination": "https://www.peoplefinders.com/opt-out", "purpose": "Review personal listing removal",
        "method": "manual_guidance", "readiness": "guidance_only", "checked": CHECKED,
        "sources": ["https://cppa.ca.gov/data_broker_registry/"],
        "limits": "Company verified in the California registry; form inspection blocked by browser safety. Current fields and verification are unknown. Track a listing locally; review instructions yourself.",
        "automation": "Unavailable; route unverified.",
    },
    "spokeo": {
        "name": "Spokeo", "kind": "public_listing", "listing_hosts": ["www.spokeo.com"], "version": 1,
        "destination": "https://help.spokeo.com/hc/en-us/articles/115010425928-How-do-I-remove-my-information-from-Spokeo-",
        "purpose": "Review personal listing removal", "method": "manual_guidance", "readiness": "guidance_only", "checked": CHECKED,
        "sources": ["https://help.spokeo.com/hc/en-us/articles/115010425928-How-do-I-remove-my-information-from-Spokeo-"],
        "limits": "Official documentation retrieval challenged and opt-out inspection safety-blocked. Current required fields and submission method are unknown. Demo fields are illustrative only.",
        "automation": "Unavailable; current route and permission unverified.",
    },
    "beenverified": {
        "name": "BeenVerified", "kind": "public_listing", "listing_hosts": ["www.beenverified.com"], "version": 1,
        "destination": "https://www.beenverified.com/faq/opt-out/", "purpose": "Review personal listing removal",
        "method": "manual_guidance", "readiness": "guidance_only", "checked": CHECKED,
        "sources": ["https://www.beenverified.com/faq/opt-out/"],
        "limits": "Official FAQ retrieval returned a security challenge. Current required fields and submission method are unknown. Affiliate coverage must be verified separately.",
        "automation": "Unavailable; current route and permission unverified.",
    },
}


# Levels from PRODUCT_SCOPE.md. Owner-email routes stop at automated simulation until a separately
# authorized pilot. Guidance-only entries record sources and gaps but lack complete instructions,
# so they are research only, not guided manual.
CAPABILITY = {
    "epsilon": "local_preparation", "apollo": "automated_simulation", "cognism": "automated_simulation",
    "lusha": "automated_simulation", "contactout": "automated_simulation", "hunter": "automated_simulation",
    "peopleconnect": "research_only", "acxiom": "research_only",
    "whitepages": "research_only", "peoplefinders": "research_only", "spokeo": "research_only",
    "beenverified": "research_only",
}


def route(identifier):
    if not isinstance(identifier, str) or identifier not in ROUTES:
        raise RuleError("Choose a supported broker from the local catalog")
    item = deepcopy(ROUTES[identifier])
    item["requirements"] = requirements(identifier)
    rules = {f["id"]: f for f in item["requirements"]["inputs"]}
    item["draft_fields"] = [{"id": key, "label": FIELDS[key][0], "max_length": FIELDS[key][1],
                             "local_required": key in item["required_for_preparation"],
                             "broker_need": rules[key]["need"], "help": rules[key]["note"]}
                            for key in item.get("fields", [])]
    return item


def fresh(item, timestamp):
    checked = date.fromisoformat(item["checked"])
    today = datetime.fromtimestamp(timestamp, timezone.utc).date()
    return 0 <= (today - checked).days <= REVIEW_DAYS


def freshness(key, timestamp):
    """Why this route's evidence is current or paused. A sending route is judged by its contract."""
    item = ROUTES[key]
    contract = contracts.for_broker(key) if item.get("contract") else None
    return contracts.freshness(contract or item, timestamp)


def capability(key):
    """One route's level on the scope's capability ladder; never inferred from readiness alone.
    An unlisted route gets the lowest level, so a missing entry can only under-claim."""
    return CAPABILITY.get(key, "research_only")


def coverage(key):
    """Who a route covers, in one plain line: from its sending contract's jurisdiction rule, or its own
    documented scope. Beside the route, never in it, so approvals do not bind this wording."""
    item = ROUTES[key]
    contract = contracts.for_broker(key) if item.get("readiness") == "owner_email" else None
    if contract:
        rule = contract["jurisdiction"]
        if rule["countries"] is None:
            text = "Anyone, wherever they live"
        elif rule.get("us_regions"):
            names = sorted(contracts.US_STATES[contracts.us_state(r)] for r in rule["us_regions"] if contracts.us_state(r))
            text = "Residents of " + (names[0] if len(names) == 1 else str(len(names)) + " US states: " + ", ".join(names))
        else:
            text = "Residents of " + ", ".join(rule["countries"])
        return text + ("; work email addresses only" if contract.get("email_use") == "professional" else "")
    if item.get("readiness") == "manual_preparation":
        return "US residents; Velum prepares the United States request only"
    return "Set by the broker; see its official guidance"


def catalog(timestamp):
    items = []
    for key in ROUTES:
        item = route(key)
        # Capability and freshness sit beside the route, not in it: approvals bind route() itself.
        items.append({"id": key, **item, "source_fresh": fresh(item, timestamp),
                      "source_digest": digest(item), "capability": capability(key), "covers": coverage(key),
                      "freshness": freshness(key, timestamp)})
    return items
