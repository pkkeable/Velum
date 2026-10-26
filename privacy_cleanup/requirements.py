"""Public, purpose-specific requirements evidence; never personal values.

`need` describes broker requirements, not our draft validation. Observing a field
does not establish that it is required or optional. No live submission is tested.
"""
from copy import deepcopy

EPSILON_FORM = "https://legal.epsilon.com/dsr"
EPSILON_POLICY = "https://legal.epsilon.com/us/NA-products-privacy-policy"
PEOPLECONNECT = "https://suppression.peopleconnect.us/"
ACXIOM = "https://www.acxiom.com/optout/"


def input_rule(key, label, need, basis, sources, note):
    return {"id": key, "label": label, "need": need, "basis": basis,
            "sources": sources, "note": note}


# These are product evidence standards, not promises made by a broker.
ACCEPTANCE = [
    "A valid local draft only means the app's checks passed; it is not broker acceptance.",
    "Record submission only after an explicit confirmation page or message, with its date and a short evidence note. Otherwise keep the result uncertain and do not retry.",
    "Record verification separately from receipt. A verification email is not a deletion confirmation.",
    "Record a broker's deletion or suppression statement using its actual wording and scope. Do not turn suppression into deletion.",
    "For a public listing, check the exact confirmed listing separately. Blocked, failed or ambiguous checks mean unknown; an absence is only a dated observation.",
]
PILOT_CHECKS = [
    "Before entering anything, confirm the official destination, purpose, eligibility, current terms and every required field, including later verification steps.",
    "Resolve any field marked unknown. Do not supply extra information just because a field exists. Changed fields, purpose or destination require a revised disclosure and new approval.",
    "The user handles CAPTCHA, inbox links, credentials and any identity proof directly. This app does not collect them.",
    "In a separately authorized pilot, submit once, retain a minimal private receipt, complete verification and reconcile the response. Record validation errors privately without copying personal values into issues or Git.",
    "A successful pilot validates only the tested branch and date. Automatic submission additionally needs a permitted interface, reviewed disclosures and crash/retry handling.",
]

REQUIREMENTS = {
    "epsilon": {
        "scope": "Consumer deletion from Epsilon marketing products; this app prepares only the United States, self-service branch. Employment requests and access requests are different flows.",
        "route_evidence": "Official deletion policy reviewed; United States / deletion form fields observed without entry or submission on 2026-10-07.",
        "inputs": [
            input_rule("country", "Country selection", "required", "observed_form", [EPSILON_FORM], "Choose United States for this app's supported branch."),
            input_rule("request_type", "Request type", "required", "observed_form", [EPSILON_FORM], "Choose Delete my Personal Information; access and opt-out are different purposes."),
            input_rule("first_name", "First name", "unknown", "observed_form", [EPSILON_FORM], "Displayed on the form. The app requires it for a draft; broker mandatory status is unconfirmed."),
            input_rule("last_name", "Last name", "unknown", "observed_form", [EPSILON_FORM], "Displayed on the form. The app requires it for a draft; broker mandatory status is unconfirmed."),
            input_rule("email", "Email", "required", "official_documentation", [EPSILON_POLICY], "The online deletion route uses an email confirmation link. Use an inbox you control."),
            *[input_rule(key, label, "unknown", "observed_form", [EPSILON_FORM],
                         "Displayed on the form. Omit from the local draft unless needed; check whether the broker requires it before entering information.")
              for key, label in [("street_address", "Street address"), ("city", "City"),
                                 ("region", "State"), ("postal_code", "ZIP code"), ("birth_date", "Birth date")]],
        ],
        "verification": "Email-link confirmation is documented for online deletion. reCAPTCHA was observed on the form. Knowledge-based identity questions described for access requests are not assumed to apply to deletion.",
        "completion": "A dated deletion statement is broker-reported evidence. Database possession remains unknown and public listing absence is not applicable.",
        "follow_up": "No completion deadline is encoded. Set a local review date based on the broker's actual acknowledgment; historical processing averages are not a deadline.",
        "fallback": "The official DSR page lists a consumer telephone alternative. Review that route and its disclosures separately; this app does not call or prepare a telephone request.",
        "gaps": ["Mandatory status of name, address and birth-date fields and conditional validation errors.",
                 "Any later deletion-specific identity proof, the receipt format and actual completion of this branch."],
        "next_action": "Compare the current US deletion form with this checklist before disclosing anything. A minimal draft can be prepared locally; it is not yet a broker-validated request.",
    },
    "peopleconnect": {
        "scope": "Suppression of covered name-search reports on Intelius, TruthFinder, Instant Checkmate and US Search. Do not infer coverage of every product, source record or affiliate.",
        "route_evidence": "Official suppression center and terms reviewed in a browser on 2026-10-07; only the entry stage was inspected.",
        "inputs": [
            input_rule("email", "Email you control", "required", "observed_form", [PEOPLECONNECT], "Required at the entry stage; verify the inbox directly."),
            input_rule("terms", "Terms and transactional-email acknowledgment", "required", "observed_form", [PEOPLECONNECT], "Review and accept yourself on the broker site. A local checkbox does not accept its terms."),
            input_rule("later_fields", "Fields after email verification", "unknown", "unverified", [], "Later identity and matching requirements were not reached. No complete request payload is available."),
        ],
        "verification": "Email verification starts the flow. Later challenges and matching requirements remain unverified.",
        "completion": "Retain the final suppression confirmation and named products. An email verification alone is not suppression. Observe each confirmed public listing separately.",
        "follow_up": "Use the timing in the actual suppression confirmation; no verified completion timer is implemented.",
        "fallback": "Use the official center yourself. Stop if it cannot complete; no bypass or alternate automation route has been established.",
        "gaps": ["Post-verification fields, match selection, final suppression control and confirmation.",
                 "Exact product coverage and any later verification for the selected report."],
        "next_action": "Review the center's instructions first. Local listing tracking is available; request preparation stays disabled until the full flow is documented.",
    },
    "acxiom": {
        "scope": "US consumer opt-out documentation only. Opt-out and deletion are separate requests; do not treat an opt-out as deletion or removal of previously supplied marketer data.",
        "route_evidence": "Official explanatory page read on 2026-10-07. Full form was not inspected; further browser inspection was safety-blocked.",
        "inputs": [
            input_rule("email", "Email for online US opt-out", "required", "official_documentation", [ACXIOM], "The documented online route requires a valid email and confirmation."),
            input_rule("other_fields", "Remaining opt-out fields", "unknown", "unverified", [], "Full form requirements have not been established."),
            input_rule("deletion_fields", "Deletion-specific requirements", "unknown", "unverified", [], "Do not reuse the opt-out field set or verification requirements for deletion."),
        ],
        "verification": "Email confirmation is documented for online opt-out. Deletion verification remains unknown.",
        "completion": "Keep the response's exact purpose and scope: opt-out is not proof of deletion. There is no verified public-listing check for this database.",
        "follow_up": "Earlier documentation described two weeks after opt-out email confirmation, with full effect potentially later. Recheck current guidance; this is not a tested service level or a deletion deadline.",
        "fallback": "The official page describes phone and postal alternatives. Recheck contact details and requirements yourself before using a separate route.",
        "gaps": ["Full opt-out field set and current conditions.", "Separate deletion route, jurisdiction, required fields, verification and response semantics."],
        "next_action": "Choose opt-out or deletion first, then inspect that route yourself. This entry supports local notes; it cannot prepare a verified payload.",
    },
}


def unknown_guide(scope, evidence, gap, action):
    return {
        "scope": scope, "route_evidence": evidence,
        "inputs": [input_rule("request_fields", "Broker request fields", "unknown", "unverified", [],
                              "No current field requirements are verified. Demo fields are synthetic examples, not live requirements.")],
        "verification": "Unknown. Review the current official instructions; never store verification codes, credentials or identity documents in this app.",
        "completion": "Receipt, verification and removal confirmation remain unverified. Listing observations can still be recorded separately after match confirmation.",
        "follow_up": "No verified processing deadline. Do not label a request overdue or a listing removed based on an invented timer.",
        "fallback": "Review the linked official guidance yourself. Stop on an access block; no alternate automated route is established.",
        "gaps": [gap, "Jurisdiction, exact fields, verification steps, confirmation evidence, processing timing and product coverage."],
        "next_action": action,
    }


APOLLO_POLICY = "https://www.apollo.io/privacy-policy"
COGNISM_NOTICE = "https://www.cognism.com/en/us-privacy-policy"
LUSHA_NOTICE = "https://www.lusha.com/legal/privacy-notice/"
CONTACTOUT_POLICY = "https://contactout.com/privacy_data_subjects"
HUNTER_POLICY = "https://hunter.io/privacy-policy"
HUNTER_GUIDE = "https://help.hunter.io/en/articles/2020343-remove-your-data-from-hunter"

REQUIREMENTS.update({
    "apollo": {
        "scope": "Deletion of your personal information from Apollo's professional contact records. Apollo may keep minimal suppression data so you are not re-added. Apollo user-account deletion is a different request.",
        "route_evidence": "Apollo's privacy policy (updated August 10, 2026; read 2026-10-08) offers a Right to Delete without limiting it to a jurisdiction and accepts privacy requests by email to its Privacy team. No message has been sent or accepted by Apollo through Velum.",
        "inputs": [
            input_rule("full_name", "Your name", "unknown", "official_documentation", [APOLLO_POLICY], "Proposed for matching. The policy does not list required request fields."),
            input_rule("email", "An email you control (sender and match key)", "unknown", "official_documentation", [APOLLO_POLICY], "Sent from this address so Apollo can reply or verify. It must be marked reachable in My information."),
        ],
        "verification": "Apollo says it may verify identity and authority. Any verification arrives in your own inbox; Velum never reads it.",
        "completion": "Your mail provider accepting the message is transport acceptance only. Record Apollo's reply in this case; a deletion statement is broker-reported, and suppression is not deletion.",
        "follow_up": "No processing deadline is encoded. Set a local review date after Apollo acknowledges.",
        "fallback": "Apollo's policy also lists a Privacy Center. Use it yourself if you prefer; Velum does not automate it.",
        "gaps": ["Minimum fields Apollo needs to match a profile, and whether a work email differs from the sender.",
                 "Apollo's actual acknowledgment format and verification flow for emailed requests."],
        "next_action": "Prepare the exact email from My information, review it, approve it once and send.",
    },
    "cognism": {
        "scope": "Deletion of personal information Cognism has collected or maintains about you, including business-professional profiles on its sales intelligence platform. Opting out of sale, sharing or targeted advertising is a different right and is not requested here.",
        "route_evidence": "Cognism's US State-Specific Privacy Notice (version October 6, 2026; read 2026-10-08) gives deletion rights to residents of California and of Colorado, Connecticut, Florida, Montana, Oregon, Texas, Virginia and Utah, and lists its privacy email as an alternative to its Privacy Center. No message has been sent to or accepted by Cognism through Velum.",
        "inputs": [
            input_rule("full_name", "Your name", "unknown", "official_documentation", [COGNISM_NOTICE], "Proposed for matching. The notice asks for enough information to verify you but lists no fields."),
            input_rule("email", "An email you control (sender and match key)", "unknown", "official_documentation", [COGNISM_NOTICE], "Sent from this address so Cognism can reply or verify. It must be marked reachable in My information."),
            input_rule("us_state", "Your current state of residence", "unknown", "official_documentation", [COGNISM_NOTICE], "The rights apply to residents of named states. Taken only from your saved current residence, never an old address."),
        ],
        "verification": "Cognism says it will verify identity where the law requires and may ask for more information to match its records. Any request arrives in your own inbox; Velum never reads it. Authorized-agent requests need signed authorization; Velum is not an agent.",
        "completion": "Your mail provider accepting the message is transport acceptance only. Record Cognism's reply in this case. Its published counts treat no information found or unverified identity as denied, so keep its exact wording.",
        "follow_up": "No processing deadline is encoded. Cognism's notice reports a median of 9 days for prior-year California requests; that is a historical figure, not a promise or deadline.",
        "fallback": "Cognism's notice also lists its Privacy Center and a telephone number. Use them yourself if you prefer; Velum does not automate them.",
        "gaps": ["Minimum fields Cognism needs to match a profile, and whether a work email differs from the sender.",
                 "Whether residents of states outside the nine named are served (the notice's general reference to comparable laws is not treated as evidence).",
                 "Cognism's acknowledgment format and verification flow for emailed requests."],
        "next_action": "Prepare the exact email from My information, review it, approve it once and send.",
    },
    "lusha": {
        "scope": "Erasure of your personal data from Lusha, including any Business Contact Card in the Lusha B2B Database. Lusha's opt-out keeps your data on a suppression list; that is a different request and is not made here.",
        "route_evidence": "Lusha's Privacy Notice (last updated September 2026; read 2026-10-08 in a normal browser) offers erasure and lets California residents email its Privacy Team. Other residents are directed to Privacy Center forms, which Velum does not automate. No message has been sent to or accepted by Lusha through Velum.",
        "inputs": [
            input_rule("full_name", "Your name", "unknown", "official_documentation", [LUSHA_NOTICE], "Proposed for matching. The notice asks for enough information to verify you and a clear description of the request."),
            input_rule("email", "An email you control (sender and match key)", "unknown", "official_documentation", [LUSHA_NOTICE], "Lusha says it sends a link to verify your email address. It must be marked reachable in My information."),
            input_rule("us_state", "Your current state of residence", "unknown", "official_documentation", [LUSHA_NOTICE], "The email channel is documented for California residents. Taken only from your saved current residence."),
        ],
        "verification": "Lusha says it sends a link to verify your email address and may request more information solely to verify your identity. Handle it in your own inbox; Velum never reads it.",
        "completion": "Your mail provider accepting the message is transport acceptance only. Record Lusha's reply in this case. Lusha may keep data it has legal or legitimate reasons to retain; erasure is not the same as its opt-out suppression list.",
        "follow_up": "No processing deadline is encoded. Lusha's notice reports prior-year averages; they are not a promise or deadline.",
        "fallback": "Residents of other states can use Lusha's own Privacy Center forms or telephone line directly. Velum does not automate those forms.",
        "gaps": ["Minimum fields Lusha needs to match a Business Contact Card, and whether a work email differs from the sender.",
                 "Lusha's acknowledgment format, and whether it informs past customers as described for erasure."],
        "next_action": "Prepare the exact email from My information, review it, approve it once and send.",
    },
    "contactout": {
        "scope": "Erasure of your personal data from ContactOut, including business-professional records in its Service. ContactOut's separate opt-out page is a different flow and is not used.",
        "route_evidence": "ContactOut's Privacy Data Subjects policy (last updated June 25, 2024; read 2026-10-08 and 2026-10-09 in a normal browser) lists a right to erasure without a jurisdiction limit and directs requests to its general support email; its California section names the same address. No message has been sent to or accepted by ContactOut through Velum.",
        "inputs": [
            input_rule("full_name", "Your name", "unknown", "official_documentation", [CONTACTOUT_POLICY], "Proposed for matching. The policy asks for enough information to verify you but lists no fields."),
            input_rule("email", "An email you control (sender and match key)", "unknown", "official_documentation", [CONTACTOUT_POLICY], "Sent from this address so ContactOut can reply or verify. It must be marked reachable in My information."),
        ],
        "verification": "ContactOut asks for enough information to verify that you are the person concerned and a clear description of the request. Any follow-up arrives in your own inbox; Velum never reads it.",
        "completion": "Your mail provider accepting the message is transport acceptance only. Record ContactOut's reply in this case. The address is a general support inbox, so a reply may come from its support team.",
        "follow_up": "ContactOut says it has one month to respond. Set a local review date; this is its stated policy, not a tested service level.",
        "fallback": "ContactOut's California section also lists its own opt-out page. Use it yourself if you prefer; Velum does not automate it.",
        "gaps": ["Minimum fields ContactOut needs to match a record, and whether a work email differs from the sender.",
                 "Whether its support team routes emailed erasure requests to a privacy process, and its acknowledgment format."],
        "next_action": "Prepare the exact email from My information, review it, approve it once and send.",
    },
    "hunter": {
        "scope": "Deletion of your personal data from Hunter, including the professional email profile in its Business Profile database. Hunter account deletion and its Claim page are separate flows.",
        "route_evidence": "Hunter's Privacy Policy (last updated April 13, 2026; read 2026-10-08 and 2026-10-09) gives residents of 15 named states a right to delete, covers its database subjects, and says to submit requests to its privacy email. California is excluded because its notice (January 3, 2023) lists only a web link or phone for deletion requests. Hunter's removal guide documents the Claim page for listed addresses. No message has been sent to or accepted by Hunter through Velum.",
        "inputs": [
            input_rule("email", "Your professional email (sender and the record to delete)", "unknown", "official_documentation", [HUNTER_POLICY, HUNTER_GUIDE], "Hunter lists professional addresses, not webmail. Used only when it is marked professional, is reachable, and is your connected sending account; Velum never guesses from a domain."),
            input_rule("us_state", "Your current state of residence", "unknown", "official_documentation", [HUNTER_POLICY], "The rights apply to residents of the 15 named states. Taken only from your saved current residence."),
        ],
        "verification": "Hunter says it may verify your identity before fulfilling a request; its listed examples are account details. Sending from the professional address shows you control it. Any follow-up arrives in that inbox; Velum never reads it.",
        "completion": "Your mail provider accepting the message is transport acceptance only. Hunter's deletion wording covers data collected from you, and it may point you to its Claim page instead. Record its actual wording and complete any Claim step yourself.",
        "follow_up": "Hunter's policy says it responds within 45 days and may extend by another 45. Set a local review date; this is its stated policy, not a tested service level.",
        "fallback": "Hunter's removal guide documents its Claim page: enter your professional email, confirm from your inbox, review and delete. California residents use that page, its link or telephone line, or DROP. Velum does not automate any of them.",
        "gaps": ["Whether Hunter processes an emailed state-rights request for a Business Profile or redirects it to the Claim page.",
                 "Hunter's acknowledgment format, and whether one request covers both found and generated versions of an address."],
        "next_action": "Mark which current email is professional in My information, then prepare, review, approve and send.",
    },
    "whitepages": unknown_guide("Personal listing removal; specific products and regional eligibility remain unverified.",
        "Company confirmed in the California registry. Official help-page inspection safety-blocked on 2026-10-07; this is not field verification.",
        "Current help instructions and the final removal destination.",
        "Read the official help page yourself before entering information. Track only a listing you have manually confirmed."),
    "peoplefinders": unknown_guide("Personal listing removal; current product coverage and eligibility remain unverified.",
        "Company confirmed in the California registry. Opt-out page inspection safety-blocked on 2026-10-07; this is not field verification.",
        "Current opt-out instructions and any subsequent destination.",
        "Inspect the official opt-out page yourself. Listing tracking is available, but a request cannot yet be prepared here."),
    "spokeo": unknown_guide("Spokeo listing removal; do not infer suppression across affiliates or every product.",
        "Official documentation retrieval challenged and opt-out browser inspection safety-blocked on 2026-10-07. Current requirements are unknown.",
        "Current supported method and final submission destination.",
        "Review Spokeo's official help yourself. Do not reuse the mock's illustrative email/listing fields as a real request."),
    "beenverified": unknown_guide("BeenVerified listing removal; affiliate coverage must be checked independently.",
        "Official opt-out FAQ retrieval returned a security challenge on 2026-10-07. Current requirements are unknown.",
        "Current FAQ instructions and final submission destination.",
        "Review BeenVerified's official opt-out FAQ yourself. The demo is not evidence of the live form's requirements."),
})


def requirements(identifier):
    return {**deepcopy(REQUIREMENTS[identifier]), "schema": 1,
            "server_validation": "untested", "acceptance": list(ACCEPTANCE),
            "pilot_checks": list(PILOT_CHECKS)}
