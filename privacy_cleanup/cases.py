"""Real local case management. Every external action is a manual user handoff.

All reads/writes share the vault lock and transaction. A handoff reservation is
committed before a URL is returned. This module has no network, browser or mail transport;
owner-email sending is separate (execution.py).
"""
import copy
import re
import secrets
import string
import time
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from .domain import RuleError, digest
from .identity import selected_fields
from .routes import FIELDS, catalog, fresh, route
from .workflow import Workflow, external_context, paused

APPROVAL_SECONDS = 24 * 3600
MAX_CASES = 100
MAX_EVENTS = 1000
# Broker replies, recorded the same way for email and manual requests. Each is the broker's own
# report: "deletion reported" is not independently verified removal, and "no record reported" is
# not proof the broker never held any data.
REPLIES = {"acknowledged", "verification_required", "verification_completed", "deletion_reported",
           "suppression_reported", "no_record_reported", "denied", "unknown"}
SENT_EMAIL = {"transport_accepted", "user_confirmed_sent", "user_sent"}
REPLY_NEXT = {
    "acknowledged": "The broker acknowledged your request. Waiting on the broker; record its next reply here.",
    "verification_required": "The broker asked you to verify. Complete it in your own inbox or on the broker's site, then record that you did.",
    "verification_completed": "Verification recorded. Waiting on the broker; record its next reply here.",
    "no_record_reported": "The broker says it holds no record. That is its report, not proof it never held your data; keep the dated reply.",
    "denied": "The broker refused. Add its stated reason as a note, and check its reply for any appeal or next step.",
}


# The attention home's groups, in display order. Waiting is calm: nothing is called overdue unless
# the owner chose a review date or a broker stated a deadline (none is recorded today).
GROUPS = ("do", "review", "waiting", "recorded")
SENT = {"transport_accepted", "user_confirmed_sent", "user_sent"}
FINAL_REPLIES = {"deletion_reported": ("Broker reports deletion", "done"),
                 "suppression_reported": ("Broker reports suppression", "done"),
                 "no_record_reported": ("Says it holds no record", "done"),
                 "denied": ("Refused", "error")}


def attention(view):
    """Where one case belongs on the attention home, or None when nothing is pending: the group,
    a status word and its tone, one sentence, the date that matters and where that date came from.
    Recorded moments stay full UTC timestamps so the page can show the local day; dates the person
    entered (a reply's received date, a review date) stay as they were entered."""
    email, attempt = view.get("execution_status"), view.get("attempt") or {}
    job, last = view.get("execution") or {}, view["outcome"]["last_reply"]
    reply = view["broker_response"]
    item = {"case_id": view["id"], "broker": view["broker"], "date": None, "source": None}
    if email == "uncertain" or attempt.get("state") in {"handoff_started", "uncertain"}:
        return {**item, "group": "do", "label": "Uncertain", "tone": "uncertain",
                "detail": "It may or may not have reached the broker. Check your Sent folder or the broker’s replies, "
                          "and record what you found. Velum won’t send it again on its own.",
                "date": job.get("dispatched_at") or attempt.get("started_at") or None, "source": "attempt"}
    if reply == "verification_required":
        return {**item, "group": "do", "label": "Verify with broker", "tone": "action",
                "detail": "The broker asked you to verify. Follow its steps in your own inbox or on its site, then record that you did.",
                "date": (last or {}).get("received_on") or (last or {}).get("at") or None, "source": "reply you recorded"}
    if view["match"] == "candidate_found":
        return {**item, "group": "do", "label": "Your turn", "tone": "action",
                "detail": "Compare the listing with your information, then confirm or reject it.",
                "date": view["created_at"], "source": "listing you added"}
    if view["due"]:
        return {**item, "group": "do", "label": "Review date", "tone": "action",
                "detail": "The review date you chose has arrived. Check for a reply and record what you find.",
                "date": view["review_on"], "source": "date you chose"}
    if email in {"prepared", "expired"} or view["request_status"] in {"prepared", "expired"}:
        return {**item, "group": "review", "label": "Ready to review", "tone": "review",
                "detail": "Review the exact request. Nothing goes out until you approve it.", "date": job.get("prepared_at") or None,
                "source": "prepared"}
    if email == "approved" or view["request_status"] == "approved":
        return {**item, "group": "review", "label": "Approved, not sent", "tone": "review",
                "detail": "Approved and waiting for you to send it.", "date": None, "source": None}
    if reply in FINAL_REPLIES:
        label, tone = FINAL_REPLIES[reply]
        return {**item, "group": "recorded", "label": label, "tone": tone,
                "detail": "This is the broker’s own report, not proof." if tone == "done" else "Note the broker’s stated reason; Velum doesn’t send the request again.",
                "date": (last or {}).get("received_on") or (last or {}).get("at") or None, "source": "reply you recorded"}
    if email in SENT or attempt.get("state") == "submitted_user_reported":
        sent = job.get("dispatched_at") or attempt.get("started_at") or None
        chosen = view["review_on"]
        return {**item, "group": "waiting", "label": "Waiting on broker", "tone": "waiting",
                "detail": ("You chose a date to check again." if chosen else "No deadline was stated."),
                "date": sent, "source": "sent", "check_on": chosen}
    return None


def stamp(timestamp):
    return datetime.fromtimestamp(timestamp, timezone.utc).isoformat(timespec="seconds")


def text(value, limit=1500, required=True):
    if not isinstance(value, str) or len(value) > limit or any(not c.isprintable() and c != "\n" for c in value):
        raise RuleError("Use bounded text without control characters")
    value = value.strip()
    if required and not value:
        raise RuleError("Add a short evidence note before continuing")
    return value


def past_day(value, timestamp):
    """A YYYY-MM-DD date that is not in the future, or an empty string when left blank."""
    if value == "":
        return ""
    try:
        if not isinstance(value, str) or len(value) != 10 or date.fromisoformat(value).isoformat() != value:
            raise ValueError()
        if value > stamp(timestamp)[:10]:
            raise ValueError()
    except ValueError:
        raise RuleError("Use the date the reply arrived (YYYY-MM-DD), not a future date") from None
    return value


def outcome(case):
    """The separate stages of a request, derived from the dated history; nothing is rewritten.

    Sending, acknowledgment, verification and the broker's reported result stay distinct, and a
    public listing's own observation is kept apart from what the broker reports."""
    job, attempt = case.get("execution") or {}, case.get("attempt") or {}
    stages = {"sent": job.get("state") or attempt.get("state") or "not_sent_yet", "acknowledged": False,
              "verification": None, "broker_reported": None, "observed": case["visibility"], "last_reply": None}
    for event in case["history"]:
        kind = event["kind"]
        if not kind.startswith("broker_"):
            continue
        reply = kind[len("broker_"):]
        stages["last_reply"] = {"result": reply, "at": event["at"], "received_on": event.get("received_on") or None}
        if reply == "acknowledged":
            stages["acknowledged"] = True
        elif reply == "verification_required":
            stages["verification"] = "requested"
        elif reply == "verification_completed":
            stages["verification"] = "completed"
        elif reply in {"deletion_reported", "suppression_reported", "no_record_reported", "denied"}:
            stages["broker_reported"] = reply
    return stages


UNRESERVED = set(string.ascii_letters + string.digits + "-._~")


def _normalize_escapes(value):
    def escape(match):
        char = chr(int(match.group(1), 16))
        return char if char in UNRESERVED else "%" + match.group(1).upper()
    return re.sub(r"%([0-9A-Fa-f]{2})", escape, value)


def _canonical_path(path):
    """One spelling per listing path: decode unreserved escapes; refuse dot/empty segments and params."""
    if ";" in path or re.search(r"%(?![0-9A-Fa-f]{2})", path):
        raise ValueError()
    segments = _normalize_escapes(path).rstrip("/").split("/")[1:]
    if not segments or any(s in {"", ".", ".."} for s in segments):
        raise ValueError()
    return "/" + "/".join(segments)


def listing_key(broker, url):
    # Compare old encoded URLs as well as new canonical ones without rewriting
    # historical evidence. Reserved escapes remain encoded.
    return broker, _normalize_escapes(url).casefold()


def listing_url(value, item):
    value = text(value, 1500)
    try:
        url = urlsplit(value)
        if (url.scheme != "https" or url.netloc != url.hostname or
                url.hostname not in item["listing_hosts"] or url.query or url.fragment or
                not url.path.startswith("/") or "\\" in value or any(c.isspace() for c in value)):
            raise ValueError()
        return urlunsplit(("https", url.hostname, _canonical_path(url.path), "", ""))
    except ValueError:
        raise RuleError("Use an HTTPS listing URL on this broker's listed host, without query, fragment, login details or ./.. path segments") from None


class Cases:
    def __init__(self, vault, clock=time.time):
        self.vault, self.clock = vault, clock
        self.execution = None  # Set by execution.Execution for owner-email routes.

    def _load(self):
        cases = []
        for (identifier,) in self.vault.db.execute("SELECT id FROM records WHERE id NOT IN ('profile', 'workflow', 'sender', 'recovery')"):
            if not re.fullmatch(r"case/[0-9a-f]{32}", identifier):
                raise RuleError("Unsupported vault record; use the matching application")
            body, revision = self.vault._read_record(identifier)
            if body.get("schema") != 1 or body.get("id") != identifier[5:]:
                self.vault.lock()
                raise RuleError("Unsupported private case schema")
            cases.append({**body, "version": revision})
        return cases

    def _event(self, case, kind, note, timestamp, **details):
        if len(case["history"]) >= MAX_EVENTS:
            raise RuleError("Case history limit reached; no records were changed")
        local = kind in {"request_prepared", "request_approved", "approval_revoked", "handoff_started", "review_date"}
        if case.get("request") and case["request"].get("id"):
            details["request_id"] = case["request"]["id"]
        case["history"].append({"at": stamp(timestamp), "kind": kind, "note": note,
                                "provenance": "local_action" if local else "user_reported", **details})
        case["updated_at"] = stamp(timestamp)

    def _save(self, case):
        body = copy.deepcopy(case)
        version = body.pop("version") + 1
        self.vault._write_record("case/" + case["id"], body, version)

    def _request_status(self, case, profile, timestamp):
        req = case.get("request")
        if not req:
            return "not_prepared"
        if case.get("attempt"):
            return "consumed"
        if req["revoked"]:
            return "revoked"
        item = route(case["broker"])
        if req["snapshot"]["profile_version"] != profile["version"] or req["snapshot"]["route"] != item:
            return "invalidated"
        if req["snapshot"].get("external_context") != external_context(self.vault, case["broker"])["fingerprint"]:
            return "invalidated"
        if not fresh(item, timestamp):
            return "source_review_due"
        approval = req["approval"]
        if approval:
            if timestamp < approval["at_epoch"] or timestamp >= approval["expires_epoch"]:
                return "expired"
            return "approved"
        return "prepared"

    def _view(self, case, profile, timestamp):
        result = copy.deepcopy(case)
        result["request_status"] = self._request_status(case, profile, timestamp)
        result["due"] = bool(case["review_on"] and case["review_on"] <= stamp(timestamp)[:10])
        attempt = case.get("attempt")
        if case["match"] == "rejected":
            result["next_step"] = "Rejected match. No request can be prepared for this candidate."
        elif attempt and attempt["state"] in {"handoff_started", "uncertain"}:
            result["next_step"] = "Reconcile this handoff before doing anything again. Check the broker page or your inbox; do not submit a second request."
        elif case["broker_response"] == "verification_required":
            result["next_step"] = "Complete verification directly with the broker. Record only the outcome here."
        elif attempt and attempt["state"] == "submitted_user_reported":
            result["next_step"] = "Review the broker response on your chosen date. Submission is your report, not independently verified receipt."
        elif external_context(self.vault, case["broker"])["blocked"]:
            result["next_step"] = "An external request to this broker blocks another handoff. Review its history in Submissions; reconcile an uncertain record before trying again."
        elif result["request_status"] == "approved" and paused(self.vault, case["id"]):
            result["next_step"] = "Resume the paused batch before starting a new handoff. Existing external pages are unaffected."
        elif result["request_status"] == "approved":
            result["next_step"] = "Begin one manual handoff, then submit directly on the official site if its fields still match."
        elif case["match"] == "candidate_found":
            result["next_step"] = "Compare the evidence and confirm or reject this listing. Finding a candidate does not confirm a match."
        elif route(case["broker"])["readiness"] == "guidance_only":
            result["next_step"] = "Review the official instructions yourself. This catalog entry supports local tracking and manual guidance; request preparation is unavailable."
        else:
            result["next_step"] = "Prepare and review the exact fields for one request. Saving information is not approval."
        if route(case["broker"])["readiness"] == "owner_email":
            if self.execution is not None:
                result["execution_status"], result["next_step"] = self.execution.view(case, profile, timestamp)
            else:
                result["execution_status"] = "not_prepared"
                result["next_step"] = "This build has no sending component; nothing can be sent."
        if case["broker_response"] in REPLY_NEXT and result.get("execution_status", "") not in {"uncertain", "prepared", "approved", "expired"}:
            result["next_step"] = REPLY_NEXT[case["broker_response"]]
        if case["broker_response"] in {"deletion_reported", "suppression_reported"}:
            result["next_step"] = ("Keep the dated broker statement. This private database has no public listing check."
                                   if case["kind"] == "private_database" else
                                   "Record a dated check of the exact listing. A broker statement alone does not prove absence.")
        result["outcome"] = outcome(case)
        return result

    def state(self, session):
        with self.vault.mutex:
            self.vault._authorize(session)
            if self.execution is not None:
                # Record results that arrived while locked and mark sends interrupted by a crash or
                # restart as uncertain before showing anything, so the versions a page loads are final.
                self.execution.settle()
            profile = self.vault._read()
            timestamp = self.clock()
            cases = [self._view(c, profile, timestamp) for c in self._load()]
            cases.sort(key=lambda c: (not c["due"], c["review_on"] or "9999", c["created_at"]))
            items = [a for a in (attention(c) for c in cases) if a]
            home = {"items": items, "counts": {g: sum(1 for a in items if a["group"] == g) for g in GROUPS}}
            from .recovery import recovery_status
            return {"recovery": recovery_status(self.vault), "cases": cases, "attention": home, "catalog": catalog(timestamp), "profile_version": profile["version"],
                    "dry_run": True, "automatic_submission": False,
                    "sender": self.execution.sender_state() if self.execution else {"configured": False, "kind": None, "simulated": False,
                                                                                         "broker_sending": False, "account": None, "gmail": None},
                    "workflow": Workflow(self.vault, self).state(session, profile, cases, timestamp)}

    def _new(self, broker, url, note, timestamp):
        item = route(broker)
        case = {"schema": 1, "id": secrets.token_hex(16), "version": 0, "broker": broker,
                "kind": item["kind"], "listing_url": url, "match": "candidate_found" if url else "not_applicable",
                "possession": "unknown", "created_at": stamp(timestamp), "updated_at": stamp(timestamp),
                "request": None, "past_requests": [], "attempt": None, "past_attempts": [],
                "broker_response": "unknown", "visibility": "unknown" if url else "not_applicable",
                "visibility_at": None, "review_on": None, "history": []}
        self._event(case, "candidate_found" if url else "private_database_case", note, timestamp)
        return case

    def create(self, session, broker, url, note, self_only):
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            if self.vault.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before changing cases")
            item = route(broker)
            if self_only is not True:
                raise RuleError("This version is for one adult acting only for themselves")
            if not self.vault._read()["profile"]:
                raise RuleError("Save your local profile first")
            note = text(note)
            if item["kind"] == "private_database":
                if url != "":
                    raise RuleError("Private database requests do not have a public listing URL")
            else:
                url = listing_url(url, item)
            with self.vault.db:
                self.vault.db.execute("BEGIN IMMEDIATE")
                existing = self._load()
                if len(existing) >= MAX_CASES:
                    raise RuleError("Local case limit reached")
                if any(listing_key(c["broker"], c["listing_url"]) == listing_key(broker, url) for c in existing):
                    raise RuleError("This broker or listing already has a case; continue its history instead")
                timestamp = self.clock()
                case = self._new(broker, url, note, timestamp)
                self._save(case)
            return self.state(session)

    def _fields(self, values, item, timestamp):
        if not isinstance(values, dict) or set(values) - set(item["fields"]):
            raise RuleError("Use only the fields in this reviewed local draft")
        fields = {key: text(value, FIELDS[key][1], required=False) for key, value in values.items()}
        fields = {key: value for key, value in fields.items() if value}
        if any(not fields.get(key) for key in item["required_for_preparation"]):
            raise RuleError("First name, last name and email are required by the app to prepare a draft; broker acceptance is untested")
        email = fields["email"]
        if email.count("@") != 1 or any(c.isspace() for c in email) or not all(email.split("@")) or "." not in email.split("@")[1]:
            raise RuleError("Check the request email format")
        if "birth_date" in fields:
            try:
                born = date.fromisoformat(fields["birth_date"])
                today = datetime.fromtimestamp(timestamp, timezone.utc).date()
                age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
                if not 18 <= age <= 120 or born.isoformat() != fields["birth_date"]:
                    raise ValueError()
            except ValueError:
                raise RuleError("If provided, birth date must be YYYY-MM-DD for an adult") from None
        return {**item["fixed_fields"], **fields}

    def command(self, session, identifier, version, action, data):
        if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise RuleError("Select an existing case")
        schemas = {"confirm": {"note"}, "reject": {"note"}, "prepare": {"fields", "self_only"},
                   "approve": {"fingerprint", "acknowledged"}, "revoke": set(),
                   "handoff": {"fingerprint", "dry_run"}, "outcome": {"result", "note"},
                   "response": {"result", "note"}, "check": {"result", "note"},
                   "review": {"date"}, "note": {"note"}}
        if isinstance(data, dict) and action == "prepare":
            schemas["prepare"] |= set(data) & {"identifiers", "drop_acknowledged"}
        if isinstance(data, dict) and action == "response":
            schemas["response"] |= set(data) & {"received_on"}
        if not isinstance(action, str) or action not in schemas or not isinstance(data, dict) or set(data) != schemas[action]:
            raise RuleError("Unsupported case command fields")
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            if self.vault.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before changing cases")
            if action in {"prepare", "approve", "handoff"}:
                from .recovery import require_reconciled
                require_reconciled(self.vault)
            handoff_url = None
            with self.vault.db:
                self.vault.db.execute("BEGIN IMMEDIATE")
                cases = self._load()
                case = next((c for c in cases if c["id"] == identifier), None)
                if not case or type(version) is not int or version != case["version"]:
                    raise RuleError("Case changed; reload before continuing")
                profile, timestamp, item = self.vault._read(), self.clock(), route(case["broker"])
                if action in {"confirm", "reject"}:
                    if case["match"] != "candidate_found":
                        raise RuleError("Only an unreviewed candidate can be confirmed or rejected")
                    case["match"] = "confirmed" if action == "confirm" else "rejected"
                    self._event(case, "match_" + case["match"], text(data["note"]), timestamp)
                elif action == "prepare":
                    context = external_context(self.vault, case["broker"])
                    if context["blocked"]:
                        raise RuleError("An external request for this broker blocks another request; reconcile uncertain history first")
                    if context["drop_overlap"] and data.get("drop_acknowledged") is not True:
                        raise RuleError("Review the possible overlap with your recorded DROP request before preparing a separate request")
                    if case["attempt"]:
                        raise RuleError("An existing handoff blocks another request; reconcile its outcome first")
                    if case["match"] not in {"confirmed", "not_applicable"}:
                        raise RuleError("Confirm the listing match before preparing a request")
                    if data["self_only"] is not True or item["readiness"] != "manual_preparation" or not fresh(item, timestamp):
                        raise RuleError("This route needs current source review or supports guidance only; no request prepared")
                    if profile["profile"]["residence"]["country"] != "US":
                        raise RuleError("This form preparation is for US residents; review your profile country first")
                    if profile["profile"]["self_adult"] is not True:
                        raise RuleError("Review the adult self-service acknowledgment in My information")
                    fields = self._fields(data["fields"], item, timestamp)
                    identifiers = selected_fields(profile["profile"], data.get("identifiers", {}), fields)
                    snapshot = {"profile_version": profile["version"], "route": item,
                                "listing_url": case["listing_url"], "fields": fields, "identifiers": identifiers,
                                "mode": "manual_only", "purpose": item["purpose"],
                                "external_context": context["fingerprint"], "drop_overlap_acknowledged": context["drop_overlap"]}
                    if case["request"]:
                        case["past_requests"].append(case["request"])
                    case["request"] = {"id": secrets.token_hex(16), "snapshot": snapshot, "fingerprint": digest(snapshot), "prepared_at": stamp(timestamp),
                                       "approval": None, "revoked": False}
                    self._event(case, "request_prepared", "Exact disclosure prepared locally; nothing sent.", timestamp)
                elif action == "approve":
                    if self._request_status(case, profile, timestamp) not in {"prepared", "expired"}:
                        raise RuleError("Prepare a current request before approving it")
                    req = case["request"]
                    if data["acknowledged"] is not True or data["fingerprint"] != req["fingerprint"] or digest(req["snapshot"]) != req["fingerprint"]:
                        raise RuleError("Review and approve this exact disclosure first")
                    req["approval"] = {"at_epoch": timestamp, "expires_epoch": timestamp + APPROVAL_SECONDS,
                                       "fingerprint": req["fingerprint"], "at": stamp(timestamp),
                                       "expires_at": stamp(timestamp + APPROVAL_SECONDS)}
                    self._event(case, "request_approved", "One manual handoff approved for this revision; expires in 24 hours.", timestamp)
                elif action == "revoke":
                    if not case["request"] or case["attempt"]:
                        raise RuleError("There is no unused approval to revoke")
                    case["request"]["revoked"] = True
                    self._event(case, "approval_revoked", "Unused request revoked locally.", timestamp)
                elif action == "handoff":
                    if external_context(self.vault, case["broker"])["blocked"]:
                        raise RuleError("An external request for this broker blocks another handoff")
                    if paused(self.vault, identifier) and data["dry_run"] is not True:
                        raise RuleError("This batch is paused; resume before starting another handoff")
                    if type(data["dry_run"]) is not bool:
                        raise RuleError("Choose dry-run or a specific manual handoff")
                    if self._request_status(case, profile, timestamp) != "approved":
                        raise RuleError("A current, unused approval is required for this handoff")
                    req = case["request"]
                    if data["fingerprint"] != req["fingerprint"] or digest(req["snapshot"]) != req["fingerprint"] or req["approval"]["fingerprint"] != req["fingerprint"]:
                        raise RuleError("Approval does not match this disclosure")
                    if data["dry_run"]:
                        return {**self.state(session), "dry_run_result": "Checked locally. No handoff reserved and no information transmitted."}
                    if any(c["attempt"] and listing_key(c["broker"], c["listing_url"]) == listing_key(case["broker"], case["listing_url"]) for c in cases):
                        raise RuleError("An existing attempt blocks a duplicate")
                    case["attempt"] = {"id": secrets.token_hex(16), "state": "handoff_started",
                                       "started_at": stamp(timestamp), "fingerprint": req["fingerprint"], "request_id": req["id"]}
                    handoff_url = item["destination"]
                    self._event(case, "handoff_started", "Manual handoff reserved. Opening a link is not submission. Outcome remains unknown until reconciled.", timestamp)
                elif action == "outcome":
                    attempt = case["attempt"]
                    if not attempt or attempt["state"] not in {"handoff_started", "uncertain"}:
                        raise RuleError("Reconcile an open or uncertain handoff first")
                    if data["result"] not in {"submitted", "uncertain", "not_disclosed"}:
                        raise RuleError("Choose a supported handoff outcome")
                    note = text(data["note"])
                    if data["result"] == "not_disclosed":
                        attempt["state"] = "closed_without_disclosure_user_reported"
                        case["past_attempts"].append(attempt)
                        case["attempt"] = None
                        case["request"]["revoked"] = True
                    else:
                        attempt["state"] = "submitted_user_reported" if data["result"] == "submitted" else "uncertain"
                    self._event(case, "handoff_" + data["result"], note, timestamp)
                elif action == "response":
                    manual = bool(case["attempt"] and case["attempt"]["state"] == "submitted_user_reported")
                    email = (case.get("execution") or {}).get("state") in SENT_EMAIL
                    if not (manual or email):
                        raise RuleError("Record a broker reply after the request was sent: a confirmed email or a submitted handoff")
                    if data["result"] not in REPLIES:
                        raise RuleError("Choose a supported broker response")
                    details = {"via": "email" if email else "manual"}
                    if "received_on" in data:
                        details["received_on"] = past_day(data["received_on"], timestamp)
                    case["broker_response"] = data["result"]
                    self._event(case, "broker_" + data["result"], text(data["note"]), timestamp, **details)
                elif action == "check":
                    if case["kind"] != "public_listing" or case["match"] != "confirmed":
                        raise RuleError("Only a confirmed public listing can have an absence check")
                    if data["result"] not in {"present", "absent", "blocked", "failed", "ambiguous"}:
                        raise RuleError("Choose a supported visibility observation")
                    case["visibility"] = data["result"] if data["result"] in {"present", "absent"} else "unknown"
                    case["visibility_at"] = stamp(timestamp)
                    self._event(case, "listing_check", text(data["note"]), timestamp, result=data["result"], listing_url=case["listing_url"])
                elif action == "review":
                    try:
                        value = data["date"]
                        if not isinstance(value, str) or (value and (date.fromisoformat(value).isoformat() != value or len(value) != 10)):
                            raise ValueError()
                    except ValueError:
                        raise RuleError("Choose a valid review date or leave it blank") from None
                    case["review_on"] = value or None
                    self._event(case, "review_date", "Local review date changed; no background check or reminder scheduled.", timestamp, review_on=value)
                else:
                    self._event(case, "note", text(data["note"]), timestamp)
                self._save(case)
            result = self.state(session)
            if handoff_url:
                result["handoff_url"] = handoff_url
            return result

    def submissions(self, session):
        """Read-only request history. Never project today's profile onto old requests."""
        with self.vault.mutex:
            self.vault._authorize(session)
            profile, timestamp = self.vault._read(), self.clock()
            entries, emails, histories = [], [], {}
            for case in self._load():
                view = self._view(case, profile, timestamp)
                requests = case["past_requests"] + ([case["request"]] if case["request"] else [])
                attempts = case["past_attempts"] + ([case["attempt"]] if case["attempt"] else [])
                counts = Counter(r["fingerprint"] for r in requests)
                indexed = defaultdict(list)
                ambiguous = set()
                for attempt in attempts:
                    if attempt.get("request_id"):
                        indexed[("id", attempt["request_id"])].append(attempt)
                    elif counts[attempt["fingerprint"]] == 1:
                        indexed[("fingerprint", attempt["fingerprint"])].append(attempt)
                    else:
                        # Old records have only a fingerprint. Do not invent
                        # an association with one of several identical revisions.
                        ambiguous.add(attempt["fingerprint"])
                if requests:
                    # Carry each case's evidence once, not once per revision.
                    histories[case["id"]] = copy.deepcopy(case["history"])
                for index, request in enumerate(requests):
                    current = request is case["request"]
                    matching = indexed.get(("id", request.get("id")), []) + indexed.get(("fingerprint", request["fingerprint"]), [])
                    entries.append({"id": case["id"] + "/" + str(index), "case_id": case["id"],
                                    "revision": index + 1,
                                    "broker": case["broker"], "request": copy.deepcopy(request),
                                    "attempts": copy.deepcopy(matching), "current": current,
                                    "request_status": self._request_status(case, profile, timestamp) if current else "superseded",
                                    "broker_response": case["broker_response"] if current else "see_dated_history",
                                    "visibility": case["visibility"] if current else "see_dated_history",
                                    "visibility_at": case["visibility_at"] if current else None,
                                    "review_on": case["review_on"] if current else None,
                                    "due": view["due"] if current else False,
                                    "next_step": view["next_step"] if current else "Earlier revision. Review the dated evidence and current case before taking another action.",
                                    "legacy_attempt_alignment_unknown": request["fingerprint"] in ambiguous})
                jobs = case.get("past_executions", []) + ([case["execution"]] if case.get("execution") else [])
                if jobs:
                    histories[case["id"]] = copy.deepcopy(case["history"])
                for index, job in enumerate(jobs):
                    current = job is case.get("execution")
                    emails.append({"id": case["id"] + "/email/" + str(index), "case_id": case["id"], "revision": index + 1,
                                   "broker": case["broker"], "current": current,
                                   # Exactly what was prepared and stored; nothing is re-rendered from
                                   # today's identity or contract. Older entries may lack a contract record.
                                   "contract_id": job["contract_id"], "contract_version": job["contract_version"],
                                   "contract": copy.deepcopy(job.get("contract")), "message": copy.deepcopy(job["message"]),
                                   "selected": sorted(job["identifiers"]), "fingerprint": job["fingerprint"],
                                   "prepared_at": job["prepared_at"],
                                   "approved_at": job["approval"]["at"] if job["approval"] else None,
                                   "dispatched_at": job["dispatched_at"], "result": copy.deepcopy(job["result"]),
                                   "status": view.get("execution_status", job["state"]) if current else ("superseded" if job["state"] == "prepared" else job["state"]),
                                   "next_step": view["next_step"] if current else "Earlier email. Review the dated case history before taking another action."})
            return {"entries": entries, "emails": emails, "histories": histories}
