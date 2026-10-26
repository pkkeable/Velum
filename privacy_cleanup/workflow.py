"""Local batch planning and user-reported external history. No outbound I/O.

One persistent batch covers the queue. A new batch starts ready (each request still needs its
own approval); refreshing keeps whatever pause the owner chose. Pause controls new sends and
handoff reservations, not already opened broker pages. Required values come from one saved identity.
"""
import secrets
from collections import Counter
from datetime import date, datetime, timezone

from . import contracts
from .domain import RuleError, digest
from . import identity
from .identity import BINDINGS
from .routes import ROUTES, catalog, fresh, route

RECORD = "workflow"
RESEARCH = {
    "apollo": "Apollo", "cognism": "Cognism", "contactout": "ContactOut",
    "lusha": "Lusha", "hunter": "Hunter", "truepeoplesearch": "TruePeopleSearch",
    "fastpeoplesearch": "FastPeopleSearch", "nuwber": "Nuwber",
}
DROP_URL = "https://privacy.ca.gov/drop/"
# Owner-email states from which "Prepare all ready emails" may prepare a fresh email.
PREPARABLE = {"not_prepared", "revoked", "invalidated", "not_sent", "user_reported_not_sent"}
MAX_CONFIRMED = 50


def read(vault):
    if not vault.db.execute("SELECT 1 FROM records WHERE id=?", (RECORD,)).fetchone():
        return {"schema": 1, "paused": True, "case_ids": [], "external": [], "history": []}, 0
    body, revision = vault._read_record(RECORD)
    if (set(body) != {"schema", "paused", "case_ids", "external", "history"} or
            body["schema"] != 1 or type(body["paused"]) is not bool or
            not all(isinstance(body[k], list) for k in ("case_ids", "external", "history"))):
        raise RuleError("Unsupported workflow record; use the matching application")
    return body, revision


def external_context(vault, broker):
    body, _ = read(vault)
    relevant = [e for e in body["external"] if e["broker"] in {broker, "drop"}]
    active = [e for e in relevant if e["state"] != "not_sent"]
    return {"blocked": any(e["broker"] == broker for e in active),
            "drop_overlap": any(e["broker"] == "drop" for e in active),
            "fingerprint": digest(relevant) if relevant else None}


def paused(vault, identifier):
    body, _ = read(vault)
    return body["paused"] and identifier in body["case_ids"]


def drop_status(profile):
    residence = (profile or {}).get("residence", {})
    country, region = residence.get("country", ""), residence.get("region", "").strip().casefold()
    if not country or (country == "US" and not region):
        return "needs_residence"
    return "eligible_self_reported" if country == "US" and region in {"ca", "california"} else "not_eligible"


def mapping(profile, item):
    """Minimum required fields only; choose preferred current or sole current entry.

    Never split a name, pick an arbitrary alias, combine different addresses or
    silently substitute a former/retired/unreachable verification identifier.
    """
    values, bindings, missing, choices, counts = {}, {}, [], {}, {}
    kind = {"professional": "Work", "personal": "Personal"}
    for key in item.get("required_for_preparation", []):
        if key == "birth_date":
            if profile.get(key):
                values[key], bindings[key] = profile[key], "profile_birth_date"
            else:
                missing.append("Add birth date in My information for this route")
            continue
        if key == "us_state":
            # Current residence only; an old or other address never supplies a jurisdiction.
            name = contracts.state_name(profile.get("residence"))
            if name:
                values[key], bindings[key] = name, "profile_residence"
            else:
                missing.append("Add your current US state of residence in My information")
            continue
        if key not in BINDINGS:
            missing.append("This route needs a reviewed field mapping")
            continue
        group, source = BINDINGS[key]
        use = item.get("email_use") if group == "emails" else None
        sender = item.get("sender") if group == "emails" else None
        if group not in choices:
            rows = [r for r in profile[group] if not r["retired"] and r["label"] == "current" and
                    (group != "emails" or r["reachable"]) and (not use or r["use"] == use) and
                    (not sender or r["value"].casefold() == sender.casefold())]
            preferred = [r for r in rows if r["preferred"]]
            choices[group] = preferred[0] if len(preferred) == 1 else rows[0] if len(rows) == 1 else None
            counts[group] = len(rows)
        row = choices[group]
        singular = {"names": "name", "emails": "email", "addresses": "address", "phones": "phone"}[group]
        if sender and not row:
            # The From address is the connected account itself, never another saved email.
            missing.append("Add your connected sending address to My information as a current email you can receive mail at"
                           + (", with type of address " + kind[use] if use else ""))
        elif use and not row:
            # Unknown or personal use fails closed; Velum never guesses from a domain.
            missing.append("Set one current email you can receive mail at to type of address " + kind[use] + " in My information for this route")
        elif not row and counts[group] > 1:
            missing.append("Mark one current " + singular + " as preferred in My information")
        elif not row:
            missing.append("Add a current email you can receive mail at (tick “I can receive verification messages here”) in My information"
                           if group == "emails" else "Add a current " + singular + " in My information")
        elif not row[source]:
            missing.append("Add a " + key.replace("_", " ") + " to your preferred current " + singular + " in My information")
        else:
            values[key], bindings[key] = row[source], row["id"]
    return values, bindings, missing


class Workflow:
    def __init__(self, vault, cases):
        self.vault, self.cases = vault, cases

    def _preparable(self, body, planned, cases, profile, timestamp):
        """Batch members whose exact email "Prepare all ready emails" may prepare: one per broker,
        an open route with nothing missing, and no DROP overlap, which needs its own review."""
        execution, open_routes, chosen = self.cases.execution, {}, []
        if execution is None:
            return chosen
        for row in planned:
            if row["state"] == "ready_to_prepare_email" and not row["drop_overlap"]:
                open_routes[row["broker"]] = True
        seen = set()
        for c in cases:
            if c["id"] not in body["case_ids"] or c["broker"] not in open_routes or c["broker"] in seen:
                continue
            if execution.status(c, profile, timestamp) in PREPARABLE:
                chosen.append(c["id"])
                seen.add(c["broker"])
        return chosen

    def _plan(self, profile, cases, timestamp):
        rows = []
        for item in catalog(timestamp):
            matches = [c for c in cases if c["broker"] == item["id"]]
            context = external_context(self.vault, item["id"])
            missing = []
            if not profile or not profile.get("self_adult"):
                missing.append("Tick “I am an adult acting only for myself” in My information")
            route_issue = None
            if item["readiness"] == "owner_email":
                contract = contracts.for_broker(item["id"])
                outcome, reason = contracts.eligibility(contract, profile["residence"]) if contract and profile else ("eligible", None)
                if not contract or not item["source_fresh"] or not contracts.fresh(contract, timestamp):
                    # Route evidence, never missing user data. Only this route pauses.
                    state = "source_review_due"
                    route_issue = (item["freshness"]["reason"] or "This route has no current sending contract. "
                                   "Preparing and sending are paused for this route only.")
                elif context["blocked"]:
                    state = "external_request_recorded"
                elif reason:
                    # Unknown residence asks for information; a known, uncovered one is not applicable.
                    state = "needs_information" if outcome == "needs_residence" else "route_not_available_in_jurisdiction"
                    missing.append(reason)
                else:
                    if profile:
                        account, problem = self.cases.execution.sender_binding() if self.cases.execution else (None, None)
                        missing.extend([problem] if problem else mapping(profile, contracts.requirement(contract, account))[2])
                    state = "needs_information" if missing else "ready_to_prepare_email"
            elif item["readiness"] != "manual_preparation":
                state = "guidance_only"
            elif not item["source_fresh"]:
                state = "source_review_due"
                route_issue = item["freshness"]["reason"]
            elif context["blocked"]:
                state = "external_request_recorded"
            elif not profile or profile["residence"]["country"] != "US":
                state = "needs_information" if not profile or not profile["residence"]["country"] else "route_not_available_in_country"
                missing.append("This local draft supports US residents; other route eligibility is separate")
            else:
                _, _, needs = mapping(profile, item)
                missing.extend(needs)
                state = "needs_information" if missing else "ready_for_local_preparation"
            if item["readiness"] == "owner_email" and state == "ready_to_prepare_email":
                # The route is open, but an earlier email to this broker already blocks another one.
                jobs = {(c.get("execution") or {}).get("state") for c in matches}
                if jobs & {"transport_accepted", "user_confirmed_sent", "user_sent"}:
                    state = "email_already_sent"
                elif jobs & {"dispatching", "uncertain"}:
                    state = "email_outcome_uncertain"
            rows.append({"broker": item["id"], "name": item["name"], "state": state, "missing": missing,
                         "route_issue": route_issue, "capability": item["capability"],
                         "case_ids": [c["id"] for c in matches], "drop_overlap": context["drop_overlap"]})
        rows.extend({"broker": key, "name": name, "state": "research_only", "missing": [], "route_issue": None,
                     "capability": "research_only", "case_ids": [],
                     "drop_overlap": external_context(self.vault, key)["drop_overlap"]} for key, name in RESEARCH.items() if key not in ROUTES)
        return rows

    def preview(self, session, draft):
        """What an unsaved draft would make available. Validates and plans in memory; writes and
        touches nothing. Preparing a request always uses the saved identity, never this draft."""
        with self.vault.mutex:
            self.vault._authorize(session)
            saved = self.vault._read()
            if saved["migration_required"]:
                raise RuleError("Upgrade this synthetic workspace before previewing changes")
            try:
                profile = identity.validate(draft, previous=saved["profile"])
            except RuleError as error:
                return {"ready": False, "problem": str(error), "rows": [], "changed": True}
            rows = self._plan(profile, self.cases._load(), self.cases.clock())
            return {"ready": True, "problem": None, "rows": rows, "changed": profile != saved["profile"]}

    def state(self, session, profile, cases, timestamp):
        # Caller already holds the vault mutex. No secret reads without authorization.
        self.vault._authorize(session)
        body, version = read(self.vault)
        if profile["migration_required"]:
            return {"version": version, "migration_required": True}
        planned = self._plan(profile["profile"], cases, timestamp)
        items = []
        for c in cases:
            if c["id"] not in body["case_ids"]:
                continue
            attempt = c.get("attempt")
            if c.get("execution_status") not in (None, "not_prepared"):
                state = "email_" + c["execution_status"]
            elif attempt and attempt["state"] in {"handoff_started", "uncertain"}:
                state = "reconcile_uncertain"
            elif c["broker_response"] == "verification_required":
                state = "waiting_for_verification"
            elif attempt:
                state = "submitted_user_reported"
            elif c["match"] == "rejected":
                state = "rejected_match"
            elif c["match"] == "candidate_found":
                state = "needs_match_confirmation"
            elif external_context(self.vault, c["broker"])["blocked"]:
                state = "external_request_recorded"
            elif c["request_status"] in {"approved", "prepared"}:
                state = "ready_for_manual_handoff" if c["request_status"] == "approved" else "needs_exact_approval"
            else:
                state = next(p["state"] for p in planned if p["broker"] == c["broker"])
            items.append({"id": c["id"], "broker": c["broker"], "state": state})
        return {**body, "version": version, "plan": planned, "items": items,
                "preparable": self._preparable(body, planned, cases, profile, timestamp),
                "counts": dict(Counter(i["state"] for i in items)),
                "drop": {"state": drop_status(profile["profile"]), "url": DROP_URL},
                "external_brokers": [{"id": k, "name": n} for k, n in
                                     {"drop": "California DROP", **{k: r["name"] for k, r in ROUTES.items()}, **RESEARCH}.items()]}

    def _pause(self, session, stamp):
        """Pausing is the batch's safety stop. For an authorized session it never depends
        on client revisions, identity completeness or the history cap, and it is idempotent.
        History stays bounded: only an active batch is recorded as paused, and resuming
        remains capped, so a full history grows by at most one pause event."""
        with self.vault.db:
            self.vault.db.execute("BEGIN IMMEDIATE")
            body, revision = read(self.vault)
            # Stores older than v4 have no workflow record and read as paused; never write one
            # there, so an un-upgraded vault stays readable by the matching older build.
            if not body["paused"]:
                body["paused"] = True
                body["history"].append({"at": stamp(self.cases.clock()), "action": "pause", "provenance": "local_action"})
                self.vault._write_record(RECORD, body, revision + 1)
        return self.cases.state(session)

    def _prepare_emails(self, session, version, profile_version):
        """Prepare each ready owner-email batch member's exact email. Preparing sends nothing and
        approves nothing; each email is then approved on its own. One refusal never stops the rest."""
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            if self.vault.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before preparing requests")
            body, revision = read(self.vault)
            profile = self.vault._read()
            if type(version) is not int or version != revision or type(profile_version) is not int or profile_version != profile["version"]:
                raise RuleError("Workflow or identity changed; reload before continuing")
            if not profile["profile"] or not profile["profile"]["self_adult"]:
                raise RuleError("Save your identity and adult self-service acknowledgment first")
            if self.cases.execution is None:
                raise RuleError("This build has no sending component")
            cases, timestamp = self.cases._load(), self.cases.clock()
            chosen = self._preparable(body, self._plan(profile["profile"], cases, timestamp), cases, profile, timestamp)
        results = []
        for identifier in chosen:
            try:
                self.cases.execution.command(session, identifier, None, "prepare", {"drop_acknowledged": False})
                results.append({"case_id": identifier, "outcome": "prepared", "reason": None})
            except RuleError as error:
                results.append({"case_id": identifier, "outcome": "not_prepared", "reason": str(error)})
        return {**self.cases.state(session), "prepare_results": results}

    def _dispatch(self, session, version, profile_version, fingerprints):
        """Send approved owner-email batch members the owner confirmed by exact fingerprint. An email
        approved after the confirmation was shown is not in that list and is not sent. Gates run
        under the vault mutex; transmission runs outside it so lock, pause and status stay
        responsive while a send is in flight."""
        if (not isinstance(fingerprints, list) or not 0 < len(fingerprints) <= MAX_CONFIRMED or
                not all(isinstance(f, str) and 0 < len(f) <= 128 for f in fingerprints) or
                len(set(fingerprints)) != len(fingerprints)):
            raise RuleError("Confirm the exact emails to send first")
        execution = self.cases.execution
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            if self.vault.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before sending requests")
            body, revision = read(self.vault)
            profile = self.vault._read()
            if type(version) is not int or version != revision or type(profile_version) is not int or profile_version != profile["version"]:
                raise RuleError("Workflow or identity changed; reload before continuing")
            if not profile["profile"] or not profile["profile"]["self_adult"]:
                raise RuleError("Save your identity and adult self-service acknowledgment first")
            if body["paused"]:
                raise RuleError("This batch is paused; resume before sending")
            if execution is None:
                raise RuleError("This build has no sending component; nothing was sent")
        results = execution.dispatch_batch(session, set(fingerprints))
        try:
            return {**self.cases.state(session), "dispatch_results": results}
        except RuleError:
            return {"dispatch_results": results, "locked": True}

    def command(self, session, version, profile_version, action, data):
        from .cases import MAX_CASES, stamp, text
        schemas = {"plan": set(), "pause": set(), "resume": set(),
                   "prepare": {"id", "case_version", "drop_acknowledged"},
                   "external": {"broker", "purpose", "date", "date_precision", "state", "note", "self_only"},
                   "reconcile": {"id", "state", "note"}, "dispatch": {"fingerprints"}, "prepare_emails": set()}
        if not isinstance(action, str) or action not in schemas or not isinstance(data, dict) or set(data) != schemas[action]:
            raise RuleError("Unsupported workflow command fields")
        if action in {"plan", "resume", "prepare", "prepare_emails", "dispatch"}:
            with self.vault.mutex:
                self.vault._authorize(session)
                from .recovery import require_reconciled
                require_reconciled(self.vault)
        if action == "dispatch":
            return self._dispatch(session, version, profile_version, data["fingerprints"])
        if action == "prepare_emails":
            return self._prepare_emails(session, version, profile_version)
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            if action == "pause":
                return self._pause(session, stamp)
            if self.vault.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before changing workflow records")
            body, revision = read(self.vault)
            profile = self.vault._read()
            if type(version) is not int or version != revision or type(profile_version) is not int or profile_version != profile["version"]:
                raise RuleError("Workflow or identity changed; reload before continuing")
            if not profile["profile"] or not profile["profile"]["self_adult"]:
                raise RuleError("Save your identity and adult self-service acknowledgment first")
            if action == "prepare":
                if data["id"] not in body["case_ids"]:
                    raise RuleError("Add this case to the batch first")
                case = next((c for c in self.cases._load() if c["id"] == data["id"]), None)
                if not case:
                    raise RuleError("Select an existing case")
                fields, bindings, missing = mapping(profile["profile"], route(case["broker"]))
                if missing:
                    raise RuleError("; ".join(missing))
                return self.cases.command(session, case["id"], data["case_version"], "prepare",
                                          {"fields": fields, "identifiers": bindings, "self_only": True,
                                           "drop_acknowledged": data["drop_acknowledged"]})
            with self.vault.db:
                self.vault.db.execute("BEGIN IMMEDIATE")
                timestamp = self.cases.clock()
                if len(body["history"]) >= 1000:
                    raise RuleError("Workflow history limit reached; no records were changed")
                if action == "plan":
                    cases = self.cases._load()
                    for row in self._plan(profile["profile"], cases, timestamp):
                        if row["state"] not in {"ready_for_local_preparation", "ready_to_prepare_email"} or row["case_ids"]:
                            continue
                        item = route(row["broker"])
                        if item["kind"] == "private_database":
                            if len(cases) >= MAX_CASES:
                                raise RuleError("Local case limit reached")
                            case = self.cases._new(row["broker"], "", "Added from saved identity to the local batch; possession remains unknown.", timestamp)
                            case["history"][-1]["provenance"] = "local_action"
                            self.cases._save(case)
                            cases.append(case)
                    # Membership is navigation, never match confirmation or approval. A new batch
                    # starts ready; a refresh keeps the owner's own pause.
                    body["case_ids"] = [c["id"] for c in cases]
                    if revision == 0:
                        body["paused"] = False
                elif action in {"pause", "resume"}:
                    body["paused"] = action == "pause"
                elif action == "external":
                    allowed = set(ROUTES) | set(RESEARCH) | {"drop"}
                    if not isinstance(data["broker"], str) or data["broker"] not in allowed or data["self_only"] is not True:
                        raise RuleError("Choose a listed broker for your own external request")
                    if len(body["external"]) >= 100:
                        raise RuleError("External request history limit reached")
                    state = text(data["state"], 40)
                    if state not in {"submitted", "uncertain"} or data["date_precision"] not in ("exact", "approximate"):
                        raise RuleError("Choose a dated submitted or uncertain report")
                    when = text(data["date"], 10)
                    try:
                        parsed = date.fromisoformat(when)
                        if parsed.isoformat() != when or parsed > datetime.fromtimestamp(timestamp, timezone.utc).date():
                            raise ValueError()
                    except ValueError:
                        raise RuleError("Use a past or current YYYY-MM-DD date; mark approximate when unsure") from None
                    event = {"at": stamp(timestamp), "state": state, "note": text(data["note"]), "provenance": "user_reported"}
                    body["external"].append({"id": secrets.token_hex(16), "broker": data["broker"],
                                             "purpose": text(data["purpose"], 200), "date": when,
                                             "date_precision": data["date_precision"], "state": state,
                                             "history": [event], "provenance": "user_reported_external",
                                             "original_payload": "unknown", "original_approval": "unknown"})
                else:
                    entry = next((e for e in body["external"] if e["id"] == data["id"]), None)
                    if not entry or entry["state"] != "uncertain" or data["state"] not in ("submitted", "not_sent"):
                        raise RuleError("Only an uncertain external request can be reconciled as submitted or not sent")
                    entry["history"].append({"at": stamp(timestamp), "state": data["state"],
                                             "note": text(data["note"]), "provenance": "user_reported"})
                    entry["state"] = data["state"]
                body["history"].append({"at": stamp(timestamp), "action": action, "provenance": "local_action"})
                self.vault._write_record(RECORD, body, revision + 1)
            return self.cases.state(session)
