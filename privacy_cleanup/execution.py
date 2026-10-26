r"""R3 durable outbox: owner-email requests that Velum transmits after exact approval.

Separate from manual cases semantics: a manual approval never becomes send authority, and a
route with a sending contract has no manual preparation path. One job per case, stored inside
the encrypted case record:

    prepared --approve--> (approved) --dispatch--> dispatching --> transport_accepted
                                                               \-> not_sent     (definitive)
                                                               \-> uncertain    (no retry)
    uncertain --found in Sent, or the broker replied--> user_confirmed_sent
    (approved) --you sent it yourself from your mail app--> user_sent
                                                       \-> uncertain    (you aren't sure it went)

"dispatching" is committed before any byte leaves this process. A dispatching job that this
process is not currently waiting on is treated as uncertain (crash or restart after possible
disclosure). Only a provider rejection (not_sent) proves an email was not sent: "not found in
Sent" is recorded but leaves the job uncertain. A new request after an uncertain one needs the
owner's explicit duplicate-risk acknowledgment; Velum never retries on its own.
(user_reported_not_sent survives only in records made before this rule.)
"""
import re
import secrets

from . import contracts
from .domain import RuleError
from .identity import selected_fields
from .routes import route
from .workflow import external_context, mapping, paused, read as read_workflow

APPROVAL_SECONDS = 24 * 3600
ACTIVE = {"dispatching", "transport_accepted", "uncertain", "user_confirmed_sent", "user_sent"}
SCHEMAS = {"prepare": {"drop_acknowledged"}, "approve": {"fingerprint", "acknowledged"}, "revoke": set(),
           "dispatch": {"fingerprint"}, "reconcile": {"result", "note"}, "self_sent": {"fingerprint", "result"}}
SELF_SENT = {"sent", "unsure"}
RECONCILE = {"sent_found", "broker_replied", "not_found_in_sent"}
STATES = {"accepted": "transport_accepted", "not_sent": "not_sent", "uncertain": "uncertain"}
NEXT = {
    "not_prepared": "Prepare the exact email from My information. Preparing sends nothing.",
    "prepared": "Review the exact sender, recipient, subject and body, then approve this one email.",
    "expired": "The approval expired. Review the exact email again before approving it.",
    "approved": "Send this approved email once, or revoke the approval. Velum transmits only this exact message.",
    "revoked": "Approval revoked. Prepare a fresh email to continue.",
    "invalidated": "Something it depends on changed (identity, sending account, contract or external history). Prepare a fresh email.",
    "source_review_due": "This route's official source needs review before preparing or sending. Other routes are unaffected.",
    "jurisdiction_unsupported": "Your saved current residence is outside this route's documented scope.",
    "dispatching": "Sending now. Pausing cannot recall a transmission already handed to your mail provider.",
    "transport_accepted": "Your mail provider accepted the message. Watch your own inbox for the broker's reply or verification request, and record what happens.",
    "not_sent": "Definitively not sent. Prepare and approve again if you want to retry.",
    "uncertain": "The outcome is uncertain. Check your Sent folder or the broker's replies and record what you found. Only a rejection from your mail provider proves it was not sent; a new request is possible only if you accept it may duplicate this one.",
    "user_confirmed_sent": "You confirmed the message was sent. Watch your inbox for the broker's reply.",
    "user_sent": "You sent this exact email yourself from your mail app. Watch your inbox for the broker's reply, and record what happens.",
    "user_reported_not_sent": "You reported it was not sent. Prepare and approve again if you want to retry.",
}


class Execution:
    def __init__(self, vault, cases, worker=None):
        self.vault, self.cases, self.worker = vault, cases, worker
        self.inflight, self.pending = set(), {}
        cases.execution = self
        self.gmail = None
        if worker is not None and worker.kind == "gmail":
            from .gmail import GmailConnector
            self.gmail = GmailConnector(vault, worker)

    def sender_state(self):
        """Caller holds the vault mutex with an authorized, unlocked vault."""
        worker = self.worker
        if worker is None:
            return {"configured": False, "kind": None, "simulated": False, "broker_sending": False, "account": None, "gmail": None}
        base = {"kind": worker.kind, "simulated": worker.simulated}
        if worker.kind != "gmail":
            return {**base, "configured": worker.available, "broker_sending": worker.available, "account": None, "gmail": None}
        gmail = self.gmail.state()
        # Real-provider broker sending is a later, separately authorized pilot; only self-tests here.
        return {**base, "configured": worker.available and gmail["connected"], "broker_sending": False,
                "account": gmail["account"], "gmail": gmail}

    def sender_binding(self):
        """(account, problem). An account-backed sender (Gmail) sends only as its connected address,
        so every email's From must be exactly that address; a saved email never stands in for it.
        The local fake provider has no account and binds nothing. Caller holds the vault mutex."""
        if self.gmail is None:
            return None, None
        account = self.gmail.state()["account"]
        if not account:
            return None, "Connect your sending account first; each email is sent from that address"
        return account, None

    def _authority(self):
        from .gmail import read
        record, _ = read(self.vault)
        if not record:
            raise RuleError("Connect your Gmail account first")
        return {key: record[key] for key in ("client_id", "client_secret", "refresh_token", "account_email")}

    def status(self, case, profile, timestamp):
        job = case.get("execution")
        if not job:
            item = contracts.for_broker(case["broker"])
            return "source_review_due" if item and not contracts.fresh(item, timestamp) else "not_prepared"
        if job["state"] == "dispatching" and job["id"] not in self.inflight:
            # A result that arrived while locked is shown as recorded; anything else is uncertain.
            return STATES[self.pending[job["id"]]["outcome"]] if job["id"] in self.pending else "uncertain"
        if job["state"] != "prepared":
            return job["state"]
        if job["revoked"]:
            return "revoked"
        try:
            item = contracts.contract(job["contract_id"])
            current = contracts.fingerprint(item, contracts.render(item, job["fields"]))
        except RuleError:
            return "invalidated"
        account, _ = self.sender_binding()
        if (job.get("sender_account") or "").casefold() != (account or "").casefold():
            return "invalidated"  # Disconnected, reconnected as someone else, or prepared for another sender.
        if (item["version"] != job["contract_version"] or current != job["fingerprint"] or
                profile["version"] != job["profile_version"] or
                external_context(self.vault, case["broker"])["fingerprint"] != job["external_context"]):
            return "invalidated"
        if not contracts.fresh(item, timestamp):
            return "source_review_due"
        if contracts.eligible(item, (profile["profile"] or {}).get("residence")):
            return "jurisdiction_unsupported"
        approval = job["approval"]
        if approval:
            if timestamp < approval["at_epoch"] or timestamp >= approval["expires_epoch"]:
                return "expired"
            return "approved"
        return "prepared"

    def view(self, case, profile, timestamp):
        status = self.status(case, profile, timestamp)
        if status == "source_review_due":
            job = case.get("execution")
            item = contracts.contract(job["contract_id"]) if job else contracts.for_broker(case["broker"])
            reason = contracts.freshness(item, timestamp)["reason"]
            return status, (reason + " Other routes are unaffected.") if reason else NEXT[status]
        return status, NEXT[status]

    # Helpers that run inside the caller's vault mutex and transaction.

    def _store(self, case):
        self.cases._save(case)
        case["version"] += 1

    def _event(self, case, kind, note, timestamp, provenance="local_action"):
        self.cases._event(case, kind, note, timestamp)
        case["history"][-1]["provenance"] = provenance

    def _apply(self, case, job, result, timestamp):
        from .cases import stamp
        job["state"] = STATES[result["outcome"]]
        job["result"] = {"outcome": result["outcome"], "reason": result["reason"], "at": stamp(timestamp),
                         "transport": self.worker.kind if self.worker else None,
                         "provider_message_id": result.get("provider_message_id")}
        note = {"transport_accepted": "Your mail provider accepted the message for delivery. This is not the broker's acknowledgment, verification or deletion.",
                "not_sent": "Definitively not sent (" + result["reason"] + "). Prepare and approve again to retry.",
                "uncertain": "Outcome uncertain (" + result["reason"] + "). Check your Sent folder; no automatic retry."}[job["state"]]
        self._event(case, "send_" + job["state"], note, timestamp, "transport_result")

    def _settle(self, cases, timestamp):
        """Persist results that arrived while locked; mark interrupted dispatches uncertain."""
        for case in cases:
            job = case.get("execution")
            if job and job["state"] == "dispatching" and job["id"] not in self.inflight:
                result = self.pending.pop(job["id"], None) or {"outcome": "uncertain", "reason": "interrupted_before_result"}
                self._apply(case, job, result, timestamp)
                self._store(case)

    def settle(self):
        """Commit pending results and interrupted dispatches in their own transaction, so a later
        refused command cannot roll them back. Requires an unlocked vault; the caller authorizes."""
        with self.vault.mutex:
            if self.vault.key is None or self.vault.needs_upgrade():
                return
            interrupted = any((c.get("execution") or {}).get("state") == "dispatching" and
                              c["execution"]["id"] not in self.inflight for c in self.cases._load())
            if not (self.pending or interrupted) or self.vault.db.in_transaction:
                return  # Nothing to record, or inside a caller's transaction: a later read settles it.
            with self.vault.db:
                self.vault.db.execute("BEGIN IMMEDIATE")
                self._settle(self.cases._load(), self.cases.clock())

    def _blocked(self, case, cases, duplicate_acknowledged=False):
        """Why another email to this broker must not be prepared or sent, or None. An uncertain
        earlier email is passed over only with the owner's explicit duplicate-risk acknowledgment;
        a sent or confirmed one always blocks."""
        if case.get("attempt"):
            return "A manual handoff for this case blocks sending; reconcile it first"
        if external_context(self.vault, case["broker"])["blocked"]:
            return "An external request recorded for this broker blocks sending; reconcile it first"
        for other in cases:
            if other["broker"] != case["broker"]:
                continue
            if other.get("attempt"):
                return "A manual handoff to this broker blocks sending; reconcile it first"
            job = other.get("execution")
            if job and job["state"] in ACTIVE:
                uncertain = job["state"] == "uncertain" or (job["state"] == "dispatching" and job["id"] not in self.inflight)
                if uncertain and duplicate_acknowledged:
                    continue
                if uncertain:
                    return ("An earlier email to this broker has an uncertain outcome. Record what you found, or accept "
                            "that a new request may duplicate it")
                return "An earlier sent or uncertain request to this broker blocks another; reconcile it first"
        return None

    def _locate(self, cases, identifier, version):
        case = next((c for c in cases if c["id"] == identifier), None)
        if not case or (version is not None and (type(version) is not int or version != case["version"])):
            raise RuleError("Case changed; reload before continuing")
        return case

    def command(self, session, identifier, version, action, data):
        from .cases import stamp, text
        if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise RuleError("Select an existing case")
        expected = SCHEMAS.get(action) if isinstance(action, str) else None
        if action == "prepare" and isinstance(data, dict):
            expected = expected | (set(data) & {"duplicate_acknowledged"})
        if expected is None or not isinstance(data, dict) or set(data) != expected:
            raise RuleError("Unsupported sending command fields")
        if action == "dispatch":
            return self.dispatch(session, identifier, version, data["fingerprint"])
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            from .recovery import require_reconciled
            if action in {"prepare", "approve", "self_sent"}:
                require_reconciled(self.vault)
            if self.vault.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before sending requests")
            self.settle()
            with self.vault.db:
                self.vault.db.execute("BEGIN IMMEDIATE")
                cases, timestamp = self.cases._load(), self.cases.clock()
                case = self._locate(cases, identifier, version)
                profile = self.vault._read()
                status = self.status(case, profile, timestamp)
                job = case.get("execution")
                if action == "prepare":
                    item = contracts.for_broker(case["broker"])
                    if not item or route(case["broker"])["readiness"] != "owner_email":
                        raise RuleError("This route has no reviewed sending contract")
                    identity = profile["profile"]
                    if not identity or identity.get("self_adult") is not True:
                        raise RuleError("Save your identity and adult self-service acknowledgment first")
                    if not contracts.fresh(item, timestamp):
                        raise RuleError("This route's official source needs review before preparing an email; other routes are unaffected")
                    reason = contracts.eligible(item, identity["residence"])
                    if reason:
                        raise RuleError(reason)
                    duplicate = data.get("duplicate_acknowledged") is True
                    blocked = self._blocked(case, cases, duplicate)
                    if blocked:
                        raise RuleError(blocked)
                    duplicate = duplicate and self._blocked(case, cases) is not None  # Recorded only when it mattered.
                    context = external_context(self.vault, case["broker"])
                    if context["drop_overlap"] and data["drop_acknowledged"] is not True:
                        raise RuleError("Review the possible overlap with your recorded DROP request before preparing a separate request")
                    account, problem = self.sender_binding()
                    if problem:
                        raise RuleError(problem)
                    fields, bindings, missing = mapping(identity, contracts.requirement(item, account))
                    if missing:
                        raise RuleError("; ".join(missing))
                    identifiers = selected_fields(identity, bindings, fields, item.get("email_use"))
                    message = contracts.render(item, fields)
                    if account and message["from"].casefold() != account.casefold():
                        raise RuleError("This email must be sent from your connected sending account")
                    if job:
                        case.setdefault("past_executions", []).append(job)
                    case["execution"] = {
                        "id": secrets.token_hex(16), "contract_id": item["id"], "contract_version": item["version"],
                        "contract": contracts.snapshot(item),  # History shows this, never a later revision.
                        "fields": fields, "identifiers": identifiers, "message": message,
                        "fingerprint": contracts.fingerprint(item, message), "profile_version": profile["version"],
                        "sender_account": account,
                        "external_context": context["fingerprint"], "drop_overlap_acknowledged": context["drop_overlap"],
                        "prepared_at": stamp(timestamp), "approval": None, "revoked": False, "state": "prepared",
                        "dispatched_at": None, "result": None, "duplicate_risk_acknowledged": duplicate}
                    if duplicate:
                        self._event(case, "send_duplicate_risk_acknowledged", "You accepted that this request may duplicate an "
                                    "earlier email to this broker whose outcome is uncertain.", timestamp, "user_reported")
                    self._event(case, "send_prepared", "Exact email prepared locally from My information; nothing sent.", timestamp)
                elif action == "approve":
                    if status not in {"prepared", "expired"}:
                        raise RuleError("Prepare a current email before approving it")
                    if data["acknowledged"] is not True or data["fingerprint"] != job["fingerprint"]:
                        raise RuleError("Review and approve this exact email first")
                    job["approval"] = {"at_epoch": timestamp, "expires_epoch": timestamp + APPROVAL_SECONDS,
                                       "fingerprint": job["fingerprint"], "at": stamp(timestamp),
                                       "expires_at": stamp(timestamp + APPROVAL_SECONDS)}
                    self._event(case, "send_approved", "One transmission of this exact email approved; expires in 24 hours.", timestamp)
                elif action == "self_sent":
                    # The owner's own report: Velum transmitted nothing and holds no email permission.
                    if status != "approved":
                        raise RuleError("Approve this exact email before you send it yourself")
                    if data["fingerprint"] != job["fingerprint"] or job["approval"]["fingerprint"] != job["fingerprint"]:
                        raise RuleError("Approval does not match this exact email")
                    if data["result"] not in SELF_SENT:
                        raise RuleError("Say whether you sent it, or aren't sure")
                    if paused(self.vault, identifier):
                        raise RuleError("This batch is paused; resume before sending")
                    blocked = self._blocked(case, cases, job.get("duplicate_risk_acknowledged") is True)
                    if blocked:
                        raise RuleError(blocked)
                    job["dispatched_at"] = stamp(timestamp)
                    if data["result"] == "sent":
                        job["state"] = "user_sent"
                        self._event(case, "send_user_sent", "You reported sending this exact email yourself from your "
                                    "mail app. Velum transmitted nothing.", timestamp, "user_reported")
                    else:
                        job["state"] = "uncertain"
                        job["result"] = {"outcome": "uncertain", "reason": "owner_unsure", "at": stamp(timestamp),
                                         "transport": "owner_mail_app", "provider_message_id": None}
                        self._event(case, "send_owner_unsure", "You opened this email in your mail app but aren't sure it "
                                    "was sent. It stays uncertain until you check your Sent folder.", timestamp, "user_reported")
                elif action == "revoke":
                    if status not in {"prepared", "approved", "expired"}:
                        raise RuleError("There is no unsent email to revoke")
                    job["revoked"], job["approval"] = True, None
                    self._event(case, "send_revoked", "Unsent email approval revoked locally.", timestamp)
                else:
                    if status != "uncertain" or data["result"] not in RECONCILE:
                        raise RuleError("Only an uncertain email can be reconciled: found in Sent, the broker replied, or not found")
                    note = text(data["note"])
                    if data["result"] == "not_found_in_sent":
                        # Not proof: only a provider rejection shows an email was not sent.
                        self._event(case, "send_not_found_in_sent", "Not found in your Sent folder; the outcome stays uncertain. " + note,
                                    timestamp, "user_reported")
                    else:
                        job["state"] = "user_confirmed_sent"
                        kind = "send_user_confirmed_sent" if data["result"] == "sent_found" else "send_confirmed_by_broker_reply"
                        self._event(case, kind, note, timestamp, "user_reported")
                self._store(case)
            return self.cases.state(session)

    def dispatch(self, session, identifier, version, fingerprint, single=True):
        """The only path that transmits. Reserve, then hand to the worker without holding the vault."""
        from .cases import stamp
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            from .recovery import require_reconciled
            require_reconciled(self.vault)
            if self.vault.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before sending requests")
            self.settle()
            with self.vault.db:
                self.vault.db.execute("BEGIN IMMEDIATE")
                cases, timestamp = self.cases._load(), self.cases.clock()
                case = self._locate(cases, identifier, version)
                profile = self.vault._read()
                if self.status(case, profile, timestamp) != "approved":
                    raise RuleError("A current, unused approval is required to send this email")
                job = case["execution"]
                if fingerprint != job["fingerprint"] or job["approval"]["fingerprint"] != job["fingerprint"]:
                    raise RuleError("Approval does not match this exact email")
                account, _ = self.sender_binding()
                if account and job["message"]["from"].casefold() != account.casefold():
                    raise RuleError("This email must be sent from your connected sending account; nothing was sent")
                if paused(self.vault, identifier):
                    raise RuleError("This batch is paused; resume before sending")
                blocked = self._blocked(case, cases, job.get("duplicate_risk_acknowledged") is True)
                if blocked:
                    raise RuleError(blocked)
                if not (self.worker and self.worker.available):
                    raise RuleError("No sender is configured; nothing was sent")
                if not self.sender_state()["broker_sending"]:
                    raise RuleError("Sending to brokers through a real mail provider is not enabled in this build; nothing was sent. Use the self-test instead.")
                job["state"], job["dispatched_at"] = "dispatching", stamp(timestamp)
                self._event(case, "send_dispatched", "Handed to the sending worker. Possible disclosure from this point; no automatic retry.", timestamp)
                self._store(case)
                envelope = {"job_id": job["id"], "contract_id": job["contract_id"],
                            "contract_version": job["contract_version"], "fields": job["fields"],
                            "fingerprint": job["fingerprint"]}
            self.inflight.add(job["id"])
        try:
            result = self.worker.send(envelope)
        except Exception:
            result = {"outcome": "uncertain", "reason": "client_error"}
        with self.vault.mutex:
            self.inflight.discard(job["id"])
            if self.vault.key is None:
                self.pending[job["id"]] = result  # Recorded by _settle at the next unlock.
            else:
                with self.vault.db:
                    self.vault.db.execute("BEGIN IMMEDIATE")
                    cases = self.cases._load()
                    case = next((c for c in cases if c["id"] == identifier), None)
                    current = case and case.get("execution")
                    if current and current["id"] == job["id"] and current["state"] == "dispatching":
                        self._apply(case, current, result, self.cases.clock())
                        self._store(case)
        summary = {"case_id": identifier, "outcome": result["outcome"], "reason": result["reason"]}
        if not single:
            return summary
        try:
            return {**self.cases.state(session), "send_result": summary}
        except RuleError:
            return {"send_result": summary, "locked": True}

    def test_send(self, session, acknowledged):
        """Send the fixed self-test message to the connected account itself. No broker, no case."""
        from . import contracts
        if acknowledged is not True:
            raise RuleError("Confirm the test message to your own address first")
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            from .recovery import require_reconciled
            require_reconciled(self.vault)
            if not self.gmail or not (self.worker and self.worker.available):
                raise RuleError("No Gmail sender is configured in this session")
            authority = self._authority()
            item = contracts.contract(contracts.SELF_TEST)
            fields = {"email": authority["account_email"]}
            envelope = {"job_id": secrets.token_hex(16), "contract_id": item["id"], "contract_version": item["version"],
                        "fields": fields, "fingerprint": contracts.fingerprint(item, contracts.render(item, fields)),
                        "authority": authority}
        try:
            result = self.worker.send(envelope)
        except Exception:
            result = {"outcome": "uncertain", "reason": "client_error"}
        self.gmail.record_test(result)
        summary = {"outcome": result["outcome"], "reason": result["reason"], "provider_message_id": result.get("provider_message_id")}
        try:
            return {**self.cases.state(session), "test_result": summary}
        except RuleError:
            return {"test_result": summary, "locked": True}

    def dispatch_batch(self, session, confirmed, limit=10):
        """Send each approved batch member the owner confirmed (by exact fingerprint) once, in order.
        Stops on pause or lock; one uncertain result does not stop unrelated cards. Capped per call."""
        results, tried = [], set()
        for _ in range(limit):
            with self.vault.mutex:
                try:
                    self.vault._authorize(session)
                except RuleError:
                    break
                body, _ = read_workflow(self.vault)
                if body["paused"]:
                    break
                profile, timestamp = self.vault._read(), self.cases.clock()
                ready = [c for c in self.cases._load() if c["id"] in body["case_ids"] and c["id"] not in tried
                         and self.status(c, profile, timestamp) == "approved"
                         and c["execution"]["fingerprint"] in confirmed]
                if not ready:
                    break
                case = ready[0]
            tried.add(case["id"])
            try:
                results.append(self.dispatch(session, case["id"], None, case["execution"]["fingerprint"], single=False))
            except RuleError as error:
                results.append({"case_id": case["id"], "outcome": "not_attempted", "reason": str(error)})
        return results
