"""Deterministic mock adapters and an explicit, transactional review workflow."""
import copy
from .domain import RuleError, Mode, now, digest, validate_preview, validate_approval
from .adapters import mock

ROOT = mock.ROOT
catalog = mock.catalog


def new_state():
    return {"schema": 1, "mode": "mock-only", "loaded": False, "identity": None,
            "candidates": [], "events": [], "version": 0}


def event(state, cid, kind, detail):
    state["events"].append({"id": len(state["events"]) + 1, "at": now(),
                            "candidate_id": cid, "kind": kind, "detail": detail,
                            "provenance": "local synthetic simulation"})


def request_snapshot(state, candidate, variant="standard"):
    return mock.prepare(state, candidate, variant, catalog())


def validate_request(state, candidate):
    request = candidate.get("request")
    if not request:
        raise RuleError("Prepare and review a request first")
    if candidate["decision"] != "confirmed":
        raise RuleError("Confirm the match first; confirmation is not submission approval")
    expected = request_snapshot(state, candidate, request["snapshot"]["variant"])
    validate_preview(request, expected)
    return request


def next_step(c):
    if c["decision"] == "pending":
        return "Compare the evidence, then confirm or reject. Missing details stay unknown."
    if c["decision"] == "rejected":
        return "Excluded from removal. Reopen only if new evidence warrants review."
    r = c.get("request")
    if not r:
        return "Prepare a request to inspect its destination and exact disclosure."
    if r["status"] in {"prepared", "approved"}:
        return "Review and approve this exact preview." if r["status"] == "prepared" else "Simulate once, or revise to invalidate approval."
    if r["status"] in {"uncertain", "manual_required"}:
        return "Manual handoff: reconcile the outcome with the broker before considering a new request. Do not retry."
    if c["verification"] == "pending":
        return "Simulate the user completing verification directly with the broker. No credentials or documents are collected."
    if c["checks"]:
        outcome = c["checks"][-1]["result"]
        if outcome == "absent":
            return "Absent in this dated mock check only. Reappearance remains possible; nothing is scheduled."
        if outcome == "present":
            return "Listing remains visible in the mock check. Review the response and follow up manually."
        return "Current visibility is UNKNOWN. A blocked, failed or ambiguous check cannot establish removal."
    if c["response"] == "broker_reports_deletion":
        return "The mock broker reports deletion; separately check whether the listing is absent."
    if c["response"] == "declined":
        return "Review the mock refusal. A manual follow-up is required; no automatic retry."
    return "Await a response or simulate one, then run a separate mock visibility check."


def view(state):
    result = copy.deepcopy(state)
    result["brokers"] = catalog()
    for c in result["candidates"]:
        c["next_step"] = next_step(c)
        c["current_visibility"] = c["checks"][-1]["conclusion"] if c["checks"] else "unknown"
        c["latest_check_at"] = c["checks"][-1]["at"] if c["checks"] else None
    return result


def apply(state, action, cid=None, value=None, fingerprint=None):
    """Called under Store's BEGIN IMMEDIATE transaction. No caller-provided PII."""
    if state["mode"] != Mode.DEMO.value:
        raise RuleError("Live mode does not exist")
    if action == "load_demo":
        if state["loaded"]:
            raise RuleError("Demo already loaded; existing attempt records must be preserved")
        fixture = mock.fixture("demo.json")
        if fixture.get("synthetic") is not True:
            raise RuleError("Only bundled synthetic fixtures are allowed")
        state["identity"] = fixture["identity"]
        state["loaded"] = True
        for item in fixture["candidates"]:
            item.update(decision="pending", request=None, verification="not_requested",
                        response="none", checks=[], found_at=now(), attempt_count=0)
            state["candidates"].append(item)
            event(state, item["id"], "candidate_found", "Authored fixture loaded; no search performed")
        return
    c = next((item for item in state["candidates"] if item["id"] == cid), None)
    if c is None:
        raise RuleError("Unknown candidate")
    if action == "decide":
        if value not in {"confirmed", "rejected", "pending"}:
            raise RuleError("Choose confirmed, rejected or pending")
        if c["attempt_count"]:
            raise RuleError("A submission attempt is already recorded; preserve history and reconcile manually")
        c["decision"] = value
        c["request"] = None
        event(state, cid, "match_" + value, "Human review recorded; any earlier request approval invalidated")
    elif action == "prepare":
        if c["decision"] != "confirmed" or c["attempt_count"]:
            raise RuleError("Preparation requires a confirmed match with no previous attempt")
        snapshot = request_snapshot(state, c, value or "standard")
        previous = c.get("request")
        revision = (previous["revision"] + 1) if previous else 1
        c["request"] = {"snapshot": snapshot, "fingerprint": digest(snapshot),
                        "revision": revision, "approval": None, "status": "prepared",
                        "prepared_at": now(), "submitted_at": None}
        event(state, cid, "request_prepared", {"revision": revision, "snapshot": snapshot,
                                              "fingerprint": digest(snapshot), "approval_invalidated": True})
    elif action == "approve":
        r = validate_request(state, c)
        if r["status"] != "prepared" or fingerprint != r["fingerprint"]:
            raise RuleError("Approve only the currently displayed, prepared request")
        r["approval"] = {"at": now(), "fingerprint": fingerprint, "revision": r["revision"]}
        r["status"] = "approved"
        event(state, cid, "request_approved", copy.deepcopy(r["approval"]))
    elif action == "submit":
        r = validate_request(state, c)
        if c["attempt_count"]:
            raise RuleError("Duplicate prevented: an attempt exists, including uncertain outcomes")
        if any(other["attempt_count"] and other["broker"] == c["broker"]
               and other["listing_url"] == c["listing_url"] for other in state["candidates"]):
            raise RuleError("Duplicate prevented: another candidate already attempted this exact broker record")
        validate_approval(r, fingerprint)
        result = mock.outcome(c["broker"], value)
        c["attempt_count"] = 1
        r["status"] = {"accepted": "submitted", "uncertain": "uncertain", "manual": "manual_required"}[result]
        r["attempted_at"] = now()
        if result == "accepted":
            r["submitted_at"] = now()
            c["verification"] = "pending"
            event(state, cid, "submitted", "SIMULATED receipt only; no network transmission")
            event(state, cid, "verification_handoff", "User would handle broker verification directly; collect no challenge data")
        else:
            event(state, cid, "submission_" + r["status"], "SIMULATED outcome; no successful submission claimed; automatic retry prohibited")
    elif action == "verify":
        r = validate_request(state, c)
        if r["status"] != "submitted" or c["verification"] != "pending":
            raise RuleError("No pending verification handoff")
        c["verification"] = "completed"
        event(state, cid, "verification_completed", "Fictional user handoff completed; not identity verification by this tool")
    elif action == "response":
        r = validate_request(state, c)
        if r["status"] != "submitted" or c["verification"] != "completed":
            raise RuleError("Complete the simulated submission and verification handoff first")
        if value not in {"broker_reports_deletion", "declined"} or c["response"] != "none":
            raise RuleError("Select one valid mock broker response")
        c["response"] = value
        event(state, cid, value, "SIMULATED broker statement; not an independent observation")
    elif action == "check":
        if not c["attempt_count"]:
            raise RuleError("This demo checks visibility only after a submission attempt")
        if value not in {"absent", "present", "blocked", "failed", "ambiguous"}:
            raise RuleError("Unknown mock check result")
        check = {"at": now(), "result": value,
                 "conclusion": value if value in {"absent", "present"} else "unknown",
                 "scope": c["listing_url"], "provenance": "authored mock result, not fetched",
                 "detail": "One synthetic listing at one time; no claim of permanent internet erasure"}
        c["checks"].append(check)
        event(state, cid, "listing_check", copy.deepcopy(check))
    else:
        raise RuleError("Unsupported action; real identities, live operations and bulk actions are disabled")
