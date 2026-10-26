"""Versioned single-adult identity records; no I/O or inferred name parts."""
import copy
import re
import secrets
from datetime import date

from .contracts import state_name
from .domain import Profile, RuleError

GROUPS = {
    "names": {"full_name": 120, "first_name": 120, "last_name": 120},
    "emails": {"value": 254},
    "addresses": {"street_address": 240, "address_line2": 240, "city": 120,
                  "region": 120, "postal_code": 32, "country": 2, "from_date": 10, "to_date": 10},
    "phones": {"value": 64, "country": 2},
}
LABELS = {"names": {"current", "former", "alias"}, "emails": {"current", "former"},
          "addresses": {"current", "past"}, "phones": {"current", "former"}}
COMMON = {"id", "label", "preferred", "retired"}
MAX_IDENTIFIERS = 10
SCHEMA = 2  # 2 adds how each email is used; 1 is read only to upgrade it.
EMAIL_USES = {"professional", "personal", "unknown"}  # Chosen by the owner; never inferred from a domain.


def clean(value, limit):
    if not isinstance(value, str) or len(value) > limit or any(not c.isprintable() for c in value):
        raise RuleError("An identity field is too long or contains unsupported characters")
    return value.strip()


def country(value):
    value = clean(value, 2)
    if value and (len(value) != 2 or not value.isascii() or not value.isalpha()):
        raise RuleError("Country must be a two-letter code")
    return value.upper()


def day(value):
    value = clean(value, 10)
    if value:
        try:
            if date.fromisoformat(value).isoformat() != value:
                raise ValueError()
        except ValueError:
            raise RuleError("Use a valid YYYY-MM-DD date") from None
    return value


def empty():
    return {"schema": SCHEMA, **{group: [] for group in GROUPS}, "birth_date": "",
            "residence": {"country": "", "region": ""}, "self_adult": False}


def entry(group, **values):
    result = {"id": secrets.token_hex(16), "label": "current", "preferred": False, "retired": False,
              **{key: "" for key in GROUPS[group]}}
    if group in {"emails", "phones"}:
        result["reachable"] = False
    if group == "emails":
        result["use"] = "unknown"
    result.update(values)
    return result


def from_legacy(values):
    values = Profile.parse(values).fields
    result = empty()
    result["names"] = [entry("names", full_name=values["full_name"], preferred=True)]
    if values["email"]:
        result["emails"] = [entry("emails", value=values["email"], preferred=True)]
    if any(values[key] for key in ("city", "region", "postal_code", "country")):
        result["addresses"] = [entry("addresses", **{key: values[key] for key in ("city", "region", "postal_code", "country")}, preferred=True)]
    result["residence"] = {key: values[key] for key in ("country", "region")}
    # Neither name parts, reachability, email use nor the adult acknowledgment is inferred.
    return result


def upgrade(values):
    """A schema 1 record as schema 2: every email's use starts unknown, whatever its domain.

    A record already at schema 2 is only validated. Nothing else changes."""
    if isinstance(values, dict) and values.get("schema") == 1:
        values = copy.deepcopy(values)
        for row in values.get("emails", []) if isinstance(values.get("emails"), list) else []:
            if isinstance(row, dict) and "use" not in row:
                row["use"] = "unknown"
        values["schema"] = SCHEMA
    return validate(values)


def validate(values, previous=None):
    if not isinstance(values, dict) or set(values) != set(empty()) or type(values["schema"]) is not int or values["schema"] != SCHEMA:
        raise RuleError("Use the supported identity record format")
    result = copy.deepcopy(values)
    if type(result["self_adult"]) is not bool:
        raise RuleError("Review the adult self-service acknowledgment")
    if not isinstance(result["residence"], dict) or set(result["residence"]) != {"country", "region"}:
        raise RuleError("Review your current residence separately from historical addresses")
    result["residence"] = {"country": country(result["residence"]["country"]), "region": clean(result["residence"]["region"], 120)}
    result["birth_date"] = day(result["birth_date"])
    if result["birth_date"]:
        born, today = date.fromisoformat(result["birth_date"]), date.today()
        age = today.year - born.year - ((today.month, today.day) < (born.month, born.day))
        if not 18 <= age <= 120:
            raise RuleError("Optional birth date must identify an adult")
    seen = set()
    for group, limits in GROUPS.items():
        rows = result[group]
        if not isinstance(rows, list) or len(rows) > MAX_IDENTIFIERS:
            raise RuleError("Keep at most ten entries in each identity category, including retired entries")
        preferred = 0
        for row in rows:
            expected = (COMMON | set(limits) | ({"reachable"} if group in {"emails", "phones"} else set())
                        | ({"use"} if group == "emails" else set()))
            if not isinstance(row, dict) or set(row) != expected:
                raise RuleError("Use only supported identity entry fields")
            identifier = row["id"]
            if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier) or identifier in seen:
                raise RuleError("Identity entries need distinct stable identifiers")
            seen.add(identifier)
            if not isinstance(row["label"], str) or row["label"] not in LABELS[group] or any(type(row[key]) is not bool for key in expected & {"preferred", "retired", "reachable"}):
                raise RuleError("Check identity labels and selection flags")
            if row["preferred"] and (row["retired"] or row["label"] != "current"):
                raise RuleError("A preferred identifier must be current and not retired")
            preferred += row["preferred"]
            for key, limit in limits.items():
                row[key] = clean(row[key], limit)
            if group == "names" and not row["full_name"]:
                raise RuleError("Each name entry needs a display name; name parts are optional")
            if group == "emails":
                if not isinstance(row["use"], str) or row["use"] not in EMAIL_USES:
                    raise RuleError("Choose professional, personal or not sure for each email")
                value = row["value"]
                if value.count("@") != 1 or any(c.isspace() for c in value) or not all(value.split("@")) or "." not in value.split("@")[1]:
                    raise RuleError("Check an email address format")
            if group in {"addresses", "phones"}:
                row["country"] = country(row["country"])
            if group == "addresses":
                if not any(row[key] for key in limits if key not in {"from_date", "to_date"}):
                    raise RuleError("Add at least one address detail")
                for key in ("from_date", "to_date"):
                    row[key] = day(row[key])
                if row["from_date"] and row["to_date"] and row["from_date"] > row["to_date"]:
                    raise RuleError("Address start date must not follow its end date")
                if row["label"] == "current" and row["to_date"]:
                    raise RuleError("An address with an end date must be labeled past")
            if group == "phones":
                value = row["value"]
                digits = re.sub(r"[^0-9]", "", value)
                if not re.fullmatch(r"\+?[0-9 ()\.\-]+", value) or not 5 <= len(digits) <= 15 or not row["country"]:
                    raise RuleError("Use a phone number with a two-letter country context; no extensions")
        if preferred > 1:
            raise RuleError("Choose at most one preferred identifier per category")
        if previous:
            old_ids = {row["id"] for row in previous[group]}
            if not old_ids <= {row["id"] for row in rows}:
                raise RuleError("Retire saved identifiers instead of deleting or moving them; history is preserved")
    if not any(not row["retired"] for row in result["names"]):
        raise RuleError("Keep at least one active name")
    return result


def warnings(profile):
    result = []
    for group in GROUPS:
        seen = set()
        for row in profile[group]:
            if row["retired"]:
                continue
            if group == "names":
                value = row["full_name"].casefold()
            elif group == "phones":
                value = (row["country"], row["value"].startswith("+"), re.sub(r"[^0-9]", "", row["value"]))
            elif group == "addresses":
                value = tuple(row[key].casefold() for key in GROUPS[group] if key not in {"from_date", "to_date"})
            else:
                value = row["value"].casefold()
            if value in seen:
                result.append("Possible duplicate in " + group + "; entries were kept separately.")
                break
            seen.add(value)
    return result


BINDINGS = {"full_name": ("names", "full_name"), "first_name": ("names", "first_name"), "last_name": ("names", "last_name"),
            "email": ("emails", "value"), **{key: ("addresses", key) for key in ("street_address", "city", "region", "postal_code")}}


def selected_fields(profile, bindings, fields, email_use=None):
    """Check each chosen source against exactly the value in the reviewed draft.

    A route that needs a particular email use (Hunter: professional) passes it here."""
    if not isinstance(bindings, dict) or set(bindings) - (set(BINDINGS) | {"birth_date", "us_state"}):
        raise RuleError("Unsupported selected identifier field")
    for key, identifier in bindings.items():
        if key == "birth_date":
            if identifier != "profile_birth_date" or not profile["birth_date"]:
                raise RuleError("Select an available birth date")
            value = profile["birth_date"]
        elif key == "us_state":
            # The saved current residence, never a historical address.
            if identifier != "profile_residence":
                raise RuleError("Use your saved current residence")
            value = state_name(profile["residence"])
        else:
            group, source = BINDINGS[key]
            row = next((r for r in profile[group] if r["id"] == identifier and not r["retired"]), None)
            if not row:
                raise RuleError("A selected identifier is unavailable; choose again")
            if group == "emails" and not row["reachable"]:
                raise RuleError("Choose an email you can receive verification messages at")
            if group == "emails" and email_use and row["use"] != email_use:
                raise RuleError("This route needs an email you marked as " + email_use)
            value = row[source]
        if not value or fields.get(key) != value:
            raise RuleError("Selected identifier values changed; review the draft again")
    return copy.deepcopy(bindings)
