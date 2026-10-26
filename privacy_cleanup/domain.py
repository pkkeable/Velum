"""Shared local domain rules. This module performs no I/O."""
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class RuleError(ValueError):
    """Only fixed, non-identifying messages may cross the UI boundary."""


class Mode(str, Enum):
    DEMO = "mock-only"
    PRIVATE = "private-local"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def validate_preview(request, expected):
    if request["snapshot"] != expected or request["fingerprint"] != digest(expected):
        raise RuleError("Request or broker metadata changed; prepare a fresh preview and approval")


def validate_approval(request, fingerprint):
    approval = request.get("approval")
    if request["status"] != "approved" or not approval or fingerprint != request["fingerprint"]:
        raise RuleError("Specific request approval is required before execution")
    if approval["fingerprint"] != digest(request["snapshot"]) or approval["revision"] != request["revision"]:
        raise RuleError("Approval no longer matches the request")


PROFILE_LIMITS = {"full_name": 120, "email": 254, "city": 120,
                  "region": 120, "postal_code": 32, "country": 2}


@dataclass(frozen=True)
class Profile:
    fields: dict = field(repr=False)

    @classmethod
    def parse(cls, values):
        if not isinstance(values, dict) or set(values) - set(PROFILE_LIMITS):
            raise RuleError("Use only the supported profile fields")
        result = {}
        for key, limit in PROFILE_LIMITS.items():
            value = values.get(key, "")
            if not isinstance(value, str) or len(value) > limit or any(not c.isprintable() for c in value):
                raise RuleError("A profile field is too long or contains unsupported characters")
            result[key] = value.strip()
        if not result["full_name"]:
            raise RuleError("A name is required to save a profile")
        email = result["email"]
        if email and (email.count("@") != 1 or any(c.isspace() for c in email) or
                      not all(email.split("@")) or "." not in email.split("@")[1]):
            raise RuleError("Check the email address format")
        country = result["country"]
        if country and (len(country) != 2 or not country.isascii() or not country.isalpha()):
            raise RuleError("Country must be a two-letter code")
        result["country"] = country.upper()
        return cls(result)
