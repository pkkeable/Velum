"""Private runtime storage, never inside a Git checkout."""
import json
import os
import sqlite3
import stat
import sys
from contextlib import contextmanager
from pathlib import Path

from .engine import ROOT, RuleError, apply, new_state, view
from .paths import validate_directory


def default_directory():
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support/PrivacyCleanupMock"
    return Path.home() / ".local/share/privacy-cleanup-mock"




class Store:
    def __init__(self, directory):
        self.directory = validate_directory(directory)
        if (self.directory / "vault.sqlite3").exists() or (self.directory / ".vault.lock").exists():
            raise RuleError("Private vaults cannot be opened by the demo")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = self.directory / "state.sqlite3"
        # Fail closed on unexpected files rather than changing their permissions.
        for p in self.directory.iterdir():
            if p.is_symlink() or not p.is_file() or p.stat().st_nlink != 1 or p.stat().st_uid != os.getuid():
                raise RuleError("Unexpected object in private data directory")
            if stat.S_IMODE(p.stat().st_mode) & 0o077:
                raise RuleError("Private files must have mode 0600")
        fd = os.open(str(self.path), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self.connect() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS runtime (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)")
            conn.execute("INSERT OR IGNORE INTO runtime VALUES (1, ?)", (json.dumps(new_state()),))

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(str(self.path), timeout=5)
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def read(self):
        with self.connect() as conn:
            state = json.loads(conn.execute("SELECT body FROM runtime WHERE id=1").fetchone()[0])
        return view(state)

    def act(self, payload):
        if not isinstance(payload, dict) or set(payload) - {"action", "candidate_id", "value", "fingerprint", "expected_version"}:
            raise RuleError("Only fixed demo commands are accepted; identity and free-text inputs are disabled")
        for key in ("action", "candidate_id", "value", "fingerprint"):
            if key in payload and (not isinstance(payload[key], str) or len(payload[key]) > 100):
                raise RuleError("Invalid command field")
        if type(payload.get("expected_version")) is not int:
            raise RuleError("Refresh the review before acting")
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            state = json.loads(conn.execute("SELECT body FROM runtime WHERE id=1").fetchone()[0])
            if payload["expected_version"] != state["version"]:
                raise RuleError("Review changed in another tab; refresh before acting")
            apply(state, payload.get("action"), payload.get("candidate_id"), payload.get("value"), payload.get("fingerprint"))
            state["version"] += 1
            conn.execute("UPDATE runtime SET body=? WHERE id=1", (json.dumps(state),))
        return view(state)
