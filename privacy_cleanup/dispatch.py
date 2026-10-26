"""UI-side client for the isolated sending worker.

The worker is spawned before the UI process installs its deny-by-default network hook, and the
two talk only over an inherited socketpair: never a loopback port, which other local accounts
could reach. Payloads travel only in frames; argv carries an fd number and a non-secret
transport spec, and the worker gets an empty environment and no stdio.
"""
import re
import socket
import subprocess
import sys
import threading
from pathlib import Path

from . import contracts
from .worker import JOB, PROVIDER_ID, SECRET, read_frame, write_frame

REPLY_TIMEOUT = 45.0  # Worker transport timeout plus margin.
OUTCOMES = {"accepted", "not_sent", "uncertain"}
REASON = re.compile(r"[a-z0-9_]{1,40}")


class WorkerClient:
    def __init__(self, sock, process=None, spec="fake"):
        self.sock, self.process = sock, process
        name = spec.split(":", 1)[0]
        self.kind = "gmail" if name.startswith("gmail") else name           # Protocol spoken.
        self.simulated = name != "gmail"                                    # Fake provider or fake Google.
        self.google_port = int(spec.rsplit(":", 1)[1]) if name == "gmail-local" else None
        self.lock = threading.Lock()
        self.broken = False

    @classmethod
    def spawn(cls, spec):
        parent, child = socket.socketpair()
        root = str(Path(__file__).resolve().parent.parent)
        code = ("import sys; sys.path.insert(0, sys.argv[1]); "
                "from privacy_cleanup.worker import main; main(int(sys.argv[2]), sys.argv[3])")
        try:
            process = subprocess.Popen([sys.executable, "-I", "-B", "-c", code, root, str(child.fileno()), spec],
                                       pass_fds=(child.fileno(),), env={}, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
        finally:
            child.close()
        return cls(parent, process, spec)

    @property
    def available(self):
        return not self.broken and (self.process is None or self.process.poll() is None)

    def send(self, envelope, timeout=REPLY_TIMEOUT):
        """Exactly one of accepted / not_sent / uncertain. Never raises for transport problems."""
        with self.lock:
            if not self.available:
                return {"outcome": "not_sent", "reason": "worker_unavailable"}
            self.sock.settimeout(timeout)
            try:
                write_frame(self.sock, {"type": "send", "envelope": envelope})
            except (OSError, ValueError):
                # The worker acts only on a complete frame, so nothing can have been sent.
                self.broken = True
                return {"outcome": "not_sent", "reason": "worker_unavailable"}
            try:
                reply = read_frame(self.sock)
            except (OSError, ValueError):
                # The worker may be mid-transmission. Stop using it; restart the app to recover.
                self.broken = True
                return {"outcome": "uncertain", "reason": "worker_unresponsive"}
            return self._checked(reply, envelope)

    def _call(self, request, timeout):
        with self.lock:
            if not self.available:
                return None
            self.sock.settimeout(timeout)
            try:
                write_frame(self.sock, request)
                return read_frame(self.sock)
            except (OSError, ValueError):
                self.broken = True
                return None

    def connect(self, request, timeout=REPLY_TIMEOUT):
        """Exchange an OAuth authorization code in the worker (the UI process's guard refuses outbound connections)."""
        reply = self._call({"type": "connect", **request}, timeout)
        if not reply or reply.get("type") != "connect" or reply.get("outcome") not in {"connected", "failed"}:
            return {"outcome": "failed", "reason": "worker_unavailable"}
        reason = reply.get("reason")
        if not isinstance(reason, str) or not REASON.fullmatch(reason):
            return {"outcome": "failed", "reason": "worker_malformed"}
        if reply["outcome"] == "failed":
            return {"outcome": "failed", "reason": reason}
        refresh, account = reply.get("refresh_token"), reply.get("account_email")
        if (not isinstance(refresh, str) or not SECRET.fullmatch(refresh) or not isinstance(account, str)
                or len(account) > 254 or not contracts.EMAIL.fullmatch(account)):
            return {"outcome": "failed", "reason": "worker_malformed"}
        return {"outcome": "connected", "refresh_token": refresh, "account_email": account}

    def revoke(self, token, timeout=REPLY_TIMEOUT):
        reply = self._call({"type": "revoke", "token": token}, timeout)
        return bool(reply and reply.get("type") == "revoke" and reply.get("outcome") == "revoked")

    def _checked(self, reply, envelope):
        if reply.get("job_id") != envelope["job_id"] or not JOB.fullmatch(envelope["job_id"]):
            self.broken = True
            return {"outcome": "uncertain", "reason": "worker_mismatch"}
        outcome, reason = reply.get("outcome"), reply.get("reason")
        if outcome not in OUTCOMES or not isinstance(reason, str) or not REASON.fullmatch(reason):
            return {"outcome": "uncertain", "reason": "worker_malformed"}
        result = {"outcome": outcome, "reason": reason}
        if outcome == "accepted":
            provider_id = reply.get("provider_message_id")
            if (reply.get("fingerprint") != envelope["fingerprint"] or not isinstance(provider_id, str)
                    or not PROVIDER_ID.fullmatch(provider_id)):
                return {"outcome": "uncertain", "reason": "worker_malformed"}
            result["provider_message_id"] = provider_id
        return result

    def close(self):
        try:
            self.sock.close()
        finally:
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
