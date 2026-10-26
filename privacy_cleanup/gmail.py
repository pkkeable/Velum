"""Connect the owner's own Gmail account with send-only permission.

Installed-app OAuth: PKCE (S256), a random state value and a one-shot redirect listener on a
random 127.0.0.1 port. The UI process never touches the network itself; the authorization-code
exchange and token revocation run in the sending worker. The refresh token, the owner's own
OAuth client and the verified account email are stored only inside the encrypted vault record
`sender`. Scopes: openid, email and gmail.send (send-only; no mailbox reading).
"""
import base64
import hashlib
import hmac
import re
import secrets
import socketserver
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from .domain import RuleError

RECORD = "sender"
SCOPE = "openid email https://www.googleapis.com/auth/gmail.send"
AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
CLIENT_ID = re.compile(r"[0-9]{6,32}-[0-9a-z]{16,64}\.apps\.googleusercontent\.com")
CLIENT_SECRET = re.compile(r"[A-Za-z0-9_-]{8,128}")
WAIT_SECONDS = 600
FIELDS = {"schema", "kind", "client_id", "client_secret", "refresh_token", "account_email", "scope",
          "connected_at", "last_test"}
PAGE = (b"<!doctype html><html lang=en><meta charset=utf-8><title>Velum</title>"
        b"<p>Velum received Google's answer. You can close this tab and return to Velum.</p></html>")


def read(vault):
    """The stored connection, or None. Caller holds the vault mutex with an unlocked vault."""
    if not vault.db.execute("SELECT 1 FROM records WHERE id=?", (RECORD,)).fetchone():
        return None, 0
    body, revision = vault._read_record(RECORD)
    if set(body) != FIELDS or body["schema"] != 1 or body["kind"] != "gmail":
        raise RuleError("Unsupported sender record; use the matching application")
    return body, revision


def _b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


class CallbackServer(HTTPServer):
    def __init__(self, connector):
        self.connector = connector
        super().__init__(("127.0.0.1", 0), CallbackHandler)

    def server_bind(self):
        # Skip HTTPServer's getfqdn(): the UI process denies DNS.
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.socket.getsockname()[1]


class CallbackHandler(BaseHTTPRequestHandler):
    sys_version = server_version = ""

    def log_message(self, *args):
        pass  # Never log the code or state.

    def reply(self, status, body):
        self.send_response(status)
        for key, value in (("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body))),
                           ("Cache-Control", "no-store"), ("Referrer-Policy", "no-referrer"),
                           ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
                           ("X-Content-Type-Options", "nosniff")):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.headers.get("Host") != "127.0.0.1:%d" % self.server.server_port:
            return self.reply(403, b"Use the exact loopback address.")
        parts = urlsplit(self.path)
        if parts.path != "/":
            return self.reply(404, b"Not found.")
        try:
            query = {k: v[0] for k, v in parse_qs(parts.query, max_num_fields=12).items() if len(v) == 1}
        except ValueError:
            query = {}
        if not self.server.connector.callback(query):
            return self.reply(400, b"This is not the pending Velum request.")
        self.reply(200, PAGE)
        self.server.connector.close_listener(self.server)


class GmailConnector:
    def __init__(self, vault, worker, clock=time.time):
        self.vault, self.worker, self.clock = vault, worker, clock
        self.authorize = ("http://127.0.0.1:%d/o/oauth2/v2/auth" % worker.google_port) if worker.google_port else AUTHORIZE
        self.lock = threading.Lock()
        self.pending = self.listener = None
        self.generation = 0
        self.flow = {"state": "idle", "reason": None}

    def state(self):
        """Caller holds the vault mutex with an authorized, unlocked vault."""
        record, _ = read(self.vault)
        return {"connected": bool(record), "account": record["account_email"] if record else None,
                "connected_at": record["connected_at"] if record else None,
                "last_test": record["last_test"] if record else None, "flow": dict(self.flow),
                "simulated": self.worker.simulated}

    def start(self, session, client_id, client_secret):
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            if self.vault.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before connecting a sender")
            if read(self.vault)[0]:
                raise RuleError("A Gmail account is already connected; disconnect it first")
        if not isinstance(client_id, str) or not CLIENT_ID.fullmatch(client_id.strip()):
            raise RuleError("Paste the Client ID of your own Google OAuth 'Desktop app' client")
        if not isinstance(client_secret, str) or not CLIENT_SECRET.fullmatch(client_secret.strip()):
            raise RuleError("Paste that Desktop app client's secret")
        self.close_listener()
        with self.lock:
            listener = CallbackServer(self)
            verifier = secrets.token_urlsafe(64)
            state = secrets.token_urlsafe(32)
            redirect = "http://127.0.0.1:%d" % listener.server_port
            self.pending = {"session": session, "generation": self.generation, "state": state, "verifier": verifier, "redirect_uri": redirect, "client_id": client_id.strip(),
                            "client_secret": client_secret.strip(), "expires": self.clock() + WAIT_SECONDS}
            self.listener, self.flow = listener, {"state": "waiting", "reason": None}
        threading.Thread(target=listener.serve_forever, daemon=True).start()
        timer = threading.Timer(WAIT_SECONDS, self._expire, args=(listener,))
        timer.daemon = True
        timer.start()
        query = {"client_id": client_id.strip(), "redirect_uri": redirect, "response_type": "code", "scope": SCOPE,
                 "code_challenge": _b64url(hashlib.sha256(verifier.encode()).digest()),
                 "code_challenge_method": "S256", "state": state, "access_type": "offline", "prompt": "consent"}
        return {"authorize_url": self.authorize + "?" + urlencode(query)}

    def _expire(self, listener):
        with self.lock:
            if self.listener is listener and self.pending:
                self.pending, self.flow = None, {"state": "failed", "reason": "timed_out"}
        if self.listener is listener:
            self.close_listener(listener)

    def close_listener(self, expected=None):
        # Never wait for a callback while holding the vault mutex: the callback
        # may itself need that mutex to reject/revoke a late exchange result.
        with self.lock:
            if expected is not None and self.listener is not expected:
                return
            listener, self.listener = self.listener, None
            self.pending = None
            self.generation += 1
        if listener:
            def stop():
                listener.shutdown()
                listener.server_close()
            threading.Thread(target=stop, daemon=True).start()

    def callback(self, query):
        """One-shot: only a request carrying the pending state value is handled; anything else is ignored."""
        with self.lock:
            pending = self.pending
            state = query.get("state")
            if (not pending or self.clock() > pending["expires"] or not isinstance(state, str)
                    or not hmac.compare_digest(state.encode(), pending["state"].encode())):
                return False
            self.pending = None
            if "code" not in query or "error" in query:
                self.flow = {"state": "failed", "reason": "consent_declined"}
                return True
            self.flow = {"state": "exchanging", "reason": None}
        result = self.worker.connect({"code": query["code"], "code_verifier": pending["verifier"],
                                      "redirect_uri": pending["redirect_uri"], "client_id": pending["client_id"],
                                      "client_secret": pending["client_secret"]})
        if result["outcome"] != "connected":
            with self.lock:
                if pending["generation"] == self.generation:
                    self.flow = {"state": "failed", "reason": result["reason"]}
            return True
        from .cases import stamp
        with self.vault.mutex:
            self.vault.expire()
            if (not self.vault._session_matches(pending["session"])
                    or pending["generation"] != self.generation or self.vault.needs_upgrade()):
                stored = False
            else:
                with self.vault.db:
                    self.vault.db.execute("BEGIN IMMEDIATE")
                    if read(self.vault)[0]:
                        stored = None
                    else:
                        self.vault._write_record(RECORD, {
                            "schema": 1, "kind": "gmail", "client_id": pending["client_id"],
                            "client_secret": pending["client_secret"], "refresh_token": result["refresh_token"],
                            "account_email": result["account_email"], "scope": SCOPE,
                            "connected_at": stamp(self.clock()), "last_test": None}, 1)
                        stored = True
        if not stored:
            # Locked meanwhile or already connected: never keep an unstored grant alive.
            self.worker.revoke(result["refresh_token"])
        with self.lock:
            if pending["generation"] == self.generation:
                self.flow = ({"state": "connected", "reason": None} if stored else
                             {"state": "failed", "reason": "vault_locked" if stored is False else "already_connected"})
        return True

    def disconnect(self, session):
        """Remove the local grant, then ask Google to revoke it (best effort)."""
        with self.vault.mutex:
            self.vault._authorize(session, touch=True)
            record, _ = read(self.vault)
            if not record:
                raise RuleError("No Gmail account is connected")
            with self.vault.db:
                self.vault.db.execute("DELETE FROM records WHERE id=?", (RECORD,))
            self.flow = {"state": "idle", "reason": None}
        return self.worker.revoke(record["refresh_token"])

    def release(self):
        """Remove the local grant and ask Google to revoke it, without a page session: used when
        a session-only workspace ends by idle expiry. None when nothing was connected."""
        self.close_listener()
        with self.lock:
            self.flow = {"state": "idle", "reason": None}
        with self.vault.mutex:
            if self.vault.key is None:
                return None
            record, _ = read(self.vault)
            if not record:
                return None
            with self.vault.db:
                self.vault.db.execute("DELETE FROM records WHERE id=?", (RECORD,))
            self.flow = {"state": "idle", "reason": None}
        return self.worker.revoke(record["refresh_token"])

    def connected(self):
        with self.vault.mutex:
            return self.vault.key is not None and bool(read(self.vault)[0])

    def record_test(self, result):
        """Remember the latest self-test outcome without any message content."""
        from .cases import stamp
        with self.vault.mutex:
            if self.vault.key is None:
                return
            with self.vault.db:
                self.vault.db.execute("BEGIN IMMEDIATE")
                record, revision = read(self.vault)
                if record:
                    record["last_test"] = {"at": stamp(self.clock()), "outcome": result["outcome"], "reason": result["reason"],
                                           "provider_message_id": result.get("provider_message_id")}
                    self.vault._write_record(RECORD, record, revision + 1)
