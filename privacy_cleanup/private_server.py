"""Encrypted local workspace with manual handoffs. This process installs the network guard;
the only outbound path is the optional sending worker spawned before it (see dispatch.py)."""
import argparse
import json
import os
import secrets
import time
import unicodedata
from pathlib import Path

from .domain import RuleError
from .dispatch import WorkerClient
from .key_store import MacKeyStore
from .local_http import LocalHandler, LoopbackServer
from .network import install
from .routes import catalog
from .vault import PassphraseSetupRequired, Vault, default_directory
from .workspace import Workspace

STATIC = Path(__file__).resolve().parent / "static"
FONT = "/fonts/EBGaramond-wght.ttf"  # Bundled; the page loads nothing from the web.
FAILED = "Private operation failed. An encrypted record was locked; a session without saving was erased."


def create_server(workspace, port=8766, worker=None):
    """workspace: a Workspace, or an existing Vault (tests), which is wrapped in one."""
    ws = workspace if isinstance(workspace, Workspace) else Workspace(worker=worker, vault=workspace)

    def sender_command(session, action, data):
        schemas = {"connect_start": {"client_id", "client_secret"}, "disconnect": set(), "test_send": {"acknowledged"}}
        if not isinstance(action, str) or action not in schemas or not isinstance(data, dict) or set(data) != schemas[action]:
            raise RuleError("Unsupported sender command fields")
        parts = ws.parts
        execution, cases = parts.execution, parts.cases
        if execution.gmail is None:
            raise RuleError("This session was not started with a Gmail sender")
        if action == "connect_start":
            return execution.gmail.start(session, data["client_id"], data["client_secret"])
        if action == "test_send":
            return execution.test_send(session, data["acknowledged"])
        revoked = execution.gmail.disconnect(session)
        return {**cases.state(session), "revoked": revoked}

    class Handler(LocalHandler):
        server_version = "PrivacyCleanupPrivate"
        token_header = "X-App-Token"

        def do_GET(self):
            if not self.guarded(api=self.path.startswith("/api/")):
                return
            try:
                token = self.headers.get("X-Private-Session")
                if self.path == "/api/status":
                    self.send_body(200, ws.status(token))
                elif self.path == "/api/brokers":
                    # Public authored metadata only. Never read or unlock records.
                    self.send_body(200, {"brokers": catalog(time.time())})
                elif self.path == "/api/profile":
                    self.send_body(200, ws.parts.store.read(token))
                elif self.path == "/api/cases":
                    self.send_body(200, ws.parts.cases.state(token))
                elif self.path == "/api/submissions":
                    self.send_body(200, ws.parts.cases.submissions(token))
                elif self.path == "/":
                    # The page carries no token. Only the launch link printed to the owner's
                    # terminal does, in its fragment, which browsers never send to a server.
                    self.send_body(200, (STATIC / "private.html").read_bytes(), "text/html; charset=utf-8")
                elif self.path == FONT:
                    self.send_body(200, (STATIC / FONT[1:]).read_bytes(), "font/ttf")
                elif self.path in {"/private.js", "/style.css"}:
                    kind = "text/javascript" if self.path.endswith(".js") else "text/css"
                    self.send_body(200, (STATIC / self.path[1:]).read_bytes(), kind + "; charset=utf-8")
                else:
                    self.send_body(404, {"error": "Not found"})
            except RuleError as error:
                self.send_body(409, {"error": str(error)})
            except Exception:
                ws.fail()
                self.send_body(500, {"error": FAILED})

        def do_POST(self):
            if not self.guarded(api=True, mutation=True):
                return
            fields = {"/api/create": {"acknowledged", "passphrase", "confirmation"}, "/api/unlock": {"passphrase"},
                      "/api/passphrase": {"passphrase", "confirmation"},
                      "/api/lock": set(), "/api/touch": set(), "/api/start": set(), "/api/end": set(),
                      "/api/convert": {"acknowledged", "passphrase", "confirmation"},
                      "/api/save": {"profile", "version"}, "/api/preview": {"profile"},
                      "/api/upgrade": {"version", "acknowledged"},
                      "/api/delete": {"confirmation", "version"},
                      "/api/cases/create": {"broker", "listing_url", "note", "self_only"},
                      "/api/cases/command": {"id", "version", "action", "data"},
                      "/api/workflow": {"version", "profile_version", "action", "data"},
                      "/api/execution": {"id", "version", "action", "data"},
                      "/api/sender": {"action", "data"}}
            if self.path not in fields:
                self.send_body(404, {"error": "Not found"})
                return
            if self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding"):
                self.send_body(415, {"error": "Use a bounded JSON command"})
                return
            # Reading and parsing failures are the client's problem; they never lock the vault.
            try:
                length = int(self.headers.get("Content-Length", "0"))
                # Full bounded identities, including escaped Unicode, must fit.
                limit = 262144 if self.path in {"/api/save", "/api/preview"} else 32768 if self.path == "/api/workflow" else 8192
                if not 0 < length <= limit:
                    self.send_body(413, {"error": "Private command exceeds its size limit"})
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError()
                payload = json.loads(body)
            except (ValueError, UnicodeError, OSError, RecursionError):
                self.send_body(400, {"error": "Invalid JSON command"})
                return
            try:
                if not isinstance(payload, dict) or set(payload) != fields[self.path]:
                    raise RuleError("Unsupported private command fields")
                session = self.headers.get("X-Private-Session")
                if self.path in {"/api/create", "/api/passphrase", "/api/convert"} and payload["passphrase"] != payload["confirmation"]:
                    raise RuleError("The passphrase confirmation does not match")
                if self.path in {"/api/create", "/api/convert"} and payload["acknowledged"] is not True:
                    raise RuleError("Review the local storage limits before creating an encrypted record")
                if self.path == "/api/start":
                    result = ws.start_session()
                elif self.path == "/api/end":
                    result = ws.end_session(session)
                elif self.path == "/api/create":
                    result = ws.create_vault(payload["passphrase"])
                elif self.path == "/api/convert":
                    result = ws.convert(session, payload["passphrase"])
                elif self.path == "/api/unlock":
                    result = ws.unlock_vault(payload["passphrase"])
                elif self.path == "/api/passphrase":
                    result = ws.set_passphrase(payload["passphrase"])
                elif self.path == "/api/save":
                    result = ws.parts.store.save(session, payload["profile"], payload["version"])
                elif self.path == "/api/preview":
                    result = ws.parts.workflow.preview(session, payload["profile"])
                elif self.path == "/api/upgrade":
                    result = ws.parts.store.upgrade_identity(session, payload["version"], payload["acknowledged"])
                elif self.path == "/api/cases/create":
                    result = ws.parts.cases.create(session, payload["broker"], payload["listing_url"], payload["note"], payload["self_only"])
                elif self.path == "/api/cases/command":
                    result = ws.parts.cases.command(session, payload["id"], payload["version"], payload["action"], payload["data"])
                elif self.path == "/api/workflow":
                    result = ws.parts.workflow.command(session, payload["version"], payload["profile_version"], payload["action"], payload["data"])
                elif self.path == "/api/execution":
                    result = ws.parts.execution.command(session, payload["id"], payload["version"], payload["action"], payload["data"])
                elif self.path == "/api/sender":
                    result = sender_command(session, payload["action"], payload["data"])
                elif self.path == "/api/delete":
                    result = ws.delete_vault(session, payload["confirmation"], payload["version"])
                elif self.path == "/api/touch":
                    ws.parts.store.touch(session)
                    result = {"ok": True}
                else:
                    result = ws.lock()
                self.send_body(200, result)
            except PassphraseSetupRequired as error:
                self.send_body(409, {"error": str(error), "passphrase_setup": True})
            except RuleError as error:
                self.send_body(409, {"error": str(error)})
            except Exception:
                ws.fail()
                self.send_body(500, {"error": FAILED})

    server = LoopbackServer(("127.0.0.1", port), Handler)
    server.token = secrets.token_urlsafe(32)
    server.workspace = ws
    server.service_actions = ws.service
    return server


def _comparable(path):
    # macOS volumes are normally case- and Unicode-normalization-insensitive.
    return unicodedata.normalize("NFD", str(path.resolve())).casefold()


def is_personal_store(path):
    """True when path names the default personal store, including case or alias spellings.

    Compares the directory on disk when both exist, and the normalized path text
    otherwise. An error while checking is treated as the personal store (fail closed)."""
    chosen, default = Path(path).expanduser().absolute(), default_directory()
    try:
        if chosen.exists() and default.exists() and os.path.samefile(chosen, default):
            return True
        return _comparable(chosen) == _comparable(default)
    except (OSError, ValueError):
        return True


def main():
    parser = argparse.ArgumentParser(description="Private local case workspace. Manual handoffs, plus owner-email sending after exact approval (local fake provider only in this build).")
    parser.add_argument("--data-dir", default=str(default_directory()))
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--synthetic-workspace", action="store_true", help="Required for this synthetic technical preview; use only fictional records")
    senders = parser.add_mutually_exclusive_group()
    senders.add_argument("--fake-transport", type=int, metavar="PORT",
                         help="Send approved emails to the local fake provider (scripts/fake_provider.py) on 127.0.0.1:PORT. Simulation only.")
    senders.add_argument("--sender", choices=["gmail"],
                         help="Connect your own Gmail account (send-only). This build sends only test messages to yourself.")
    senders.add_argument("--fake-google", type=int, metavar="PORT",
                         help="Run the Gmail flow against the local fake Google (scripts/fake_provider.py --google). Simulation only.")
    args = parser.parse_args()
    if not args.synthetic_workspace or is_personal_store(args.data_dir):
        parser.error("Saved storage awaits independent review. Use --synthetic-workspace and an explicit temporary --data-dir; personal storage is disabled in this build.")
    os.umask(0o077)
    workspace = server = worker = None
    try:
        keys = MacKeyStore()
        spec = ("fake:127.0.0.1:%d" % args.fake_transport if args.fake_transport is not None else
                "gmail-local:127.0.0.1:%d" % args.fake_google if args.fake_google is not None else
                "gmail" if args.sender == "gmail" else None)
        if spec:
            # Spawned before this process denies child processes and networking. The worker gets
            # its own narrower guard: only its transport's endpoints.
            worker = WorkerClient.spawn(spec)
        install()
        # Nothing is opened or created in the data directory until the owner chooses an
        # encrypted record, unless one already exists there.
        workspace = Workspace(args.data_dir, keys, worker)
        server = create_server(workspace, args.port, worker)
        print("Velum, private local workspace. Open this link (it is valid until the server stops; do not share it):\n"
              "  http://127.0.0.1:%d/#token=%s\n"
              "Nothing is kept unless you choose an encrypted record. %s Ctrl+C stops the server."
              % (server.server_port, server.token,
                 ("Gmail sender: connect in Privacy/settings; only test messages to yourself are sent."
                  if worker and worker.kind == "gmail" and not worker.simulated else
                  "Sending is simulated against a local fake service." if worker else
                  "No sender configured; nothing can be sent.")),
              flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except (RuleError, OSError, ValueError):
        parser.exit(2, "Cannot start private mode. Check Keychain, private directory, runtime and loopback port.\n")
    finally:
        if server:
            server.server_close()
        if workspace:
            workspace.close()
        if worker:
            worker.close()
