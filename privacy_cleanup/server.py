"""Fixed loopback HTTP API. No outbound clients, file browsing or user uploads."""
import argparse
import hmac
import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .local_http import LocalHandler, LoopbackServer

from .engine import ROOT, RuleError
from .network import install
from .storage import Store, default_directory

STATIC = ROOT / "privacy_cleanup/static"


def create_server(store, port=8765):
    token = secrets.token_urlsafe(32)

    class Handler(LocalHandler):
        server_version = "PrivacyCleanupMock"
        sys_version = ""

        def do_GET(self):
            if not self.guarded(api=self.path == "/api/state"):
                return
            if self.path == "/api/state":
                self.send_body(200, store.read())
            elif self.path == "/":
                page = (STATIC / "index.html").read_text().replace("__DEMO_TOKEN__", token)
                self.send_body(200, page, "text/html; charset=utf-8")
            elif self.path == "/fonts/EBGaramond-wght.ttf":
                self.send_body(200, (STATIC / "fonts/EBGaramond-wght.ttf").read_bytes(), "font/ttf")
            elif self.path in {"/app.js", "/style.css"}:
                content_type = "text/javascript" if self.path.endswith("js") else "text/css"
                self.send_body(200, (STATIC / self.path[1:]).read_bytes(), content_type + "; charset=utf-8")
            else:
                self.send_body(404, {"error": "Not found"})

        def do_POST(self):
            if not self.guarded(api=True, mutation=True):
                return
            if self.path != "/api/action":
                self.send_body(404, {"error": "Not found"})
                return
            if self.headers.get("Content-Type") != "application/json" or self.headers.get("Transfer-Encoding"):
                self.send_body(415, {"error": "Use a bounded JSON demo command"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2048:
                    self.send_body(413, {"error": "Demo commands must be at most 2048 bytes"})
                    return
                payload = json.loads(self.rfile.read(length))
                self.send_body(200, store.act(payload))
            except RuleError as exc:
                self.send_body(409, {"error": str(exc)})
            except (ValueError, UnicodeError):
                self.send_body(400, {"error": "Invalid JSON command"})
            except Exception:
                # No raw exception, SQL, request or local path in the response/log.
                self.send_body(500, {"error": "Local operation failed; refresh to reconcile state before retrying"})

    server = LoopbackServer(("127.0.0.1", port), Handler)
    server.token = token
    return server


def main():
    parser = argparse.ArgumentParser(description="Offline synthetic privacy cleanup demo. No live mode.")
    parser.add_argument("--data-dir", default=str(default_directory()), help="Private, non-Git directory; mode 0700")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    os.umask(0o077)
    install()
    try:
        store = Store(args.data_dir)
        server = create_server(store, args.port)
    except (RuleError, OSError):
        parser.exit(2, "Cannot start: use an unused loopback port and a private owned directory outside Git.\n")
    print("Mock-only demo: http://127.0.0.1:%d\nNo live searches, emails or submissions. Ctrl+C stops the server." % server.server_port, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
