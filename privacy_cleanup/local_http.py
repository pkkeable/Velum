"""Shared loopback HTTP protections for immutable demo/private servers."""
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer


class LocalHandler(BaseHTTPRequestHandler):
    token_header = "X-Demo-Token"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass  # Never log paths, headers, bodies or runtime identities.

    def send_body(self, status, body, content_type="application/json; charset=utf-8"):
        if isinstance(body, dict):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        # Every 127.0.0.1 port is the same site; isolate this window from other local pages.
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'")
        self.end_headers()
        self.wfile.write(body)

    def send_error(self, code, message=None, explain=None):
        # Replace http.server's HTML error page so malformed requests get the same headers.
        self.close_connection = True
        self.send_body(code, {"error": "Request rejected"})

    def guarded(self, api=False, mutation=False):
        host = "127.0.0.1:" + str(self.server.server_port)
        if self.headers.get("Host") != host:
            self.send_body(403, {"error": "Use the exact loopback URL printed by the server"})
            return False
        origin = self.headers.get("Origin")
        if origin is not None and origin != "http://" + host:
            self.send_body(403, {"error": "Cross-origin access blocked"})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self.send_body(403, {"error": "Cross-site access blocked"})
            return False
        if mutation and origin != "http://" + host:
            self.send_body(403, {"error": "A same-origin request is required"})
            return False
        if api and not hmac.compare_digest(self.headers.get(self.token_header, "").encode("utf-8", "surrogateescape"),
                                           self.server.token.encode()):
            self.send_body(403, {"error": "Open the local application to obtain a session token"})
            return False
        return True


class LoopbackServer(ThreadingHTTPServer):
    def server_bind(self):
        TCPServer.server_bind(self)
        self.server_name = "127.0.0.1"
        self.server_port = self.socket.getsockname()[1]
