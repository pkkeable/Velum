"""Local fake mail provider for synthetic R3 development and tests. Never a real transport.

Listens on 127.0.0.1 only. The sending worker posts one JSON message per approved email; this
server records it in memory and answers according to its mode, so tests can inject acceptance,
rejection, server errors, hangs, disconnects and malformed or hostile responses.

    python -m scripts.fake_provider --port 8799 [--mode accept]
"""
import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODES = {"accept", "reject", "rate_limited", "server_error", "hang", "disconnect", "malformed",
         "oversized", "redirect", "bad_id"}


class FakeProvider(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port=0, mode="accept", hang_seconds=3.0, sequence=()):
        self.mode, self.hang_seconds = mode, hang_seconds
        self.sequence = list(sequence)  # Modes used for the next requests in order, then `mode`.
        self.received, self.lock = [], threading.Lock()
        super().__init__(("127.0.0.1", port), Handler)

    def server_bind(self):
        # Skip HTTPServer's getfqdn(); the worker's guard and tests need no DNS.
        import socketserver
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = "127.0.0.1", self.socket.getsockname()[1]

    def handle_error(self, request, client_address):
        pass  # Injected disconnects are expected; keep test output clean.

    def start(self):
        threading.Thread(target=self.serve_forever, daemon=True).start()
        return self

    def stop(self):
        self.shutdown()
        self.server_close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def reply(self, status, body, headers=()):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        for key, value in headers:
            self.send_header(key, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        server = self.server
        if self.path != "/v1/send":
            return self.reply(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", "0"))
        message = json.loads(self.rfile.read(length))
        with server.lock:
            mode = server.sequence.pop(0) if server.sequence else server.mode
        if mode in {"reject", "rate_limited"}:
            return self.reply(400 if mode == "reject" else 429, {"error": "rejected"})
        with server.lock:
            server.received.append(message)  # Every mode below may have "sent" the message.
            number = len(server.received)
        if mode == "accept":
            return self.reply(200, {"id": "fake-%d" % number})
        if mode == "server_error":
            return self.reply(500, {"error": "internal"})
        if mode == "hang":
            time.sleep(server.hang_seconds)
            return self.reply(200, {"id": "fake-%d" % number})
        if mode == "disconnect":
            self.close_connection = True
            self.connection.shutdown(2)
            return None
        if mode == "malformed":
            return self.reply(200, b"<html>not json</html>")
        if mode == "oversized":
            return self.reply(200, {"id": "fake-%d" % number, "padding": "x" * 50000})
        if mode == "redirect":
            return self.reply(302, {"error": "moved"}, [("Location", "https://attacker.invalid/steal")])
        return self.reply(200, {"id": "../../etc\r\nX-Injected: 1"})  # bad_id


GOOGLE_MODES = {"accept", "deny_consent", "reject_code", "no_refresh", "broad_scope", "wrong_audience",
                "unverified_email", "invalid_grant", "send_400", "send_403", "send_429", "send_500", "send_disconnect"}
GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send"


class FakeGoogle(FakeProvider):
    """Local stand-in for Google's OAuth and Gmail send endpoints, for the gmail-local transport.

    Implements the authorization redirect, PKCE-checked code exchange, refresh, send and revoke.
    Records decoded MIME messages; never contacts Google."""

    def __init__(self, port=0, mode="accept", account="owner-canary@example.invalid"):
        self.account, self.codes, self.refresh, self.access, self.revoked = account, {}, set(), set(), []
        FakeProvider.__init__(self, port, mode)
        self.RequestHandlerClass = GoogleHandler


class GoogleHandler(Handler):
    def do_GET(self):
        import base64
        import hashlib
        from urllib.parse import parse_qs, urlencode, urlsplit
        server, parts = self.server, urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if parts.path != "/o/oauth2/v2/auth":
            return self.reply(404, {"error": "not found"})
        if server.mode == "deny_consent":
            target = query["redirect_uri"] + "?" + urlencode({"error": "access_denied", "state": query["state"]})
        else:
            code = "code-%d" % (len(server.codes) + 1)
            server.codes[code] = {"challenge": query["code_challenge"], "client_id": query["client_id"],
                                  "redirect_uri": query["redirect_uri"]}
            target = query["redirect_uri"] + "?" + urlencode({"state": query["state"], "code": code, "scope": query["scope"]})
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        import base64
        import hashlib
        from urllib.parse import parse_qs
        server = self.server
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.path == "/token":
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            if form.get("grant_type") == "authorization_code":
                grant = server.codes.pop(form.get("code"), None)
                challenge = base64.urlsafe_b64encode(hashlib.sha256(form.get("code_verifier", "").encode()).digest()).decode().rstrip("=")
                if (server.mode == "reject_code" or not grant or grant["challenge"] != challenge
                        or grant["client_id"] != form.get("client_id") or grant["redirect_uri"] != form.get("redirect_uri")):
                    return self.reply(400, {"error": "invalid_grant"})
                token = "refresh-%d" % (len(server.refresh) + 1)
                server.refresh.add(token)
                claims = {"iss": "https://accounts.google.com", "email": server.account, "email_verified": server.mode != "unverified_email",
                          "aud": "other-client" if server.mode == "wrong_audience" else form["client_id"]}
                encode = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")  # noqa: E731
                scope = "openid https://www.googleapis.com/auth/userinfo.email " + GMAIL_SEND
                if server.mode == "broad_scope":
                    scope += " https://www.googleapis.com/auth/gmail.readonly"
                response = {"access_token": "access-initial", "expires_in": 3599, "token_type": "Bearer", "scope": scope,
                            "id_token": encode({"alg": "none"}) + "." + encode(claims) + ".sig"}
                if server.mode != "no_refresh":
                    response["refresh_token"] = token
                return self.reply(200, response)
            if form.get("grant_type") == "refresh_token":
                if server.mode == "invalid_grant" or form.get("refresh_token") not in server.refresh:
                    return self.reply(400, {"error": "invalid_grant"})
                token = "access-%d" % (len(server.access) + 1)
                server.access.add(token)
                return self.reply(200, {"access_token": token, "expires_in": 3599, "token_type": "Bearer"})
            return self.reply(400, {"error": "unsupported_grant_type"})
        if self.path == "/revoke":
            form = {k: v[0] for k, v in parse_qs(body.decode()).items()}
            server.revoked.append(form.get("token"))
            server.refresh.discard(form.get("token"))
            return self.reply(200, {})
        if self.path == "/gmail/v1/users/me/messages/send":
            if self.headers.get("Authorization", "").removeprefix("Bearer ") not in server.access:
                return self.reply(401, {"error": {"code": 401}})
            status = {"send_400": 400, "send_403": 403, "send_429": 429}.get(server.mode)
            if status:
                return self.reply(status, {"error": {"code": status}})
            raw = json.loads(body)["raw"]
            with server.lock:
                server.received.append(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
                number = len(server.received)
            if server.mode == "send_500":
                return self.reply(500, {"error": {"code": 500}})
            if server.mode == "send_disconnect":
                self.close_connection = True
                self.connection.shutdown(2)
                return None
            return self.reply(200, {"id": "gm-%d" % number, "threadId": "th-%d" % number, "labelIds": ["SENT"]})
        return self.reply(404, {"error": "not found"})


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8799)
    parser.add_argument("--mode", default="accept")
    parser.add_argument("--sequence", default="", help="Comma-separated modes for the next sends in order, then --mode "
                                                           "(for example accept,reject,server_error,hang)")
    parser.add_argument("--hang-seconds", type=float, default=3.0, help="How long the hang mode holds a request")
    parser.add_argument("--google", action="store_true", help="Act as a fake Google OAuth + Gmail API for --fake-google")
    args = parser.parse_args()
    sequence = [m for m in args.sequence.split(",") if m]
    if args.mode not in (GOOGLE_MODES if args.google else MODES) or not set(sequence) <= MODES or (sequence and args.google):
        parser.error("unknown mode or sequence")
    server = (FakeGoogle(args.port, args.mode) if args.google else
              FakeProvider(args.port, args.mode, hang_seconds=args.hang_seconds, sequence=sequence))
    print("Fake provider (simulation only) on http://127.0.0.1:%d, mode=%s. Ctrl+C stops." % (server.server_port, args.mode), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        print("Received %d synthetic message(s)." % len(server.received))


if __name__ == "__main__":
    main()
