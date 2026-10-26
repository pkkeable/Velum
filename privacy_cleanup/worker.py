"""Isolated sending worker: one request at a time over an inherited socket.

The worker trusts nothing from the UI process except the owner's approval fingerprint. It
renders each message itself from the authored contract and refuses any mismatch, so the UI
cannot choose a recipient or alter wording. It holds no vault, key or identity record, keeps
no files or logs, and its own audit hook lets it reach only its configured endpoints.

Transports (chosen at spawn time, before the UI process denies child processes):

    fake:127.0.0.1:PORT         local fake provider (scripts/fake_provider.py), simulation only
    gmail                       Gmail API over TLS to Google's token and send hosts
    gmail-local:127.0.0.1:PORT  the Gmail protocol against a local fake Google (tests and QA)

Both Gmail transports are self-only in this build: they send only messages addressed to the
connected account itself. Sending to brokers through a real provider is a later pilot step.
"""
import base64
import email.policy
import email.utils
import http.client
import json
import os
import re
import socket
import ssl
import struct
import sys
import time
from email.message import EmailMessage
from urllib.parse import urlencode

from . import contracts
from .domain import RuleError

MAX_FRAME = 65536
MAX_RESPONSE = 16384
MAX_SENDS = 50          # Per worker lifetime; a runaway caller cannot turn this into a mailer.
MIN_INTERVAL = 1.0      # Seconds between transmissions.
TRANSPORT_TIMEOUT = 20.0
JOB = re.compile(r"[0-9a-f]{32}")
PROVIDER_ID = re.compile(r"[A-Za-z0-9._-]{1,128}")
SECRET = re.compile(r"[\x21-\x7e]{1,2048}")
ENVELOPE = {"job_id", "contract_id", "contract_version", "fields", "fingerprint"}
AUTHORITY = {"client_id", "client_secret", "refresh_token", "account_email"}
GMAIL_SEND = "https://www.googleapis.com/auth/gmail.send"
GRANTABLE = {GMAIL_SEND, "openid", "email", "https://www.googleapis.com/auth/userinfo.email"}
GOOGLE_ISSUERS = {"accounts.google.com", "https://accounts.google.com"}
REJECTED = {400, 401, 403, 404, 409, 413, 422, 429}


# Framing shared with the UI-side client: 4-byte big-endian length, then UTF-8 JSON.

def _exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("peer closed")
        data += chunk
    return data


def read_frame(sock):
    (size,) = struct.unpack(">I", _exact(sock, 4))
    if not 0 < size <= MAX_FRAME:
        raise ValueError("frame size")
    value = json.loads(_exact(sock, size))
    if not isinstance(value, dict):
        raise ValueError("frame type")
    return value


def write_frame(sock, value):
    data = json.dumps(value, separators=(",", ":")).encode()
    if len(data) > MAX_FRAME:
        raise ValueError("frame size")
    sock.sendall(struct.pack(">I", len(data)) + data)


def parse_spec(spec):
    if spec == "gmail":
        return "gmail", None, None
    match = re.fullmatch(r"(fake|gmail-local):127\.0\.0\.1:([0-9]{1,5})", spec or "")
    if not match or not 1 <= int(match.group(2)) <= 65535:
        raise ValueError("Unsupported transport specification")
    return match.group(1), "127.0.0.1", int(match.group(2))


class Network:
    """What this worker may reach: literal (ip, port) pairs, or named hosts whose addresses
    are pinned at the single resolution the transport performs."""

    def __init__(self, literals=(), hostnames=()):
        self.literals, self.hostnames, self.pinned = set(literals), set(hostnames), set()

    def resolve(self, host, port):
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        addresses = [(family, address) for family, _, _, _, address in infos if family in (socket.AF_INET, socket.AF_INET6)]
        self.pinned |= {(address[0], address[1]) for _, address in addresses}
        return addresses

    def may_resolve(self, host, port):
        host = host.decode() if isinstance(host, bytes) else host
        port = int(port) if isinstance(port, (int, str)) and str(port).isdigit() else None
        return (host, port) in self.hostnames or (host, port) in self.literals

    def may_connect(self, address):
        return isinstance(address, tuple) and len(address) >= 2 and (
            (address[0], address[1]) in self.literals or (address[0], address[1]) in self.pinned)


def install_guard(network, port=None):
    """Worker-side deny-by-default boundary: only the configured endpoints, no bind, no
    children, no native code, no file writes. install_guard(host, port) means one literal."""
    if not isinstance(network, Network):
        network = Network(literals={(network, port)})
    write = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC

    def guard(event, args):
        if event == "socket.getaddrinfo":
            if not network.may_resolve(args[0], args[1]):
                raise PermissionError("Worker resolves only its configured endpoints")
        elif event in {"socket.connect", "socket.connect_ex"}:
            if not network.may_connect(args[1]):
                raise PermissionError("Worker connects only to its configured endpoints")
        elif event in {"socket.bind", "socket.sendto", "socket.sendmsg", "socket.gethostbyname",
                       "socket.gethostbyaddr", "socket.getnameinfo"}:
            raise PermissionError("Worker network use is limited to its outbound endpoints")
        elif event in {"subprocess.Popen", "os.system", "os.exec", "os.posix_spawn", "os.spawn",
                       "os.fork", "os.forkpty", "ctypes.dlopen", "ctypes.dlsym"}:
            raise PermissionError("Worker cannot start processes or load native code")
        elif event == "open" and isinstance(args[2], int) and args[2] & write:
            raise PermissionError("Worker writes no files")

    sys.dont_write_bytecode = True
    sys.addaudithook(guard)
    import _posixsubprocess
    _posixsubprocess.fork_exec = lambda *a, **k: (_ for _ in ()).throw(PermissionError("Worker cannot start processes"))
    return network


class Unreachable(Exception):
    """Nothing was transmitted: the connection or TLS handshake failed before any request."""


class Interrupted(Exception):
    """The request may have reached the server."""


class HTTPClient:
    def __init__(self, network, timeout=TRANSPORT_TIMEOUT, context=None):
        self.network, self.timeout = network, timeout
        self.context = context or ssl.create_default_context()

    def post(self, endpoint, path, body, headers):
        host, port, secure = endpoint
        if secure:
            try:
                addresses = self.network.resolve(host, port)
            except OSError:
                raise Unreachable() from None
            sock = None
            for family, address in addresses:
                candidate = socket.socket(family, socket.SOCK_STREAM)
                candidate.settimeout(self.timeout)
                try:
                    candidate.connect(address)
                    sock = candidate
                    break
                except OSError:
                    candidate.close()
            if sock is None:
                raise Unreachable()
            try:
                tls = self.context.wrap_socket(sock, server_hostname=host)
            except (OSError, ssl.SSLError):
                sock.close()
                raise Unreachable() from None
            connection = http.client.HTTPSConnection(host, port, timeout=self.timeout)
            connection.sock = tls
        else:
            connection = http.client.HTTPConnection(host, port, timeout=self.timeout)
            try:
                connection.connect()
            except OSError:
                raise Unreachable() from None
        try:
            try:
                connection.request("POST", path, body, headers)
                response = connection.getresponse()
                data = response.read(MAX_RESPONSE + 1)
            except (OSError, http.client.HTTPException):
                raise Interrupted() from None
        finally:
            connection.close()
        if len(data) > MAX_RESPONSE:
            raise Interrupted()
        return response.status, data


def classify(status, data):
    """Provider response to an outcome. Anything ambiguous is uncertain; redirects are never followed."""
    if 200 <= status < 300:
        try:
            provider_id = json.loads(data)["id"]
        except (ValueError, TypeError, KeyError):
            provider_id = None
        if not isinstance(provider_id, str) or not PROVIDER_ID.fullmatch(provider_id):
            return {"outcome": "uncertain", "reason": "malformed_acceptance"}
        return {"outcome": "accepted", "reason": "provider_accepted", "provider_message_id": provider_id}
    if status in REJECTED:
        return {"outcome": "not_sent", "reason": "provider_rejected_%d" % status}
    return {"outcome": "uncertain", "reason": "provider_status_%d" % status}


class FakeTransport:
    """Loopback fake mail provider. Classifies outcomes conservatively."""
    kind, needs_authority = "fake", False

    def __init__(self, host, port, timeout=TRANSPORT_TIMEOUT, network=None):
        self.endpoint = (host, port, False)
        self.http = HTTPClient(network or Network(literals={(host, port)}), timeout)

    def send(self, message, job_id, authority=None):
        body = json.dumps({**message, "idempotency_key": job_id}).encode()
        try:
            status, data = self.http.post(self.endpoint, "/v1/send", body, {"Content-Type": "application/json"})
        except Unreachable:
            return {"outcome": "not_sent", "reason": "provider_unreachable"}
        except Interrupted:
            return {"outcome": "uncertain", "reason": "interrupted_after_request"}
        return classify(status, data)


def mime(message):
    """RFC 5322 bytes for a rendered message. Header values were already checked for control
    characters; EmailMessage also refuses newlines in headers. No Message-ID (Gmail adds one),
    so nothing here performs a hostname lookup."""
    msg = EmailMessage(policy=email.policy.SMTP)
    msg["From"], msg["To"], msg["Subject"] = message["from"], message["to"], message["subject"]
    msg["Date"] = email.utils.formatdate(usegmt=True)
    msg.set_content(message["body"])
    return msg.as_bytes()


def _b64url(data):
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def id_token_email(id_token, client_id):
    """The verified Google account email from an ID token received directly from Google's token
    endpoint over TLS. OpenID Connect Core 3.1.3.7 lets that TLS validation stand in for checking
    the signature; the audience, issuer and email_verified claims are still checked."""
    try:
        payload = id_token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, IndexError, AttributeError, TypeError):
        return None
    audience = claims.get("aud") if isinstance(claims, dict) else None
    value = claims.get("email") if isinstance(claims, dict) else None
    if (audience != client_id or claims.get("iss") not in GOOGLE_ISSUERS or claims.get("email_verified") is not True
            or not isinstance(value, str) or not contracts.EMAIL.fullmatch(value) or len(value) > 254):
        return None
    return value


class GmailTransport:
    """Gmail API with a short-lived access token obtained per job; never stored."""
    kind, needs_authority = "gmail", True
    GOOGLE = {"token": ("oauth2.googleapis.com", 443, True), "send": ("gmail.googleapis.com", 443, True),
              "revoke": ("oauth2.googleapis.com", 443, True)}

    def __init__(self, endpoints=None, timeout=TRANSPORT_TIMEOUT, network=None, context=None):
        self.endpoints = endpoints or self.GOOGLE
        self.network = network or self.network_for(self.endpoints)
        self.http = HTTPClient(self.network, timeout, context)

    @staticmethod
    def network_for(endpoints):
        literals = {(h, p) for h, p, secure in endpoints.values() if not secure}
        hostnames = {(h, p) for h, p, secure in endpoints.values() if secure}
        return Network(literals, hostnames)

    @classmethod
    def local(cls, port, timeout=TRANSPORT_TIMEOUT):
        endpoint = ("127.0.0.1", port, False)
        return cls({"token": endpoint, "send": endpoint, "revoke": endpoint}, timeout)

    def _form(self, which, values):
        return self.http.post(self.endpoints[which], {"token": "/token", "revoke": "/revoke"}[which],
                              urlencode(values).encode(), {"Content-Type": "application/x-www-form-urlencoded"})

    def _access_token(self, authority):
        try:
            status, data = self._form("token", {"client_id": authority["client_id"], "client_secret": authority["client_secret"],
                                                "grant_type": "refresh_token", "refresh_token": authority["refresh_token"]})
        except (Unreachable, Interrupted):
            return None, "authorization_unavailable"
        try:
            body = json.loads(data)
        except ValueError:
            body = {}
        if status == 200 and isinstance(body.get("access_token"), str) and SECRET.fullmatch(body["access_token"]):
            return body["access_token"], None
        return None, "authorization_expired" if body.get("error") == "invalid_grant" else "authorization_failed"

    def send(self, message, job_id, authority):
        account = authority["account_email"].casefold()
        if message["to"].casefold() != account or message["from"].casefold() != account:
            # This build sends only to the connected account itself; no broker through a real provider.
            return {"outcome": "not_sent", "reason": "refused_broker_sending_disabled"}
        token, problem = self._access_token(authority)
        if not token:
            # No message bytes were sent: definitively not sent.
            return {"outcome": "not_sent", "reason": problem}
        body = json.dumps({"raw": _b64url(mime(message))}).encode()
        path = "/gmail/v1/users/me/messages/send"
        try:
            status, data = self.http.post(self.endpoints["send"], path, body,
                                          {"Content-Type": "application/json", "Authorization": "Bearer " + token})
        except Unreachable:
            return {"outcome": "not_sent", "reason": "provider_unreachable"}
        except Interrupted:
            return {"outcome": "uncertain", "reason": "interrupted_after_request"}
        return classify(status, data)

    def exchange(self, request):
        try:
            status, data = self._form("token", {"client_id": request["client_id"], "client_secret": request["client_secret"],
                                                "code": request["code"], "code_verifier": request["code_verifier"],
                                                "grant_type": "authorization_code", "redirect_uri": request["redirect_uri"]})
            body = json.loads(data)
        except (Unreachable, Interrupted):
            return {"outcome": "failed", "reason": "google_unreachable"}
        except ValueError:
            return {"outcome": "failed", "reason": "malformed_token_response"}
        if status != 200 or not isinstance(body, dict):
            return {"outcome": "failed", "reason": "code_rejected"}
        refresh, scopes = body.get("refresh_token"), set(str(body.get("scope", "")).split())
        if not isinstance(refresh, str) or not SECRET.fullmatch(refresh):
            return {"outcome": "failed", "reason": "no_refresh_token"}
        if GMAIL_SEND not in scopes or not scopes <= GRANTABLE:
            return {"outcome": "failed", "reason": "unexpected_scope"}
        account = id_token_email(body.get("id_token"), request["client_id"])
        if not account:
            return {"outcome": "failed", "reason": "unverified_account"}
        return {"outcome": "connected", "reason": "connected", "refresh_token": refresh, "account_email": account}

    def revoke(self, token):
        try:
            status, _ = self._form("revoke", {"token": token})
        except (Unreachable, Interrupted):
            return {"outcome": "failed", "reason": "google_unreachable"}
        return {"outcome": "revoked" if status == 200 else "failed", "reason": "revoked" if status == 200 else "revoke_rejected"}


class Worker:
    def __init__(self, transport, clock=time.monotonic, sleep=time.sleep, now=time.time):
        self.transport, self.clock, self.sleep, self.now = transport, clock, sleep, now
        self.seen, self.sent, self.last = set(), 0, None

    def handle(self, request):
        kind = request.get("type")
        if kind in {"connect", "revoke"}:
            return self._account(kind, request)
        envelope = request.get("envelope") if kind == "send" else None
        job_id = envelope.get("job_id") if isinstance(envelope, dict) else None
        expected = ENVELOPE | ({"authority"} if self.transport.needs_authority else set())
        if not isinstance(envelope, dict) or set(envelope) != expected or not isinstance(job_id, str) or not JOB.fullmatch(job_id):
            return {"job_id": job_id if isinstance(job_id, str) else None, "outcome": "not_sent", "reason": "refused_malformed"}
        refuse = lambda reason: {"job_id": job_id, "outcome": "not_sent", "reason": "refused_" + reason}  # noqa: E731
        authority = envelope.get("authority")
        if self.transport.needs_authority and (not isinstance(authority, dict) or set(authority) != AUTHORITY or
                                               not all(isinstance(v, str) and SECRET.fullmatch(v) for v in authority.values())):
            return refuse("malformed")
        if job_id in self.seen:
            return refuse("duplicate_job")
        try:
            item = contracts.contract(envelope["contract_id"])
        except RuleError:
            return refuse("unknown_contract")
        if envelope["contract_version"] != item["version"]:
            return refuse("contract_changed")
        if not contracts.fresh(item, self.now()):
            return refuse("source_review_due")
        try:
            message = contracts.render(item, envelope["fields"])
        except RuleError:
            return refuse("invalid_fields")
        fingerprint = contracts.fingerprint(item, message)
        if envelope["fingerprint"] != fingerprint:
            return refuse("fingerprint_mismatch")
        if self.sent >= MAX_SENDS:
            return refuse("send_cap")
        if self.last is not None:
            wait = MIN_INTERVAL - (self.clock() - self.last)
            if wait > 0:
                self.sleep(wait)
        self.seen.add(job_id)
        self.sent += 1
        self.last = self.clock()
        result = self.transport.send(message, job_id, authority)
        return {"job_id": job_id, "fingerprint": fingerprint, "transport": self.transport.kind, **result}

    def _account(self, kind, request):
        if not hasattr(self.transport, "exchange"):
            return {"type": kind, "outcome": "failed", "reason": "unsupported"}
        if kind == "connect":
            keys = {"type", "code", "code_verifier", "redirect_uri", "client_id", "client_secret"}
            if set(request) != keys or not all(isinstance(request[k], str) and SECRET.fullmatch(request[k]) for k in keys - {"type"}):
                return {"type": kind, "outcome": "failed", "reason": "malformed"}
            return {"type": kind, **self.transport.exchange(request)}
        if set(request) != {"type", "token"} or not isinstance(request["token"], str) or not SECRET.fullmatch(request["token"]):
            return {"type": kind, "outcome": "failed", "reason": "malformed"}
        return {"type": kind, **self.transport.revoke(request["token"])}


def transport_for(spec):
    kind, host, port = parse_spec(spec)
    if kind == "fake":
        return FakeTransport(host, port)
    if kind == "gmail-local":
        return GmailTransport.local(port)
    return GmailTransport()


def serve(sock, worker):
    while True:
        try:
            request = read_frame(sock)
        except (ConnectionError, OSError):
            return
        except ValueError:
            write_frame(sock, {"job_id": None, "outcome": "not_sent", "reason": "refused_malformed"})
            continue
        try:
            reply = worker.handle(request)
        except Exception:  # Never echo internals; a send may have reached the provider.
            envelope = request.get("envelope")
            reply = {"job_id": envelope.get("job_id") if isinstance(envelope, dict) else None, "type": request.get("type"),
                     "outcome": "uncertain" if request.get("type") == "send" else "failed", "reason": "worker_error"}
        write_frame(sock, reply)


def main(fd, spec):
    """Entry point used by dispatch.WorkerClient.spawn; the fd is the inherited socket."""
    transport = transport_for(spec)
    sock = socket.socket(fileno=fd)
    install_guard(transport.http.network)
    serve(sock, Worker(transport))
