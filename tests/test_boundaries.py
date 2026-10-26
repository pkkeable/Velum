import http.client
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from privacy_cleanup.engine import ROOT, RuleError
from privacy_cleanup.server import create_server
from privacy_cleanup.storage import Store

TMP = "/private/tmp" if Path("/private/tmp").exists() else "/tmp"


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=TMP)
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_repository_data_dir_rejected_before_write(self):
        with self.assertRaises(RuleError): Store(ROOT / "runtime")
        self.assertFalse((ROOT / "runtime").exists())

    def test_other_git_worktree_rejected(self):
        repo = self.root / "repo"; repo.mkdir(); (repo / ".git").write_text("gitdir: elsewhere")
        with self.assertRaises(RuleError): Store(repo / "runtime")

    def test_symlink_rejected_without_following(self):
        target = self.root / "target"; target.mkdir(mode=0o700)
        link = self.root / "linked"; link.symlink_to(target)
        with self.assertRaises(RuleError): Store(link)
        self.assertFalse((target / "state.sqlite3").exists())

    def test_permissions_and_persistence(self):
        store = Store(self.root / "private")
        self.assertEqual(stat.S_IMODE(store.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
        store.act({"action": "load_demo", "expected_version": 0})
        self.assertEqual(store.read(), Store(store.directory).read())

    def test_public_directory_and_db_symlink_rejected(self):
        p = self.root / "public"; p.mkdir(); p.chmod(0o755)
        with self.assertRaises(RuleError): Store(p)
        private = self.root / "private"; private.mkdir(mode=0o700)
        (private / "state.sqlite3").symlink_to(self.root / "elsewhere")
        with self.assertRaises(RuleError): Store(private)


class NetworkGuardTests(unittest.TestCase):
    def test_audit_guard_blocks_outbound_dns_udp_subprocess_and_remote_bind(self):
        # Isolated interpreter: this never disables the application's guard.
        code = """
import socket, subprocess, sys
from privacy_cleanup.network import install
install()
operations = [lambda: socket.getaddrinfo('example.invalid', 443),
 lambda: socket.getnameinfo(('192.0.2.1',443),0),
 lambda: socket.socket().connect(('192.0.2.1',443)),
 lambda: socket.socket(socket.AF_INET,socket.SOCK_DGRAM).sendto(b'x',('192.0.2.1',53)),
 lambda: socket.socket().bind(('0.0.0.0',0)),
 lambda: subprocess.run([sys.executable,'-V'])]
for op in operations:
 try: op()
 except PermissionError: pass
 else: raise AssertionError('guard failed')
s=socket.socket(); s.bind(('127.0.0.1',0)); s.close()
print('blocked')
"""
        result = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "blocked")

    def test_audit_guard_blocks_unaudited_spawn_fork_and_native_escapes(self):
        # Review L-3: these paths bypassed the original event list.
        code = """
import ctypes, ctypes.util, os, sys
from multiprocessing.util import spawnv_passfds
framework = ctypes.CDLL(ctypes.util.find_library('Security')) if sys.platform == 'darwin' else None
from privacy_cleanup.network import install
install()
operations = [lambda: spawnv_passfds(b'/usr/bin/true', [b'/usr/bin/true'], ()),
 lambda: os.fork(),
 lambda: ctypes.CDLL(None),
 lambda: ctypes.pythonapi.system]
for op in operations:
 try: op()
 except PermissionError: pass
 else: raise AssertionError('guard failed')
if framework is not None:
 ctypes.c_void_p.in_dll(framework, 'kSecClass')  # Keychain lookups keep working.
print('blocked')
"""
        result = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "blocked")

    def test_guarded_server_starts_without_dns(self):
        code = """
from privacy_cleanup.network import install
from privacy_cleanup.server import create_server
install()
s=create_server(None,0)
assert s.server_address[0]=='127.0.0.1'
s.server_close()
"""
        result = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(dir=TMP)
        cls.store = Store(Path(cls.tmp.name) / "private")
        cls.server = create_server(cls.store, 0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port
        cls.host = "127.0.0.1:" + str(cls.port)
        connection = http.client.HTTPConnection("127.0.0.1", cls.port)
        connection.request("GET", "/")
        cls.page = connection.getresponse().read().decode()
        cls.token = re.search(r'name="demo-token" content="([^"]+)"', cls.page).group(1)
        connection.close()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close(); cls.thread.join(); cls.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            result = connection.getresponse()
            return result.status, dict(result.getheaders()), result.read()
        finally: connection.close()

    def test_state_requires_session_token(self):
        self.assertEqual(self.request("GET", "/api/state")[0], 403)
        self.assertEqual(self.request("GET", "/api/state", headers={"X-Demo-Token": self.token})[0], 200)

    def test_foreign_host_and_origin_rejected(self):
        for headers in ({"Host": "attacker.invalid"}, {"Origin": "https://attacker.invalid"}, {"Sec-Fetch-Site": "cross-site"}):
            self.assertEqual(self.request("GET", "/", headers=headers)[0], 403)

    def test_post_requires_origin_token_and_json(self):
        body = json.dumps({"action": "load_demo", "expected_version": 0})
        headers = {"Origin": "http://" + self.host, "X-Demo-Token": self.token, "Content-Type": "application/json"}
        for missing in ("Origin", "X-Demo-Token", "Content-Type"):
            h = dict(headers); del h[missing]
            self.assertIn(self.request("POST", "/api/action", body, h)[0], (403, 415))
        self.assertEqual(self.request("POST", "/api/action", body, headers)[0], 200)

    def test_oversized_or_bad_body_is_rejected(self):
        headers = {"Origin": "http://" + self.host, "X-Demo-Token": self.token, "Content-Type": "application/json"}
        self.assertEqual(self.request("POST", "/api/action", "x" * 2049, headers)[0], 413)
        self.assertEqual(self.request("POST", "/api/action", "[", headers)[0], 400)

    def test_no_private_file_or_traversal_serving(self):
        for path in ("/state.sqlite3", "/../fixtures/demo.json", "/.git/config", "/api/export", "/api/import"):
            self.assertEqual(self.request("GET", path)[0], 404)

    def test_security_headers_and_no_external_assets(self):
        status, headers, _ = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertIn("connect-src 'self'", headers["Content-Security-Policy"])
        self.assertIn("form-action 'none'", headers["Content-Security-Policy"])
        self.assertNotRegex(self.page, r'(?:src|href)="https?://[^\"]+\.(?:js|css)')

    def test_broker_content_renderer_has_no_html_or_eval_sink(self):
        for name in ("app.js", "private.js"):
            js = (ROOT / "privacy_cleanup/static" / name).read_text()
            # Comments may name prohibited APIs; executable assignments/calls are absent.
            self.assertNotRegex(js, r'\.innerHTML\s*=|\beval\s*\(|insertAdjacentHTML\s*\(')
            self.assertIn("node.textContent = text", js)
