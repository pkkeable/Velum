import hashlib
import unittest
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from scripts.check_public_tree import audit, snapshot
from scripts.check_distribution import check as check_wheel


def safe_files():
    files = {"fixtures/demo.json": b'{"synthetic":true}', "fixtures/brokers.json": b"{}"}
    files["fixtures/manifest.sha256"] = "\n".join(hashlib.sha256(data).hexdigest() + "  " + name for name, data in files.items()).encode()
    return files


class PublicTreeTests(unittest.TestCase):
    def test_distribution_rejects_runtime_content_and_metadata_leaks(self):
        import zipfile
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "synthetic.whl"
            def write(extra):
                with zipfile.ZipFile(wheel, "w") as archive:
                    for name, data in safe_files().items():
                        archive.writestr("privacy_cleanup/" + name, data)
                    for name, data in extra.items(): archive.writestr(name, data)
            write({})
            self.assertFalse(check_wheel(wheel))
            write({"private/profile.json":b"synthetic runtime"})
            self.assertTrue(check_wheel(wheel))
            write({"privacy_cleanup_local-0.2.0a1.dist-info/METADATA":b"sentinel"+b"@"+b"unapproved.invalid-domain.com"})
            errors = check_wheel(wheel)
            self.assertTrue(errors)
            self.assertNotIn("sentinel", " ".join(errors))
            # Review L-5: a root README.md used to be overwritten by the metadata scan key.
            write({"README.md": b"sentinel" + b"@" + b"unapproved.invalid-domain.com"})
            self.assertTrue(check_wheel(wheel))

    def test_only_the_pinned_font_passes_as_a_binary(self):
        from scripts.check_public_tree import PINNED_BINARIES
        name = "privacy_cleanup/static/fonts/EBGaramond-wght.ttf"
        font = (Path(__file__).resolve().parent.parent / name).read_bytes()
        self.assertEqual(hashlib.sha256(font).hexdigest(), PINNED_BINARIES[name])
        self.assertEqual(audit({**safe_files(), name: font}), [])
        self.assertEqual(audit({**safe_files(), name: font[:-1] + b"x"}), ["pinned binary changed; review required"])
        self.assertTrue(audit({**safe_files(), "privacy_cleanup/static/private.js": b"\0binary"}))
        import zipfile
        with tempfile.TemporaryDirectory() as temp:
            wheel = Path(temp) / "synthetic.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                for item, data in safe_files().items():
                    archive.writestr("privacy_cleanup/" + item, data)
                archive.writestr(name, font)
            self.assertFalse(check_wheel(wheel))

    def test_synthetic_bundle_passes(self):
        self.assertEqual(audit(safe_files()), [])

    def test_runtime_material_rejected_even_if_force_added(self):
        for name in ("runtime/state.sqlite3", "screenshots/demo.png", ".env", "exports/profile.json", "browser/session.json"):
            files = safe_files(); files[name] = b"fictional but still runtime material"
            self.assertTrue(audit(files))

    def test_fixture_modification_requires_explicit_review(self):
        files = safe_files(); files["fixtures/demo.json"] = b'{"synthetic":false}'
        self.assertIn("synthetic fixture seal changed; review required", audit(files))

    def test_email_in_allowed_code_detected_without_echoing_match(self):
        files = safe_files(); files["README.md"] = b"sentinel" + b"@" + b"unapproved.invalid-domain.com"
        errors = audit(files)
        self.assertTrue(errors)
        self.assertNotIn("sentinel", " ".join(errors))

    def test_reviewed_recipient_is_allowed_only_in_its_contract_file(self):
        address = b"privacy" + b"@" + b"apollo.io"
        files = safe_files(); files["privacy_cleanup/contracts.py"] = address
        self.assertEqual(audit(files), [])
        for name in ("README.md", "tests/test_execution.py", "docs/ARCHITECTURE.md"):
            files = safe_files(); files[name] = address
            self.assertIn("non-example email (match withheld)", audit(files), name)

    def test_identifier_and_private_key_patterns(self):
        for data in (b"123" + b"-45-" + b"6789", b"-----BEGIN " + b"PRIVATE KEY-----"):
            files = safe_files(); files["README.md"] = data
            self.assertTrue(audit(files))

    def test_unknown_path_and_binary_rejected(self):
        for name, data in (("profile.txt", b"private"), ("README.md", b"\0")):
            files = safe_files(); files[name] = data
            self.assertTrue(audit(files))

    def test_actual_index_catches_force_added_runtime_and_sanitized_worktree(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args):
                return subprocess.run(["git", "-C", temp, *args], check=True, capture_output=True)
            git("init")
            for name, data in safe_files().items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(data)
            (root / ".gitignore").write_text("runtime/\n")
            (root / "runtime").mkdir()
            (root / "runtime/state.sqlite3").write_bytes(b"synthetic runtime forbidden in Git")
            (root / "README.md").write_bytes(b"sentinel" + b"@" + b"unapproved.invalid-domain.com")
            git("add", "."); git("add", "-f", "runtime/state.sqlite3")
            (root / "README.md").write_text("sanitized working copy")
            with patch("scripts.check_public_tree.ROOT", root):
                errors = audit(snapshot("index"))
            self.assertIn("non-example email (match withheld)", errors)
            self.assertIn("unapproved path (name withheld)", errors)

    def test_staged_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            subprocess.run(["git", "init", temp], check=True, capture_output=True)
            (root / "README.md").symlink_to("../unread-private-file")
            subprocess.run(["git", "-C", temp, "add", "README.md"], check=True, capture_output=True)
            with patch("scripts.check_public_tree.ROOT", root):
                errors = audit(snapshot("index"))
            self.assertIn("binary or oversized artifact (contents withheld)", errors)
