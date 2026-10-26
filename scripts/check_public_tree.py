"""Fail closed on unreviewed paths and obvious data leaks; never print matches.

This is a guardrail, not a comprehensive personal-data detector. Inspect diffs.
"""
import argparse
import hashlib
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PUBLIC_FILES = {
    '.githooks/pre-commit',
    '.github/ISSUE_TEMPLATE/bug_report.md',
    '.github/workflows/check.yml',
    '.gitignore',
    'AGENTS.md',
    'CONTRIBUTING.md',
    'LICENSE',
    'MANIFEST.in',
    'Makefile',
    'README.md',
    'SECURITY.md',
    'docs/ARCHITECTURE.md',
    'docs/COVERAGE.md',
    'docs/HISTORY.md',
    'docs/MAC_ACCEPTANCE.md',
    'docs/PRODUCT_SCOPE.md',
    'docs/RECOVERY.md',
    'docs/RELEASE.md',
    'docs/ROADMAP.md',
    'docs/SECURITY_REVIEW.md',
    'docs/SECURITY_VALIDATION.md',
    'docs/THREAT_MODEL.md',
    'docs/WALKTHROUGH.md',
    'fixtures/__init__.py',
    'fixtures/brokers.json',
    'fixtures/demo.json',
    'fixtures/manifest.sha256',
    'privacy_cleanup/THIRD_PARTY.md',
    'privacy_cleanup/__init__.py',
    'privacy_cleanup/__main__.py',
    'privacy_cleanup/adapters/__init__.py',
    'privacy_cleanup/adapters/mock.py',
    'privacy_cleanup/cases.py',
    'privacy_cleanup/contracts.py',
    'privacy_cleanup/dispatch.py',
    'privacy_cleanup/domain.py',
    'privacy_cleanup/engine.py',
    'privacy_cleanup/execution.py',
    'privacy_cleanup/gmail.py',
    'privacy_cleanup/identity.py',
    'privacy_cleanup/key_store.py',
    'privacy_cleanup/local_http.py',
    'privacy_cleanup/network.py',
    'privacy_cleanup/paths.py',
    'privacy_cleanup/private_server.py',
    'privacy_cleanup/recovery.py',
    'privacy_cleanup/requirements.py',
    'privacy_cleanup/routes.py',
    'privacy_cleanup/server.py',
    'privacy_cleanup/static/app.js',
    'privacy_cleanup/static/fonts/EBGaramond-wght.ttf',
    'privacy_cleanup/static/fonts/OFL.txt',
    'privacy_cleanup/static/index.html',
    'privacy_cleanup/static/private.html',
    'privacy_cleanup/static/private.js',
    'privacy_cleanup/static/style.css',
    'privacy_cleanup/storage.py',
    'privacy_cleanup/vault.py',
    'privacy_cleanup/worker.py',
    'privacy_cleanup/workflow.py',
    'privacy_cleanup/workspace.py',
    'pyproject.toml',
    'requirements-build.lock',
    'requirements-private-linux.lock',
    'requirements-private.lock',
    'scripts/__init__.py',
    'scripts/check_distribution.py',
    'scripts/check_installed.py',
    'scripts/check_public_tree.py',
    'scripts/check_release.py',
    'scripts/demo.py',
    'scripts/fake_provider.py',
    'scripts/keychain_check.py',
    'scripts/run_tests.py',
    'tests/private_ui.test.cjs',
    'tests/test_attention.py',
    'tests/test_boundaries.py',
    'tests/test_cases.py',
    'tests/test_coverage.py',
    'tests/test_engine.py',
    'tests/test_execution.py',
    'tests/test_gmail.py',
    'tests/test_identity.py',
    'tests/test_preview.py',
    'tests/test_privacy_modes.py',
    'tests/test_private.py',
    'tests/test_public_tree.py',
    'tests/test_recovery.py',
    'tests/test_requirements.py',
    'tests/test_security_validation.py',
    'tests/test_workflow.py',
}
EMAIL = re.compile(rb"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# Reviewed business recipients, each pinned from an official source and allowed only in the file
# that defines the route contract. This is not a general exception for real addresses.
REVIEWED = {"privacy@apollo.io", "privacy@cognism.com", "privacy@lusha.com", "support@contactout.com", "privacy@hunter.io"}
REVIEWED_RECIPIENTS = {"privacy_cleanup/contracts.py": REVIEWED, "scripts/check_public_tree.py": REVIEWED}
# Reviewed binaries, each pinned by SHA-256. EB Garamond (SIL Open Font License, OFL.txt beside it),
# downloaded 2026-10-11 from github.com/google/fonts ofl/ebgaramond/EBGaramond[wght].ttf.
PINNED_BINARIES = {"privacy_cleanup/static/fonts/EBGaramond-wght.ttf": "ef9512f92f6d579e5dc75af59a5a4b1b8b47d2eda89e00b954d44520e5369027"}
PINNED_LIMIT = 1000000
PATTERNS = [
    re.compile(rb"claude[.]" + rb"ai/|chatgpt[.]com/" + rb"codex", re.I),
    re.compile(rb"consulting " + rb"colors|privacy-cleanup-python312" + rb"-venv", re.I),
    re.compile(rb"pkkeable/" + rb"privacy-cleanup", re.I),
    re.compile(rb"\b\d{3}-\d{2}-\d{4}\b"),
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(rb"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
    re.compile(rb"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(rb"(?:/Users/|/home/)[A-Za-z][A-Za-z0-9._-]+/"),
]


def audit(files):
    failures = []
    for name, data in files.items():
        if name not in PUBLIC_FILES:
            failures.append("unapproved path (name withheld)")
            continue
        if name in PINNED_BINARIES:
            if len(data) > PINNED_LIMIT or hashlib.sha256(data).hexdigest() != PINNED_BINARIES[name]:
                failures.append("pinned binary changed; review required")
            continue
        if len(data) > 180000 or b"\0" in data:
            failures.append("binary or oversized artifact (contents withheld)")
        if any(p.search(data) for p in PATTERNS):
            failures.append("possible sensitive content (match withheld)")
        for match in EMAIL.finditer(data):
            domain = match.group(1).decode().lower()
            if match.group(0).decode().lower() in REVIEWED_RECIPIENTS.get(name, set()):
                continue
            if not (domain.endswith(".invalid") or domain in {"example.com", "example.org", "example.net"}):
                failures.append("non-example email (match withheld)")
    if "fixtures/manifest.sha256" in files:
        try:
            expected = {}
            for line in files["fixtures/manifest.sha256"].decode().splitlines():
                hash_value, name = line.split("  ", 1)
                expected[name] = hash_value
            if set(expected) != {"fixtures/demo.json", "fixtures/brokers.json"}:
                raise ValueError()
            for name, value in expected.items():
                if name not in files or hashlib.sha256(files[name]).hexdigest() != value:
                    failures.append("synthetic fixture seal changed; review required")
        except (ValueError, UnicodeError):
            failures.append("invalid synthetic fixture seal")
    else:
        failures.append("missing synthetic fixture seal")
    return failures


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], stderr=subprocess.DEVNULL)


def snapshot(rev):
    if rev == "index":
        entries = git("ls-files", "--stage", "-z").split(b"\0")
    else:
        entries = git("ls-tree", "-r", "-z", rev).split(b"\0")
    files = {}
    for entry in entries:
        if not entry:
            continue
        meta, name = entry.split(b"\t", 1)
        mode = meta.split()[0]
        path = name.decode()
        # Block symlinks and gitlinks without following or inspecting their targets.
        files[path] = (git("show", (":" if rev == "index" else rev + ":") + path)
                       if mode in {b"100644", b"100755"} else b"\0")
    return files


def working_files():
    files = {}
    for p in ROOT.rglob("*"):
        name = p.relative_to(ROOT).as_posix()
        parts = p.relative_to(ROOT).parts
        if ".git" in parts or "__pycache__" in parts or name == ".DS_Store":
            continue
        if p.is_symlink():
            files[name] = b"\0"  # Never follow a link into private storage.
        elif p.is_file():
            limit = PINNED_LIMIT if name in PINNED_BINARIES else 180000
            files[name] = p.read_bytes() if p.stat().st_size <= limit else b"\0"
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staged", action="store_true", help="Check the full Git index, not sanitized worktree replacements")
    parser.add_argument("--history", action="store_true", help="Also inspect every reachable commit, all refs")
    args = parser.parse_args()
    failures = audit(snapshot("index") if args.staged else working_files())
    # Even ignored files become visible if force-added to the index.
    if not args.staged:
        try:
            indexed = snapshot("index")
            if indexed:
                failures.extend(audit(indexed))
        except subprocess.CalledProcessError:
            failures.append("Git index could not be audited")
    if args.history:
        for rev in git("rev-list", "--all").decode().splitlines():
            failures.extend(audit(snapshot(rev)))
    if failures:
        for message in sorted(set(failures)):
            print("FAIL:", message)
        raise SystemExit(1)
    print("PASS: public paths, content checks and synthetic fixture seals; manual review still required")


if __name__ == "__main__":
    main()
