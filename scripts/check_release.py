"""Check version fields, local documentation links, claim IDs and Git attribution.

These are release guardrails, not a security audit. Never print matched private data.
"""
import ast
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent


def document_versions(name, text):
    # The owner-approved demo image is unchanged and remains on its published tag.
    # Exempt only this exact URL in the README, never surrounding version claims.
    if name == 'README.md':
        asset = 'https://github.com/pkkeable/Velum/releases/download/v0.5.1/velum-demo.png'
        text = re.sub(re.escape(asset) + r'(?=$|[\s"<>)])', '', text)
    return re.findall(r'(?<![\d.])0\.\d+\.\d+(?:a\d+|rc\d+)?\b', text)


def main():
    failures = []
    project = (ROOT / 'pyproject.toml').read_text()
    version = re.search(r'^version = "([^"]+)"', project, re.M).group(1)
    package = (ROOT / 'privacy_cleanup/__init__.py').read_text()
    if re.search(r'__version__\s*=\s*[\'"]([^\'"]+)', package).group(1) != version:
        failures.append('package and project versions differ')
    for name in ('README.md', 'SECURITY.md', 'docs/RELEASE.md'):
        text = (ROOT / name).read_text()
        versions = document_versions(name, text)
        if not versions or any(v != version for v in versions):
            failures.append('release version documentation differs: ' + name)
    for path in ROOT.rglob('*.md'):
        if '.git' in path.parts:
            continue
        for raw in re.findall(r'\]\(([^)]+)\)', path.read_text()):
            target = raw.strip('<>').split('#', 1)[0]
            if not target or re.match(r'^[a-z]+:', target):
                continue
            if not (path.parent / unquote(target)).exists():
                failures.append('broken local link in ' + str(path.relative_to(ROOT)))
    claims = (ROOT / 'docs/SECURITY_VALIDATION.md').read_text()
    refs = re.findall(r'`(tests/[^`]+\.py)::(\w+)::(test_\w+)`', claims)
    if len(refs) < 18:
        failures.append('claim map is incomplete')
    for file, cls, method in refs:
        tree = ast.parse((ROOT / file).read_text())
        if not any(isinstance(c, ast.ClassDef) and c.name == cls and any(isinstance(f, ast.FunctionDef) and f.name == method for f in c.body) for c in tree.body):
            failures.append('missing claim test: ' + file + '::' + cls + '::' + method)
    emails = subprocess.check_output(['git', 'log', '--all', '--format=%ae%n%ce'], cwd=ROOT).decode().splitlines()
    if any(not re.fullmatch(r'(?:[0-9]+\+)?[A-Za-z0-9-]+@users\.noreply\.github\.com|noreply@github\.com', email) for email in emails):
        failures.append('unapproved author/committer email (withheld)')
    if failures:
        for failure in sorted(set(failures)):
            print('FAIL:', failure)
        raise SystemExit(1)
    print('PASS: version, local links, claim IDs and commit attribution; manual review still required')


if __name__ == '__main__':
    main()
