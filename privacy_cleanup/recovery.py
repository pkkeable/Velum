"""Explicit local encrypted recovery. No network, plaintext files or credential export."""
import argparse
import getpass
import json
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .domain import RuleError, canonical
from .paths import open_directory, check_file, validate_directory
from .vault import Vault, SessionVault, SCHEMA, WRAPPED, passphrase_bytes

MAGIC = b'VELUM-BACKUP\x01'
MAX_BYTES = 16 * 1024 * 1024
MAX_RECORDS = 102  # profile, workflow, up to 100 cases; never sender or recovery metadata.
RECORD = 'recovery'


def stamp():
    return datetime.now(timezone.utc).isoformat()


def _key(secret, salt):
    # Costs are fixed by the format, never taken from attacker-controlled input.
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(passphrase_bytes(secret, setting=True))


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def _bounded(value, depth=0):
    if depth > 24:
        raise ValueError()
    if isinstance(value, dict):
        if len(value) > 128:
            raise ValueError()
        for k, v in value.items():
            if not isinstance(k, str) or len(k) > 256:
                raise ValueError()
            _bounded(v, depth + 1)
    elif isinstance(value, list):
        if len(value) > 1000:
            raise ValueError()
        for v in value:
            _bounded(v, depth + 1)
    elif isinstance(value, str):
        if len(value) > 262144:
            raise ValueError()
    elif value is not None and type(value) not in (int, bool, float):
        raise ValueError()


def snapshot(vault, session):
    if vault.store != 'vault':
        raise RuleError('Save this session to an encrypted record before making a backup')
    with vault.mutex:
        vault._authorize(session)
        require_reconciled(vault)
        if vault.needs_upgrade():
            raise RuleError('Upgrade the synthetic store before making a backup')
        with vault.db:
            vault.db.execute('BEGIN IMMEDIATE')
            rows = vault.db.execute("SELECT id FROM records WHERE id NOT IN ('sender', 'recovery') ORDER BY id").fetchall()
            if not 1 <= len(rows) <= MAX_RECORDS:
                raise RuleError('Backup record limit exceeded')
            records = []
            for (identifier,) in rows:
                if identifier not in {'profile', 'workflow'} and not re.fullmatch(r'case/[0-9a-f]{32}', identifier):
                    raise RuleError('Unsupported record; backup refused')
                body, revision = vault._read_record(identifier)
                records.append({'id': identifier, 'revision': revision, 'body': body})
            return {'format': 1, 'schema': SCHEMA, 'created_at': stamp(), 'records': records}


def seal(manifest, secret):
    plaintext = canonical(manifest)
    if len(plaintext) > MAX_BYTES - 64:
        raise RuleError('Backup exceeds the supported size limit')
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    header = MAGIC + salt + nonce
    return header + AESGCM(_key(secret, salt)).encrypt(nonce, plaintext, header)


def unseal(blob, secret):
    if not isinstance(blob, bytes) or not len(MAGIC)+44 <= len(blob) <= MAX_BYTES or not blob.startswith(MAGIC):
        raise RuleError('Unsupported or damaged backup')
    end = len(MAGIC)
    header, salt, nonce = blob[:end+28], blob[end:end+16], blob[end+16:end+28]
    try:
        raw = AESGCM(_key(secret, salt)).decrypt(nonce, blob[end+28:], header)
        body = json.loads(raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _bounded(body)
        if set(body) != {'format', 'schema', 'created_at', 'records'} or type(body['format']) is not int or body['format'] != 1 or type(body['schema']) is not int or body['schema'] != SCHEMA:
            raise ValueError()
        if not isinstance(body['created_at'], str) or len(body['created_at']) > 40:
            raise ValueError()
        created = datetime.fromisoformat(body['created_at'])
        if created.tzinfo is None:
            raise ValueError()
        rows = body['records']
        if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_RECORDS:
            raise ValueError()
        seen = set()
        for row in rows:
            if not isinstance(row, dict) or set(row) != {'id', 'revision', 'body'}:
                raise ValueError()
            identifier = row['id']
            if not isinstance(identifier, str) or identifier in seen or (identifier not in {'profile', 'workflow'} and not re.fullmatch(r'case/[0-9a-f]{32}', identifier)):
                raise ValueError()
            if type(row['revision']) is not int or not 0 <= row['revision'] < 2**53 or not isinstance(row['body'], dict):
                raise ValueError()
            seen.add(identifier)
        if 'profile' not in seen:
            raise ValueError()
        return body
    except (InvalidTag, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise RuleError('Wrong backup passphrase or damaged/unsupported backup; nothing restored') from None


def write_archive(path, blob):
    path = Path(path).expanduser().absolute()
    parent, fd = open_directory(path.parent)
    temporary = '.velum-backup-' + secrets.token_hex(16)
    try:
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(out, 'wb') as stream:
            stream.write(blob)
            stream.flush()
            os.fsync(stream.fileno())
        # Atomic no-clobber publication; a crash leaves only encrypted bytes.
        os.link(temporary, path.name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass
        os.close(fd)


def read_archive(path):
    path = Path(path).expanduser().absolute()
    parent, fd = open_directory(path.parent)
    try:
        source = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(source, 'rb') as stream:
            info = os.fstat(stream.fileno())
            check_file(info)
            if info.st_size > MAX_BYTES:
                raise RuleError('Backup exceeds the supported size limit')
            blob = stream.read(MAX_BYTES + 1)
            if len(blob) > MAX_BYTES:
                raise RuleError('Backup exceeds the supported size limit')
            return blob
    finally:
        os.close(fd)


def export(vault, session, path, secret):
    write_archive(path, seal(snapshot(vault, session), secret))


def recovery_status(vault):
    if not vault.db.execute('SELECT 1 FROM records WHERE id=?', (RECORD,)).fetchone():
        return None
    body, _ = vault._read_record(RECORD)
    if set(body) != {'schema', 'restored_at', 'snapshot_at', 'reconciled_at'} or body['schema'] != 1:
        raise RuleError('Unsupported recovery record')
    return body


def require_reconciled(vault):
    status = recovery_status(vault)
    if status and status['reconciled_at'] is None:
        raise RuleError('Restored history is stale. Check activity since the backup, record missing or uncertain requests, then run recovery reconcile before preparing or sending requests')


def reconcile(vault, session, confirmation):
    if confirmation != 'RECONCILED':
        raise RuleError('Review missing activity and type RECONCILED to continue')
    with vault.mutex:
        vault._authorize(session)
        status = recovery_status(vault)
        if not status or status['reconciled_at'] is not None:
            raise RuleError('No pending recovery reconciliation')
        status['reconciled_at'] = stamp()
        with vault.db:
            vault.db.execute('BEGIN IMMEDIATE')
            _, revision = vault._read_record(RECORD)
            vault._write_record(RECORD, status, revision + 1)


def restore(blob, secret, directory, keys, vault_secret, *, open_vault=Vault):
    manifest = unseal(blob, secret)  # Validate before touching destination or Keychain.
    passphrase_bytes(vault_secret, setting=True)
    staging = SessionVault()
    try:
        token = staging.start()['session']
        with staging.db:
            for row in manifest['records']:
                body = row['body']
                if row['id'] == 'workflow':
                    body['paused'] = True
                if row['id'].startswith('case/'):
                    for field in ('past_requests', 'past_attempts', 'past_executions', 'history'):
                        items = body.get(field, [])
                        if not isinstance(items, list) or any(not isinstance(item, dict) for item in items):
                            raise ValueError()
                    for field in ('request', 'execution', 'attempt'):
                        if body.get(field) is not None and not isinstance(body[field], dict):
                            raise ValueError()
                    for field in ('request', 'execution'):
                        request = body.get(field)
                        unused = (field == 'request' and not body.get('attempt')) or (field == 'execution' and request and request.get('state') == 'prepared')
                        if request and unused:
                            request['approval'] = None
                            request['revoked'] = True
                staging._write_record(row['id'], body, row['revision'] + 1)
            staging._write_record(RECORD, {'schema': 1, 'snapshot_at': manifest['created_at'], 'restored_at': stamp(), 'reconciled_at': None}, 1)
        from .cases import Cases
        from .execution import Execution
        cases = Cases(staging)
        Execution(staging, cases, None)
        cases.state(token)  # Normal readers validate; interrupted dispatch becomes uncertain.
        cases.submissions(token)  # Historical records must also be readable before installation.
        records = staging.records(token)
    except (ValueError, KeyError, TypeError, AttributeError, RecursionError, OverflowError):
        raise RuleError('Damaged or unsupported backup records; nothing restored') from None
    finally:
        staging.close()
    directory = validate_directory(directory)
    # Only a new sibling directory; never adopt or overwrite an existing store.
    parent, fd = open_directory(directory.parent)
    vault = None
    identifier = None
    created = False
    try:
        os.mkdir(directory.name, 0o700, dir_fd=fd)
        created = True
        vault = open_vault(directory, keys)
        identifier = vault._meta()[0]
        key = AESGCM.generate_key(bit_length=256)
        vault._store_wrapped(identifier, key, passphrase_bytes(vault_secret, setting=True))
        vault.key = key
        with vault.mutex, vault.db:
            vault.db.execute('BEGIN IMMEDIATE')
            for record_id, body, revision in records:
                vault._write_record(record_id, body, revision)
            vault.db.execute("UPDATE meta SET status='active' WHERE id=1")
        vault.close()
        vault = None
        os.fsync(fd)
        return manifest['created_at']
    except BaseException:
        if vault:
            vault.close()
        if identifier:
            # A failed cleanup is surfaced; never conceal an orphaned wrapped key.
            keys.delete(identifier + WRAPPED)
        if created:
            # The failed directory is deliberately retained for inspection. It contains
            # only an empty shell or encrypted rolled-back data, never a usable restore.
            pass
        raise
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description='Synthetic-only local encrypted backup and restore. Stop the app first. Secrets are prompted, never command arguments.')
    parser.add_argument('action', choices=('export', 'restore', 'reconcile'))
    parser.add_argument('--data-dir', required=True, help='Explicit synthetic store; restore requires a nonexistent directory')
    parser.add_argument('--archive', help='Encrypted file in an owned mode-0700 non-Git directory; export never overwrites')
    parser.add_argument('--synthetic-workspace', action='store_true')
    args = parser.parse_args()
    from .private_server import is_personal_store
    if not args.synthetic_workspace or is_personal_store(args.data_dir):
        parser.error('Only explicit synthetic workspaces are allowed; personal storage remains disabled')
    if sys.platform != 'darwin' or sys.version_info < (3, 12):
        parser.error('Recovery CLI requires Python 3.12+ and native macOS Keychain; Linux uses synthetic test key stores only')
    if (args.action in {'export', 'restore'}) != bool(args.archive):
        parser.error('Use --archive only for export or restore')
    from .key_store import MacKeyStore
    from .network import install
    keys = MacKeyStore()
    install()
    vault = None
    try:
        if args.action == 'restore':
            blob = read_archive(args.archive)
            recovery_secret = getpass.getpass('Backup recovery passphrase: ')
            new_secret = getpass.getpass('New vault passphrase: ')
            if new_secret != getpass.getpass('Confirm new vault passphrase: '):
                raise RuleError('Passphrase confirmation does not match')
            restore(blob, recovery_secret, args.data_dir, keys, new_secret)
            print('Restored locked into the new store. No sending grants restored. History is stale: reconcile missing activity before any new requests.')
        else:
            if not Path(args.data_dir, 'vault.sqlite3').is_file():
                raise RuleError('Select an existing saved synthetic store')
            vault = Vault(args.data_dir, keys)
            token = vault.unlock(getpass.getpass('Vault passphrase: '))['session']
            if args.action == 'export':
                secret = getpass.getpass('Separate backup recovery passphrase (12+ characters): ')
                if secret != getpass.getpass('Confirm backup recovery passphrase: '):
                    raise RuleError('Passphrase confirmation does not match')
                export(vault, token, args.archive, secret)
                print('Encrypted backup saved. Keep its passphrase separately. Local deletion will not erase this copy. OAuth grants were excluded.')
            else:
                print('Check Sent mail and broker replies since the snapshot. In the app, record missing requests and reconcile uncertain attempts. This cannot verify external history; queues stay paused and exact approvals must be renewed.')
                reconcile(vault, token, input('After completing that review, type RECONCILED: '))
                print('Recovery reconciliation recorded; reconnect explicitly and review each new request. No queue was resumed.')
    except (RuleError, OSError, ValueError, KeyError, TypeError, RecursionError):
        raise SystemExit('Recovery failed safely. Check the secret, archive, supported version and private destination. Existing stores were not overwritten; inspect any new incomplete destination before retrying.') from None
    except (KeyboardInterrupt, EOFError):
        raise SystemExit('Recovery cancelled. No existing store was overwritten.') from None
    finally:
        if vault:
            vault.close()
