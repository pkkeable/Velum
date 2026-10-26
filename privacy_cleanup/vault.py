"""Encrypted single-owner records. No fixtures, exports or networking."""
import fcntl
import hmac
import json
import os
import secrets
import sqlite3
import threading
import time
import unicodedata
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .domain import Mode, Profile, RuleError, canonical
from . import identity
from .paths import check_file, open_directory, validate_directory

SCHEMA = 5  # 5: emails record how they are used (identity record schema 2).
ENVELOPE = 1  # Preserve authentication context for existing v1 profile ciphertext.
FILES = {".vault.lock", "vault.sqlite3", "vault.sqlite3-journal", "vault.sqlite3-wal", "vault.sqlite3-shm"}

# The data key is stored in Keychain only after wrapping with a passphrase-derived
# key. Unlocking therefore needs something the owner knows, not just loopback access.
WRAPPED = ".wrapped-v1"  # Keychain account suffix; legacy raw keys use the bare vault ID.
WRAP_MAGIC = b"PCW1"
WRAP_LENGTH = len(WRAP_MAGIC) + 3 + 16 + 12 + 32 + 16
KDF_LOG2N = 17  # scrypt n=2**17, r=8, p=1: 128 MiB and roughly 0.5 s per attempt.
PASSPHRASE_MIN, PASSPHRASE_MAX = 12, 1024
DELETE_CONFIRMATION = "DELETE"


class PassphraseSetupRequired(RuleError):
    """A vault created before passphrases holds an unwrapped key; the owner must set one."""


def passphrase_bytes(value, setting=False):
    error = ("Use a vault passphrase of at least %d characters after Unicode normalization" % PASSPHRASE_MIN
             if setting else "Enter your vault passphrase")
    if not isinstance(value, str) or not 1 <= len(value) <= PASSPHRASE_MAX or any(not c.isprintable() for c in value):
        raise RuleError(error)
    normalized = unicodedata.normalize("NFC", value)
    # Enforce the minimum when setting a secret. Unlock must still accept an
    # equivalent spelling of a previously accepted, shorter normalized secret.
    if len(normalized) < (PASSPHRASE_MIN if setting else 1):
        raise RuleError(error)
    return normalized.encode()


def default_directory():
    return Path.home() / "Library/Application Support/PrivacyCleanup/private"


class Vault:
    mode = Mode.PRIVATE
    store = "vault"

    def __init__(self, directory, keys, idle_seconds=900, clock=time.monotonic, wall=time.time, kdf_log2n=KDF_LOG2N):
        self.mutex = threading.RLock()
        self.keys, self.idle_seconds, self.clock, self.wall = keys, idle_seconds, clock, wall
        if not 14 <= kdf_log2n <= 20:
            raise RuleError("Unsupported key-derivation cost")
        self.kdf_log2n = kdf_log2n
        self.failures, self.retry_at = 0, None
        self.key = self.session = None
        self.directory_fd = self.lock_fd = self.db = None
        try:
            self.directory, self.directory_fd = open_directory(directory)
            self.dir_identity = self._identity(os.fstat(self.directory_fd))
            self._check_files()
            self.lock_fd = os.open(".vault.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.directory_fd)
            check_file(os.fstat(self.lock_fd))
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise RuleError("This private vault is already open in another process") from None
            fd = os.open("vault.sqlite3", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=self.directory_fd)
            try:
                check_file(os.fstat(fd))
                self.db_identity = self._identity(os.fstat(fd))
            finally:
                os.close(fd)
            self.db = sqlite3.connect(str(self.directory / "vault.sqlite3"), check_same_thread=False)
            self._guard_files()
            self.db.execute("PRAGMA temp_store=MEMORY")
            self.db.execute("PRAGMA secure_delete=ON")
            self._migrate()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _identity(info):
        return info.st_dev, info.st_ino

    def _check_files(self):
        for name in os.listdir(self.directory_fd):
            if name not in FILES:
                raise RuleError("Use an empty dedicated private directory, separate from the demo")
            check_file(os.stat(name, dir_fd=self.directory_fd, follow_symlinks=False))

    def _guard_files(self):
        try:
            self._verify_files()
        except (OSError, RuleError):
            self.lock()
            raise

    def _verify_files(self):
        validate_directory(self.directory)
        if self._identity(self.directory.stat()) != self.dir_identity:
            self.lock()
            raise RuleError("Private directory changed; close the application")
        self._check_files()
        if self._identity(os.stat("vault.sqlite3", dir_fd=self.directory_fd, follow_symlinks=False)) != self.db_identity:
            self.lock()
            raise RuleError("Private database changed; close the application")

    def _migrate(self):
        version = self.db.execute("PRAGMA user_version").fetchone()[0]
        if version not in {0, 1, 2, 3, 4, SCHEMA}:
            raise RuleError("Unsupported private database version; use the matching application")
        if version == 0:
            if self.db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchone():
                raise RuleError("This is not an empty private database")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                self.db.execute("CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), vault_id TEXT NOT NULL, status TEXT NOT NULL)")
                self.db.execute("CREATE TABLE records (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, nonce BLOB NOT NULL, body BLOB NOT NULL)")
                self.db.execute("CREATE TABLE used_nonces (nonce BLOB PRIMARY KEY)")
                self.db.execute("INSERT INTO meta VALUES (1, ?, 'empty')", (secrets.token_hex(16),))
                self.db.execute("PRAGMA user_version=%d" % SCHEMA)
        if self._meta()[1] not in {"empty", "active", "deleting"}:
            raise RuleError("Invalid vault metadata")
        # Older encrypted stores are not rewritten on startup or unlock. The
        # owner must explicitly request migration after authenticating.

    def needs_upgrade(self):
        return self.db.execute("PRAGMA user_version").fetchone()[0] < SCHEMA

    def _meta(self):
        row = self.db.execute("SELECT vault_id, status FROM meta WHERE id=1").fetchone()
        if not row or len(row[0]) != 32 or any(c not in "0123456789abcdef" for c in row[0]):
            raise RuleError("Invalid vault metadata")
        return row

    def _aad(self, revision, record_id="profile"):
        return canonical(["privacy-cleanup", ENVELOPE, self._meta()[0], record_id, revision])

    def _write(self, body, revision):
        self._write_record("profile", body, revision)

    def _write_record(self, record_id, body, revision):
        # Called inside the caller's transaction; a used nonce is never reclaimed.
        for _ in range(8):
            nonce = secrets.token_bytes(12)
            try:
                self.db.execute("INSERT INTO used_nonces VALUES (?)", (nonce,))
                break
            except sqlite3.IntegrityError:
                continue
        else:
            raise RuleError("Encryption nonce allocation failed; no profile was changed")
        encrypted = AESGCM(self.key).encrypt(nonce, canonical(body), self._aad(revision, record_id))
        self.db.execute("INSERT OR REPLACE INTO records VALUES (?, ?, ?, ?)", (record_id, revision, nonce, encrypted))

    def _read_record(self, record_id):
        row = self.db.execute("SELECT revision, nonce, body FROM records WHERE id=?", (record_id,)).fetchone()
        if not row:
            raise RuleError("Encrypted record is missing")
        revision, nonce, encrypted = row
        try:
            body = json.loads(AESGCM(self.key).decrypt(nonce, encrypted, self._aad(revision, record_id)))
            if not isinstance(body, dict):
                raise ValueError()
        except (InvalidTag, ValueError, TypeError):
            self.lock()
            raise RuleError("Vault authentication failed; records were not opened") from None
        return body, revision

    def _read(self):
        body, revision = self._read_record("profile")
        try:
            if not isinstance(body, dict) or set(body) != {"profile"}:
                raise ValueError()
            if body["profile"] is not None:
                version = self.db.execute("PRAGMA user_version").fetchone()[0]
                if version < 3:
                    Profile.parse(body["profile"])
                elif version < SCHEMA:
                    # Shown in the current shape until the owner upgrades; nothing is written.
                    body["profile"] = identity.upgrade(body["profile"])
                else:
                    identity.validate(body["profile"])
        except (InvalidTag, ValueError, TypeError):
            self.lock()
            raise RuleError("Vault authentication failed; records were not opened") from None
        return {"profile": body["profile"], "version": revision,
                "migration_required": self.needs_upgrade(),
                "warnings": identity.warnings(body["profile"]) if body["profile"] and not self.needs_upgrade() else []}

    def upgrade_identity(self, session, version, acknowledged):
        with self.mutex:
            self._authorize(session)
            if acknowledged is not True:
                raise RuleError("Review the identity upgrade before continuing")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                old = self._read()
                if not old["migration_required"] or type(version) is not int or old["version"] != version:
                    raise RuleError("Vault version changed; reload before upgrading")
                profile = old["profile"]
                if profile and self.db.execute("PRAGMA user_version").fetchone()[0] < 3:
                    profile = identity.from_legacy(profile)
                if profile:
                    # Every email's use starts unknown; it is never guessed from a domain.
                    profile = identity.upgrade(profile)
                # Incrementing the profile revision invalidates every unused
                # request approval. Cases, attempts and exact snapshots stay intact.
                self._write({"profile": profile}, version + 1)
                self.db.execute("PRAGMA user_version=%d" % SCHEMA)
            return self.read(session)

    def lock(self):
        with self.mutex:
            self.key = self.session = None

    def due(self):
        """True when the open session has idled out, or a clock jump makes its age unknowable."""
        with self.mutex:
            if not self.session:
                return False
            mono = self.clock() - self.last_active
            wall = self.wall() - self.last_wall
            return max(mono, wall) >= self.idle_seconds or min(mono, wall) < 0 or wall - mono > 5

    def expire(self):
        with self.mutex:
            if self.due():
                self.lock()

    def _session_matches(self, session):
        return bool(self.session and isinstance(session, str) and
                    hmac.compare_digest(self.session.encode(), session.encode()))

    def _authorize(self, session, touch=False):
        self.expire()
        self._guard_files()
        if self._meta()[1] != "active" or not self._session_matches(session):
            raise RuleError("Vault is locked or this session expired; unlock again")
        if touch:
            self.last_active, self.last_wall = self.clock(), self.wall()

    def remaining(self):
        """Seconds until idle expiry, or None when no session is open."""
        with self.mutex:
            if not self.session:
                return None
            idle = max(self.clock() - self.last_active, self.wall() - self.last_wall)
            return max(0, int(self.idle_seconds - idle))

    def status(self, session=None):
        with self.mutex:
            self.expire()
            self._guard_files()
            status = self._meta()[1]
            # session_valid lets a tab whose session was replaced clear itself.
            return {"mode": self.mode.value, "store": self.store, "locked": self.session is None,
                    "initialized": status != "empty", "deletion_pending": status == "deleting",
                    "idle_seconds": self.idle_seconds, "remaining_seconds": self.remaining(),
                    "session_valid": self._session_matches(session)}

    # Key wrapping. Keychain holds only the wrapped data key; the passphrase is never stored.

    @staticmethod
    def _wrap_aad(identifier, header):
        return canonical(["privacy-cleanup-key-wrap", 1, identifier]) + header

    @staticmethod
    def _kek(salt, log2n, secret):
        return Scrypt(salt=salt, length=32, n=2 ** log2n, r=8, p=1).derive(secret)

    def _store_wrapped(self, identifier, key, secret):
        salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
        header = WRAP_MAGIC + bytes([self.kdf_log2n, 8, 1]) + salt
        sealed = AESGCM(self._kek(salt, self.kdf_log2n, secret)).encrypt(nonce, key, self._wrap_aad(identifier, header))
        blob = header + nonce + sealed
        # A new account name, never an overwrite: keyring replaces items by delete-then-add.
        self.keys.put(identifier + WRAPPED, blob)
        if self.keys.get(identifier + WRAPPED) != blob:
            raise RuleError("Keychain could not store the protected vault key; nothing was changed")

    def _unwrap(self, identifier, blob, secret):
        if not isinstance(blob, bytes) or len(blob) != WRAP_LENGTH or not blob.startswith(WRAP_MAGIC):
            raise RuleError("The protected vault key is invalid")
        log2n, r, p = blob[4:7]
        if not 14 <= log2n <= 20 or (r, p) != (8, 1):
            raise RuleError("The protected vault key is invalid")
        header, nonce, sealed = blob[:23], blob[23:35], blob[35:]
        try:
            key = AESGCM(self._kek(blob[7:23], log2n, secret)).decrypt(nonce, sealed, self._wrap_aad(identifier, header))
        except InvalidTag:
            self.failures += 1
            if self.failures >= 3:
                self.retry_at = self.clock() + min(300, 2 ** (self.failures - 3))
            raise RuleError("That passphrase does not unlock this vault") from None
        self.failures, self.retry_at = 0, None
        return key

    def _retire_legacy(self, identifier):
        try:
            if self.keys.get(identifier) is not None:
                self.keys.delete(identifier)
            return True
        except RuleError:
            return False

    def _open(self, key, create=False, retire=None):
        """Verify the key against stored records, then start the single unlock session."""
        if not isinstance(key, bytes) or len(key) != 32:
            raise RuleError("Vault key is invalid")
        self.key = key
        try:
            if create:
                with self.db:
                    self.db.execute("BEGIN IMMEDIATE")
                    self._write({"profile": None}, 0)
                    self.db.execute("UPDATE meta SET status='active' WHERE id=1")
            self._read()
        except BaseException:
            self.lock()
            raise
        notice = {}
        if retire is not None and not self._retire_legacy(retire):
            notice["notice"] = "The old unprotected Keychain entry could not be removed yet; it is retried at every unlock."
        self.session = secrets.token_urlsafe(32)
        self.last_active, self.last_wall = self.clock(), self.wall()
        return {**notice, "session": self.session, **self.read(self.session)}

    def unlock(self, passphrase, create=False):
        with self.mutex:
            self.lock()
            self._guard_files()
            identifier, status = self._meta()
            if status == "deleting":
                raise RuleError("Finish the pending local deletion first")
            if (status == "empty") != create:
                raise RuleError("Vault state changed; refresh before continuing")
            if self.retry_at is not None and self.clock() < self.retry_at:
                raise RuleError("Too many incorrect passphrases; wait a moment before trying again")
            secret = passphrase_bytes(passphrase, setting=create)
            if create:
                # An empty vault never encrypted anything, so a key still filed under its current
                # ID (left by an interrupted creation) is an orphan: remove it first. A failure
                # stops creation, so orphans never accumulate.
                for name in (identifier + WRAPPED, identifier):
                    if self.keys.get(name) is not None:
                        self.keys.delete(name)
                # A fresh identifier for every creation: never adopt a pre-existing Keychain key.
                identifier = secrets.token_hex(16)
                with self.db:
                    self.db.execute("BEGIN IMMEDIATE")
                    self.db.execute("UPDATE meta SET vault_id=? WHERE id=1 AND status='empty'", (identifier,))
                key = AESGCM.generate_key(bit_length=256)
                self._store_wrapped(identifier, key, secret)
                try:
                    return self._open(key, create=True)
                except BaseException:
                    try:
                        self.keys.delete(identifier + WRAPPED)
                    except RuleError:
                        pass
                    raise
            wrapped = self.keys.get(identifier + WRAPPED)
            if wrapped is None:
                if self.keys.get(identifier) is not None:
                    raise PassphraseSetupRequired("This vault was created before passphrases. Set a passphrase to protect it.")
                raise RuleError("Vault key is missing; encrypted records cannot be recovered without it")
            return self._open(self._unwrap(identifier, wrapped, secret), retire=identifier)

    def set_passphrase(self, passphrase):
        """One-time upgrade of a legacy vault: wrap its existing key, then remove the raw copy."""
        with self.mutex:
            self.lock()
            self._guard_files()
            identifier, status = self._meta()
            if status != "active":
                raise RuleError("Vault state changed; refresh before continuing")
            secret = passphrase_bytes(passphrase, setting=True)
            if self.keys.get(identifier + WRAPPED) is not None:
                raise RuleError("This vault already has a passphrase; unlock with it")
            key = self.keys.get(identifier)
            if key is None:
                raise RuleError("Vault key is missing; encrypted records cannot be recovered without it")
            if not isinstance(key, bytes) or len(key) != 32:
                raise RuleError("Vault key is invalid")
            self.key = key  # Prove the legacy key opens the records before wrapping it.
            try:
                self._read()
            finally:
                self.lock()
            self._store_wrapped(identifier, key, secret)
            return self._open(key, retire=identifier)

    def read(self, session):
        with self.mutex:
            self._authorize(session)
            return self._read()

    def touch(self, session):
        with self.mutex:
            self._authorize(session, touch=True)

    def save(self, session, fields, version):
        with self.mutex:
            self._authorize(session)
            if self.needs_upgrade():
                raise RuleError("Upgrade this synthetic workspace before editing its identity")
            with self.db:
                self.db.execute("BEGIN IMMEDIATE")
                old = self._read()
                if type(version) is not int or version != old["version"]:
                    raise RuleError("Profile changed; reload before saving")
                profile = identity.validate(fields, previous=old["profile"])
                self._write({"profile": profile}, version + 1)
            self.last_active, self.last_wall = self.clock(), self.wall()
            return self.read(session)

    def check_delete(self, session, confirmation, version):
        """Everything deletion depends on, checked before anything (Google access included) changes."""
        with self.mutex:
            self._guard_files()
            if confirmation != DELETE_CONFIRMATION:
                raise RuleError("Type DELETE to confirm")
            if self._meta()[1] != "deleting":
                self._authorize(session)
                if type(version) is not int or version != self._read()["version"]:
                    raise RuleError("Your records changed on another page; reload before deleting")

    def delete(self, session, confirmation, version):
        with self.mutex:
            self.check_delete(session, confirmation, version)
            identifier, status = self._meta()
            if status != "deleting":
                with self.db:
                    self.db.execute("UPDATE meta SET status='deleting' WHERE id=1")
            self.lock()
            # A persisted tombstone blocks reads after a crash or failed key removal.
            self.keys.delete(identifier + WRAPPED)
            self.keys.delete(identifier)
            with self.db:
                self.db.execute("DELETE FROM records")
                self.db.execute("DELETE FROM used_nonces")
                self.db.execute("UPDATE meta SET vault_id=?, status='empty' WHERE id=1", (secrets.token_hex(16),))
            return self.status()

    def close(self):
        with self.mutex:
            self.lock()
            if self.db is not None:
                self.db.close()
                self.db = None
            for name in ("lock_fd", "directory_fd"):
                fd = getattr(self, name, None)
                if fd is not None:
                    os.close(fd)
                    setattr(self, name, None)


class SessionVault(Vault):
    """The "Nothing is kept" store. Records live in an in-memory SQLite database, encrypted
    under a key generated for this session alone. No directory, file or Keychain entry is
    ever created. Ending the session, idle expiry, a crash or quitting erases everything.

    Memory is not perfect erasure: the OS can swap pages or write crash reports. The product
    copy says so. This class only guarantees that Velum itself writes nothing to disk."""
    store = "session"

    def __init__(self, idle_seconds=1800, clock=time.monotonic, wall=time.time):
        self.mutex = threading.RLock()
        self.keys, self.idle_seconds, self.clock, self.wall = None, idle_seconds, clock, wall
        self.kdf_log2n, self.failures, self.retry_at = KDF_LOG2N, 0, None
        self.key = self.session = None
        self.directory_fd = self.lock_fd = self.db = None
        self.stale = False
        self.before_expire = None  # Workspace-owned revoke-before-erase callback.
        self.ended = None  # How the last session ended; never personal data.
        self._fresh()

    def _fresh(self):
        if self.db is not None:
            self.db.close()
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.execute("PRAGMA temp_store=MEMORY")
        with db:
            db.execute("CREATE TABLE meta (id INTEGER PRIMARY KEY CHECK(id=1), vault_id TEXT NOT NULL, status TEXT NOT NULL)")
            db.execute("CREATE TABLE records (id TEXT PRIMARY KEY, revision INTEGER NOT NULL, nonce BLOB NOT NULL, body BLOB NOT NULL)")
            db.execute("CREATE TABLE used_nonces (nonce BLOB PRIMARY KEY)")
            db.execute("INSERT INTO meta VALUES (1, ?, 'empty')", (secrets.token_hex(16),))
            db.execute("PRAGMA user_version=%d" % SCHEMA)
        self.db, self.stale = db, False

    def _settle(self):
        # An erase requested inside an open transaction happens once it closes.
        if self.stale and not self.db.in_transaction:
            self._fresh()

    def _guard_files(self):
        self._settle()

    def lock(self):
        """Without its key nothing is readable; drop the database too."""
        with self.mutex:
            self.key = self.session = None
            if self.db is not None:
                self.stale = True
                self._settle()

    def expire(self):
        with self.mutex:
            if self.due():
                revoked = None
                try:
                    revoked = self.before_expire() if self.before_expire else None
                except Exception:
                    revoked = False
                finally:
                    self.lock()
                self.ended = {"reason": "idle", "revoked": revoked}

    def start(self):
        """Erase anything left from an earlier session, then open a new empty one."""
        with self.mutex:
            self.lock()
            self._settle()
            self.ended = None
            return self._open(AESGCM.generate_key(bit_length=256), create=True)

    def end(self, session, reason="ended", revoked=None):
        with self.mutex:
            if session is not None:
                self._authorize(session)
            self.lock()
            self.ended = {"reason": reason, "revoked": revoked}

    def records(self, session):
        """Every decrypted record, for moving this session into an encrypted vault."""
        with self.mutex:
            self._authorize(session)
            rows = self.db.execute("SELECT id FROM records ORDER BY id").fetchall()
            return [(identifier, *self._read_record(identifier)) for (identifier,) in rows]

    def status(self, session=None):
        with self.mutex:
            self.expire()
            self._settle()
            return {"mode": self.mode.value, "store": self.store, "locked": self.session is None,
                    "initialized": self.session is not None, "deletion_pending": False,
                    "idle_seconds": self.idle_seconds, "remaining_seconds": self.remaining(),
                    "session_valid": self._session_matches(session), "ended": self.ended}

    def unlock(self, passphrase, create=False):
        raise RuleError("Nothing is kept in this mode, so there is nothing to unlock; start a new session")

    def set_passphrase(self, passphrase):
        raise RuleError("Nothing is kept in this mode, so there is no passphrase")

    def delete(self, session, confirmation, version):
        raise RuleError("End the session instead; it erases everything")

    def close(self):
        with self.mutex:
            self.key = self.session = None
            if self.db is not None:
                self.db.close()
                self.db = None
