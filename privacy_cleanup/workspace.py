"""The one store this process serves: nothing chosen yet, a session-only store, or the
encrypted vault. Session-only ("Nothing is kept") is the default and never touches the data
directory or the Keychain; the vault is opened only when the owner chooses it or one exists.
"""
import threading
from pathlib import Path

from .cases import Cases
from .domain import RuleError
from .execution import Execution
from .vault import SessionVault, Vault
from .workflow import Workflow


class Parts:
    """A store and the services bound to it."""
    def __init__(self, store, worker):
        self.store = store
        self.cases = Cases(store)
        self.execution = Execution(store, self.cases, worker)
        self.workflow = Workflow(store, self.cases)


class Workspace:
    def __init__(self, data_dir=None, keys=None, worker=None, vault=None, session_store=None, open_vault=Vault):
        self.mutex = threading.RLock()
        self.data_dir, self.keys, self.worker, self.open_vault = data_dir, keys, worker, open_vault
        self.session = Parts(session_store or SessionVault(), worker)
        self.session.store.before_expire = self._release_session
        self.vault = None
        if vault is None and data_dir is not None and (Path(data_dir) / "vault.sqlite3").exists():
            vault = open_vault(data_dir, keys)
        if vault is not None:
            self.vault = Parts(vault, worker)
        # An existing record (or an interrupted deletion) is offered first; otherwise the
        # owner chooses on the first-run screen.
        self.active = "vault" if self.vault and self.vault.store.status()["initialized"] else None

    # The active store and its services.

    def _resolve(self):
        # A record that exists is offered whenever no session-only workspace is open.
        if self.active is None and self.vault and self.vault.store.status()["initialized"]:
            self.active = "vault"

    @property
    def parts(self):
        with self.mutex:
            self._resolve()
            if self.active == "session":
                return self.session
            if self.active == "vault":
                return self.vault
            raise RuleError("Choose what Velum keeps before continuing")

    def status(self, token=None):
        with self.mutex:
            self._resolve()
            vault_status = self.vault.store.status(token if self.active == "vault" else None) if self.vault else None
            vault_exists = bool(vault_status and vault_status["initialized"])
            if self.active == "session":
                result = self.session.store.status(token)
            elif self.active == "vault":
                result = vault_status
            else:
                result = {"mode": "private-local", "store": None, "locked": True, "initialized": False,
                          "deletion_pending": False, "idle_seconds": None, "remaining_seconds": None,
                          "session_valid": False, "ended": self.session.store.ended}
            return {**result, "vault_exists": vault_exists}

    def _need_vault(self):
        if self.vault is None:
            if self.data_dir is None:
                raise RuleError("No directory is configured for an encrypted record")
            self.vault = Parts(self.open_vault(self.data_dir, self.keys), self.worker)
        return self.vault

    # Choosing and opening a store.

    def start_session(self):
        with self.mutex:
            if self.vault and self.vault.store.status()["initialized"]:
                if self.vault.store.session:
                    raise RuleError("Lock your encrypted record before starting a session without saving")
            if self.session.store.session is not None:
                self._expire_session("replaced")
            self.active = "session"
            return self.session.store.start()

    def create_vault(self, passphrase):
        with self.mutex:
            self._refuse_open_session()
            parts = self._need_vault()
            result = parts.store.unlock(passphrase, create=True)
            self.active = "vault"
            return result

    def unlock_vault(self, passphrase):
        with self.mutex:
            self._refuse_open_session()
            if not self.vault:
                raise RuleError("There is no encrypted record on this Mac yet")
            result = self.vault.store.unlock(passphrase)
            self.active = "vault"
            return result

    def set_passphrase(self, passphrase):
        with self.mutex:
            self._refuse_open_session()
            if not self.vault:
                raise RuleError("There is no encrypted record on this Mac yet")
            result = self.vault.store.set_passphrase(passphrase)
            self.active = "vault"
            return result

    def _refuse_open_session(self):
        if self.active == "session" and self.session.store.session:
            raise RuleError("End this session first, or keep it by switching it to an encrypted record")

    # Ending, locking and deleting: check, then revoke Google access, then erase.

    def end_session(self, token):
        with self.mutex:
            store, gmail = self.session.store, self.session.execution.gmail
            with store.mutex:
                store._authorize(token)
                revoked = gmail.release() if gmail and gmail.connected() else None
                store.end(token, revoked=revoked)
            self.active = None
            return {**self.status(), "revoked": revoked}

    def lock(self):
        with self.mutex:
            if self.active == "session":
                self._expire_session("locked")
            elif self.vault:
                self.vault.store.lock()
            return self.status()

    def delete_vault(self, token, confirmation, version):
        with self.mutex:
            if self.active != "vault" or not self.vault:
                raise RuleError("There is no encrypted record open to delete")
            store, gmail = self.vault.store, self.vault.execution.gmail
            with store.mutex:
                store.check_delete(token, confirmation, version)
                revoked = gmail.release() if gmail and store.key is not None and gmail.connected() else None
                store.delete(token, confirmation, version)
            self.active = None
            return {**self.status(), "revoked": revoked}

    def convert(self, token, passphrase):
        """Keep this session: move its records into a new encrypted record, then erase the session."""
        with self.mutex:
            if self.active != "session":
                raise RuleError("Only a session without saving can be switched to an encrypted record")
            session = self.session
            with session.store.mutex:
                session.store._authorize(token)
                execution, gmail = session.execution, session.execution.gmail
                if execution.inflight or execution.pending:
                    raise RuleError("Wait until sending finishes before switching")
                if gmail and gmail.flow["state"] in {"waiting", "exchanging"}:
                    raise RuleError("Finish or cancel connecting Gmail before switching")
                records = session.store.records(token)
                parts = self._need_vault()
                if parts.store.status()["initialized"]:
                    raise RuleError("An encrypted record already exists on this Mac; unlock it instead")
                result = parts.store.unlock(passphrase, create=True)
                store = parts.store
                with store.mutex, store.db:
                    store.db.execute("BEGIN IMMEDIATE")
                    for identifier, body, revision in records:
                        store._write_record(identifier, body, revision)
                # The Gmail grant moved with the records, so it is not revoked.
                session.store.end(token, reason="converted")
            self.active = "vault"
            return {**result, **store.read(result["session"]), "session": result["session"]}

    # Idle expiry, run by the server loop.

    def _release_session(self):
        # Called under the store lock too: never acquire the workspace lock here.
        gmail = self.session.execution.gmail
        try:
            return gmail.release() if gmail else None
        except Exception:  # Erasing must not depend on reaching Google.
            return False

    def _expire_session(self, reason):
        store = self.session.store
        with store.mutex:
            revoked = self._release_session()
            store.lock()
        store.ended = {"reason": reason, "revoked": revoked}
        self.active = None

    def fail(self):
        """After an unexpected error: lock the encrypted record, erase a session-only one."""
        with self.mutex:
            if self.active == "session":
                self._expire_session("error")
            if self.vault:
                self.vault.store.lock()

    def service(self):
        with self.mutex:
            if self.active == "session":
                store = self.session.store
                if store.due():
                    self._expire_session("idle")
                else:
                    store.expire()
            if self.vault:
                self.vault.store.expire()

    def close(self):
        with self.mutex:
            if self.session.store.session is not None:
                self._expire_session("closed")
            self.session.store.close()
            if self.vault:
                self.vault.store.close()
