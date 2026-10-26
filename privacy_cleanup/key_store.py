"""Explicit native backend only. Never use keyring's plugin/backend discovery."""
import base64
import sys

from .domain import RuleError


class MacKeyStore:
    def __init__(self):
        if sys.platform != "darwin":
            raise RuleError("Private mode currently requires macOS Keychain")
        try:
            from keyring.backends.macOS import Keyring
            self.backend = Keyring()
            self.backend.keychain = None  # Ignore environment/config overrides.
            self.backend.priority
        except Exception:
            raise RuleError("Native Keychain is unavailable; private mode cannot start") from None
        self.service = "org.privacycleanup.local.vault.v1"

    def get(self, identifier):
        try:
            value = self.backend.get_password(self.service, identifier)
            if value is None:
                return None
            key = base64.b64decode(value, validate=True)
            if not 32 <= len(key) <= 256:  # A legacy raw key or a passphrase-wrapped key.
                raise ValueError()
            return key
        except Exception:
            raise RuleError("Keychain could not supply the vault key") from None

    def put(self, identifier, key):
        try:
            self.backend.set_password(self.service, identifier, base64.b64encode(key).decode())
            if self.get(identifier) != key:
                raise ValueError()
        except Exception:
            raise RuleError("Keychain could not store the vault key; no profile was saved") from None

    def delete(self, identifier):
        try:
            if self.backend.get_password(self.service, identifier) is not None:
                self.backend.delete_password(self.service, identifier)
            if self.backend.get_password(self.service, identifier) is not None:
                raise ValueError()
        except Exception:
            raise RuleError("Key removal is incomplete; retry local deletion after unlocking Keychain") from None
