"""Explicit native integration check: create/read/delete our own temporary key only.

Not part of automated tests. May trigger a macOS Keychain prompt. No existing
credential or application key is requested; no key bytes are printed.
"""
import secrets

from privacy_cleanup.key_store import MacKeyStore
from privacy_cleanup.network import install


def main():
    store = MacKeyStore()
    store.service = "org.privacycleanup.local.synthetic-selftest"
    identifier = "temporary-" + secrets.token_hex(16)
    expected = secrets.token_bytes(32)
    install()
    try:
        store.put(identifier, expected)
        if store.get(identifier) != expected:
            raise RuntimeError("Native key round trip failed")
    finally:
        store.delete(identifier)
    if store.get(identifier) is not None:
        raise RuntimeError("Temporary key cleanup failed")
    print("PASS: native Keychain create/read/delete with outbound denial; no existing credentials accessed")


if __name__ == "__main__":
    main()
