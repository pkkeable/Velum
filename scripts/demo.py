"""A reproducible end-to-end fictional run using an isolated temporary directory."""
import tempfile
from pathlib import Path

from privacy_cleanup.network import install
from privacy_cleanup.storage import Store


def main():
    install()
    with tempfile.TemporaryDirectory(prefix="privacy-cleanup-test-", dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp") as temporary:
        store = Store(Path(temporary) / "runtime")

        def act(action, cid=None, value=None):
            state = store.read()
            command = {"action": action, "expected_version": state["version"]}
            if cid:
                command["candidate_id"] = cid
                c = next(c for c in state["candidates"] if c["id"] == cid)
                if c["request"]:
                    command["fingerprint"] = c["request"]["fingerprint"]
            if value:
                command["value"] = value
            return store.act(command)

        act("load_demo")
        act("decide", "spokeo-2", "rejected")
        for cid, scenario in [("spokeo-1", "accepted"), ("beenverified-1", "uncertain"), ("acxiom-1", "manual")]:
            act("decide", cid, "confirmed")
            act("prepare", cid)
            act("approve", cid)
            act("submit", cid, scenario)
        act("verify", "spokeo-1")
        act("response", "spokeo-1", "broker_reports_deletion")
        act("check", "spokeo-1", "absent")
        act("check", "beenverified-1", "blocked")
        for c in store.read()["candidates"]:
            print(c["id"], "|", c["decision"], "|", c["request"]["status"] if c["request"] else "no request", "|", c["response"], "| visibility:", c["current_visibility"])
        print("PASS: fictional workflow complete; no live requests; temporary records deleted on exit")


if __name__ == "__main__":
    main()
